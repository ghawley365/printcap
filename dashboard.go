package main

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// secretSentinel is the placeholder the settings API substitutes for every
// secret it returns (SNMP community, USM/SMB passwords, TLS key/cert paths,
// service password). On save, a field still equal to the sentinel means "keep the
// stored value", so the unauthenticated dashboard never has to reveal a secret to
// round-trip the rest of the config.
const secretSentinel = "***"

// dashboardHandler builds the live web UI and its JSON API on its own HTTP mux
// so it never collides with the IPP endpoint.
func dashboardHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashIndex)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/jobs", apiJobs)
	mux.HandleFunc("/api/config", apiConfig)
	mux.HandleFunc("/api/settings", apiSettings)
	mux.HandleFunc("/api/capture", apiCapture)
	mux.HandleFunc("/api/capturefile", apiCaptureFile)
	mux.HandleFunc("/api/capture/stream", apiCaptureStream)
	mux.HandleFunc("/api/capture/live", apiCaptureLive)
	mux.HandleFunc("/api/job", apiJobData)
	mux.HandleFunc("/api/jobpreview", apiJobPreview)
	mux.HandleFunc("/api/jobdelete", apiJobDelete)
	mux.HandleFunc("/api/export", apiExport)
	mux.HandleFunc("/api/listeners", apiListeners)
	mux.HandleFunc("/api/control", apiControl)
	mux.HandleFunc("/api/listener", apiListener)
	mux.HandleFunc("/api/loglevel", apiLogLevel)
	mux.HandleFunc("/api/events", apiEvents)
	mux.HandleFunc("/api/logs", apiLogs)
	mux.HandleFunc("/api/logfile", apiLogFile)
	mux.HandleFunc("/api/version", apiVersion)
	return mux
}

// apiVersion reports the printcap build version.
func apiVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"version": version})
}

// apiLogFile streams the active log file as a download.
func apiLogFile(w http.ResponseWriter, r *http.Request) {
	path := logger.LogFilePath()
	if path == "" {
		http.Error(w, "no log file configured", http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "log file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	safeServeHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
}

// apiCapture returns a filtered, paginated view of the interceptor's pcap as
// per-packet summaries the UI color-codes (resets/ICMP errors highlighted). It is
// read-only and safe over the unauthenticated dashboard. If capture has never run
// (no pcap file), it returns an empty result rather than an error.
func apiCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	f := captureFilter{
		class:  q.Get("class"),
		proto:  q.Get("proto"),
		q:      q.Get("q"),
		offset: atoiDefault(q.Get("offset"), 0),
		limit:  atoiDefault(q.Get("limit"), 500),
	}
	if f.limit <= 0 || f.limit > 5000 {
		f.limit = 500
	}
	path := interceptPcapPath(cfg.Intercept)
	res, err := capturePackets(path, f)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, &captureResult{File: filepath.Base(path), Packets: []packetSummary{}})
			return
		}
		http.Error(w, "cannot read capture: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if res.Packets == nil {
		res.Packets = []packetSummary{}
	}
	writeJSON(w, res)
}

// apiCaptureStream reassembles both directions of the TCP conversation between
// two endpoints (?a=ip:port&b=ip:port) from the captured pcap and returns each
// half-stream base64-encoded (capped) for the viewer's "follow stream" feature.
func apiCaptureStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a, err := netip.ParseAddrPort(r.URL.Query().Get("a"))
	if err != nil {
		http.Error(w, "bad 'a' endpoint (want ip:port)", http.StatusBadRequest)
		return
	}
	b, err := netip.ParseAddrPort(r.URL.Query().Get("b"))
	if err != nil {
		http.Error(w, "bad 'b' endpoint (want ip:port)", http.StatusBadRequest)
		return
	}
	path := interceptPcapPath(cfg.Intercept)
	ab, ba, parsed, ferr := followStream(path, a, b)
	if ferr != nil {
		if os.IsNotExist(ferr) {
			writeJSON(w, map[string]interface{}{"a": a.String(), "b": b.String(), "a_to_b_len": 0, "b_to_a_len": 0})
			return
		}
		http.Error(w, "cannot read capture: "+ferr.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{
		"a":          a.String(),
		"b":          b.String(),
		"a_to_b_len": len(ab),
		"b_to_a_len": len(ba),
		"a_to_b":     base64.StdEncoding.EncodeToString(ab),
		"b_to_a":     base64.StdEncoding.EncodeToString(ba),
		"a_is_http":  looksHTTP(ab),
		"b_is_http":  looksHTTP(ba),
		"capped":     len(ab) >= maxFollowBytes || len(ba) >= maxFollowBytes,
		"parsed":     parsed,
	})
}

// apiCaptureLive returns packets recorded since the caller's cursor from the
// in-memory live ring, applying the same filters as the static viewer. The UI
// polls it for a live, scrolling capture window without re-reading the pcap.
func apiCaptureLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	since, _ := strconv.ParseUint(q.Get("since"), 10, 64)
	limit := atoiDefault(q.Get("limit"), 1000)
	if limit <= 0 || limit > 4000 {
		limit = 1000
	}
	f := captureFilter{
		class: q.Get("class"),
		proto: q.Get("proto"),
		svc:   q.Get("svc"),
		port:  atoiDefault(q.Get("port"), 0),
		q:     q.Get("q"),
	}
	recs, link, cursor, firstNo, dropped := captureLive.since(since, limit)
	rows := make([]packetSummary, 0, len(recs))
	for i, rec := range recs {
		s := dissectSummary(link, rec.data)
		s.No = int(firstNo) + i
		s.Len = rec.origLen
		s.Time = rec.ts.Format("15:04:05.000")
		if captureMatch(s, f) {
			rows = append(rows, s)
		}
	}
	seq, depth := captureLive.stats()
	writeJSON(w, map[string]interface{}{
		"packets": rows,
		"cursor":  cursor,
		"dropped": dropped,
		"total":   seq,
		"depth":   depth,
		"running": engine.Running() && interceptModule != nil,
	})
}

// apiCaptureFile streams the raw interceptor pcap as a download.
func apiCaptureFile(w http.ResponseWriter, r *http.Request) {
	path := interceptPcapPath(cfg.Intercept)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "no capture file yet (run intercept mode first)", http.StatusNotFound)
		return
	}
	defer f.Close()
	safeServeHeaders(w)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(path)+"\"")
	http.ServeContent(w, r, filepath.Base(path), time.Time{}, f)
}

// apiLogs returns recent log entries (newest first), optionally filtered by a
// minimum level (?level=info|debug|trace) and capped by ?n=.
func apiLogs(w http.ResponseWriter, r *http.Request) {
	n := atoiDefault(r.URL.Query().Get("n"), 200)
	if n <= 0 || n > 2000 {
		n = 200
	}
	min := LevelTrace // default: everything currently buffered
	if lv := r.URL.Query().Get("level"); lv != "" {
		min = parseLevel(lv)
	}
	writeJSON(w, logger.recent(n, min))
}

func dashHost() string {
	if cfg.Bind == "0.0.0.0" || cfg.Bind == "" || cfg.Bind == "::" {
		return "localhost"
	}
	return cfg.Bind
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func apiStats(w http.ResponseWriter, r *http.Request) {
	type listener struct {
		Name string `json:"name"`
		Port int    `json:"port"`
	}
	ls := []listener{
		{"Raw/9100", cfg.Ports.Raw9100},
		{"LPR", cfg.Ports.LPR},
		{"IPP", cfg.Ports.IPP},
		{"IPPS", cfg.Ports.IPPS},
		{"IPP/IPPS (auto)", cfg.Ports.AutoTLS},
		{"SNMP", snmpPortIfEnabled()},
		{"Dashboard", cfg.Ports.Dashboard},
	}
	writeJSON(w, map[string]interface{}{
		"stats":     store.stats(),
		"listeners": ls,
		"printer": map[string]string{
			"name":           cfg.Printer.Name,
			"make_and_model": cfg.Printer.MakeAndModel,
			"location":       cfg.Printer.Location,
			"serial":         cfg.Printer.Serial,
		},
		"save_mode": cfg.Save,
	})
}

func snmpPortIfEnabled() int {
	if cfg.SNMP.Enabled {
		return cfg.Ports.SNMP
	}
	return 0
}

// filterFromQuery builds a jobFilter from the request's query parameters,
// shared by /api/jobs (paginated) and /api/export (no pagination).
func filterFromQuery(r *http.Request) jobFilter {
	q := r.URL.Query()
	f := jobFilter{
		Q:        q.Get("q"),
		Protocol: q.Get("protocol"),
		Sort:     q.Get("sort"),
		Desc:     true,
	}
	switch strings.ToLower(q.Get("order")) {
	case "asc":
		f.Desc = false
	case "desc":
		f.Desc = true
	}
	f.Offset = atoiDefault(q.Get("offset"), 0)
	f.Limit = atoiDefault(q.Get("limit"), 50)
	return f
}

func apiJobs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f := filterFromQuery(r)
	page, total := store.query(f)
	if page == nil {
		page = []job{}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	writeJSON(w, map[string]interface{}{
		"jobs":   page,
		"total":  total,
		"offset": f.Offset,
		"limit":  limit,
	})
}

// apiJobPreview returns up to 64 KiB of a saved spool file as text/plain. The
// path is constrained to captureDir() via filepath.Base.
func apiJobPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	j, ok := store.get(id)
	if !ok || j.SavedAs == "" {
		http.Error(w, "no saved data for that job", http.StatusNotFound)
		return
	}
	path := filepath.Join(captureDir(), filepath.Base(j.SavedAs))
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	// Captured bytes are attacker-controlled; stop the browser from MIME-sniffing
	// them into HTML/JS that would run in the dashboard origin.
	safeServeHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"preview.txt\"")
	io.CopyN(w, f, 64*1024)
}

// csrfGuard requires a custom request header on state-changing endpoints. A
// browser cannot set a custom header on a cross-origin "simple" request without
// triggering a CORS preflight, which this server never grants — so a malicious
// site the operator visits cannot drive-by POST to the (unauthenticated, local)
// dashboard. Returns false (and writes 403) if the header is absent.
func csrfGuard(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "printcap" {
		http.Error(w, "missing X-Requested-With: printcap header", http.StatusForbidden)
		return false
	}
	return true
}

// safeServeHeaders hardens responses that serve attacker-controlled file bytes
// (captured spool data, logs): disable MIME-sniffing and forbid any active
// content, so a malicious captured document cannot become stored XSS in the
// dashboard origin.
func safeServeHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
}

// apiJobDelete removes a job from the store and deletes its on-disk artifacts:
// the spool file, the .json sidecar, the decoded sidecar, and any -sent-*
// transformed copies. Every path is constrained to captureDir().
func apiJobDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !csrfGuard(w, r) {
		return
	}
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	j, ok := store.remove(id)
	if !ok {
		http.Error(w, "no such job", http.StatusNotFound)
		return
	}
	dir := captureDir()
	rm := func(name string) {
		if name == "" {
			return
		}
		_ = os.Remove(filepath.Join(dir, filepath.Base(name)))
	}
	rm(j.SavedAs)
	rm(j.DecodedAs)
	if j.captureBase != "" {
		base := filepath.Base(j.captureBase)
		rm(base + ".json")
		if matches, err := filepath.Glob(filepath.Join(dir, base+"-sent-*")); err == nil {
			for _, m := range matches {
				// Glob results already live under dir; Base-join keeps them there.
				_ = os.Remove(filepath.Join(dir, filepath.Base(m)))
			}
		}
	}
	writeJSON(w, map[string]bool{"deleted": true})
}

// apiExport streams the filtered job list (no pagination) as CSV or JSON.
func apiExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f := filterFromQuery(r)
	f.Offset = 0
	f.Limit = 1 << 30 // effectively unbounded for the ≤200-entry ring
	jobs, _ := store.query(f)

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"printcap-jobs.json\"")
		if jobs == nil {
			jobs = []job{}
		}
		json.NewEncoder(w).Encode(jobs)
		return
	}
	// default: CSV
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"printcap-jobs.csv\"")
	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "received", "protocol", "source", "user", "host", "job_name", "bytes", "pdl", "dlp_matches", "saved_as"})
	for _, j := range jobs {
		// Job fields (name/user/host/source/…) are attacker-controlled (anyone
		// can send a print job); csvSafe neutralizes spreadsheet formula
		// injection when the operator opens the export in Excel/Sheets.
		cw.Write([]string{
			strconv.Itoa(j.ID), csvSafe(j.Received), csvSafe(j.Protocol), csvSafe(j.Source), csvSafe(j.User), csvSafe(j.Host),
			csvSafe(j.JobName), strconv.Itoa(j.Bytes), csvSafe(j.PDL),
			csvSafe(strings.Join(j.DLPMatches, "; ")), csvSafe(j.SavedAs),
		})
	}
	cw.Flush()
}

// csvSafe neutralizes CSV/spreadsheet formula injection: a cell beginning with
// =, +, -, @, tab, or CR is treated as a formula by Excel/Sheets, so we prefix
// such values with a single quote to force them to be read as text.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// apiListeners returns the runtime status of every configured listener.
func apiListeners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, listenerStatuses())
}

// apiControl performs an engine lifecycle action ASYNCHRONOUSLY: it responds
// first, then bounces the engine in a goroutine. This is mandatory — the
// dashboard is itself a listener, so a synchronous stop/restart would deadlock
// the handler against the server's own Shutdown. The dashboard briefly drops
// during restart/stop.
func apiControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !csrfGuard(w, r) {
		return
	}
	action := r.URL.Query().Get("action")
	switch action {
	case "stop", "start", "restart":
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	engineAction(action)
}

// engineAction runs an engine lifecycle action in a detached goroutine. It is a
// package var so tests can stub it (a real bounce would try to bind ports). The
// respond-first / bounce-after ordering is required: the dashboard is itself a
// listener, so a synchronous stop/restart would deadlock the handler against the
// server's own Shutdown. Assigned in init() to break the static initialization
// cycle (engineAction → Start → dashboardHandler → apiControl → engineAction).
var engineAction func(action string)

// applyConfigAsync swaps in an edited config and persists it, in a detached
// goroutine. It mirrors the GUI's stop-before-mutate discipline: the engine is
// stopped FIRST so every handler goroutine that reads the global cfg has drained
// before cfg is reassigned (otherwise the swap would be a data race), then the
// config is written to disk, logging is reconfigured (level/path may have
// changed), and the engine is brought back up. A package var so tests can stub it
// (a real apply would bind ports and rewrite the config file).
//
// Caveat: the native Windows GUI mutates the same global cfg on its UI thread.
// Do not drive settings changes from the GUI and the web editor against the same
// running instance simultaneously — apply from one surface at a time.
var applyConfigAsync func(nc *Config, restart bool)

func init() {
	engineAction = func(action string) {
		go func() {
			switch action {
			case "stop":
				engine.Stop()
			case "start":
				engine.Start()
			case "restart":
				engine.Stop()
				engine.Start()
			}
		}()
	}
	applyConfigAsync = func(nc *Config, restart bool) {
		go func() {
			wasRunning := engine.Running()
			if wasRunning {
				engine.Stop() // drains all readers of cfg before we swap it
			}
			cfg = nc
			if err := dumpConfig(configFilePath); err != nil {
				logErr("dashboard", "saving config to %s failed: %v", configFilePath, err)
			}
			configureLogging() // pick up any log level / path / sink changes
			if wasRunning || restart {
				engine.Start()
			}
		}()
	}
}

// apiListener toggles a single listener on/off and bounces the engine so the
// change takes effect. Like apiControl it responds before acting (the bounce
// briefly drops the dashboard).
func apiListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !csrfGuard(w, r) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	enabled := r.URL.Query().Get("enabled") != "false"
	setListenerDisabled(name, !enabled)
	writeJSON(w, map[string]bool{"ok": true})
	engineAction("restart")
}

// apiLogLevel changes the live log level without restarting the logger.
func apiLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !csrfGuard(w, r) {
		return
	}
	lv := r.URL.Query().Get("level")
	if !knownLevel(lv) {
		http.Error(w, "unknown level", http.StatusBadRequest)
		return
	}
	logger.SetLevel(parseLevel(lv))
	writeJSON(w, map[string]string{"level": strings.ToLower(strings.TrimSpace(lv))})
}

// knownLevel reports whether s names a log level we accept (parseLevel itself
// defaults unknown input to info, so we validate explicitly here).
func knownLevel(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "err", "warn", "warning", "info", "debug", "trace", "verbose":
		return true
	}
	return false
}

// apiEvents is a Server-Sent Events stream of live stats, pushed immediately on
// connect and every ~1.5s thereafter until the client disconnects. It replaces
// the frontend's polling loop.
func apiEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	send := func() {
		payload, err := json.Marshal(map[string]interface{}{
			"stats":     store.stats(),
			"listeners": listenerStatuses(),
			"level":     logger.Level().String(),
		})
		if err != nil {
			return
		}
		w.Write([]byte("data: "))
		w.Write(payload)
		w.Write([]byte("\n\n"))
		flusher.Flush()
	}
	send()
	stopping := engine.Stopping()
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-stopping:
			return // engine is bouncing; exit now so Shutdown isn't blocked
		case <-ticker.C:
			send()
		}
	}
}

func apiConfig(w http.ResponseWriter, r *http.Request) {
	// Return a copy with secrets redacted — the dashboard is unauthenticated,
	// so it must not leak the SNMP community string or key material paths.
	writeJSON(w, redactedConfig())
}

// redactedConfig returns a shallow copy of the active config with all secret
// material removed: the SNMP community string, SNMPv3 USM passphrases, and TLS
// key/cert file paths. Safe to expose over the unauthenticated dashboard.
func redactedConfig() *Config {
	c := *cfg
	if c.SNMP.Community != "" {
		c.SNMP.Community = secretSentinel
	}
	if len(c.SNMP.Users) > 0 {
		us := make([]SNMPUser, len(c.SNMP.Users))
		copy(us, c.SNMP.Users)
		for i := range us {
			if us[i].AuthPass != "" {
				us[i].AuthPass = secretSentinel
			}
			if us[i].PrivPass != "" {
				us[i].PrivPass = secretSentinel
			}
		}
		c.SNMP.Users = us
	}
	if len(c.SMB.Users) > 0 {
		us := make([]SMBUser, len(c.SMB.Users))
		copy(us, c.SMB.Users)
		for i := range us {
			if us[i].Password != "" {
				us[i].Password = secretSentinel
			}
		}
		c.SMB.Users = us
	}
	// TLS paths are not secrets but can leak filesystem layout; mask the presence
	// with the sentinel so the settings editor can round-trip them unchanged.
	if c.TLS.CertFile != "" {
		c.TLS.CertFile = secretSentinel
	}
	if c.TLS.KeyFile != "" {
		c.TLS.KeyFile = secretSentinel
	}
	if c.Service.Password != "" {
		c.Service.Password = secretSentinel
	}
	return &c
}

// apiSettings serves the full effective config for editing (GET, secrets masked
// with the sentinel) and applies an edited config (POST). Writes are guarded by
// the CSRF header and, unless dashboard.allow_remote_admin is set, restricted to
// requests from the local machine — the dashboard is unauthenticated, so letting
// a remote client rewrite the config (output paths, forward targets, service
// account) would be a privilege-escalation vector.
func apiSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, redactedConfig())
	case http.MethodPost:
		if !csrfGuard(w, r) {
			return
		}
		if !cfg.Dashboard.AllowRemoteAdmin && !isLoopbackRequest(r) {
			http.Error(w, "settings can only be changed from the local machine (set dashboard.allow_remote_admin=true to permit remote changes)", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "could not read request body", http.StatusBadRequest)
			return
		}
		// Start from the current config so any key the editor omits keeps its
		// value, then overlay the posted JSON and restore any masked secrets.
		nc := *cfg
		if err := json.Unmarshal(body, &nc); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		mergeSecrets(&nc, cfg)

		issues := validateConfig(&nc)
		if hasErrors(issues) {
			var errs []string
			for _, is := range issues {
				if is.Severity == sevError {
					errs = append(errs, is.String())
				}
			}
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]interface{}{"ok": false, "errors": errs})
			return
		}
		var warnings []string
		for _, is := range issues {
			if is.Severity == sevWarning {
				warnings = append(warnings, is.String())
			}
		}
		restart := r.URL.Query().Get("restart") == "true"
		logInfo("dashboard", "settings updated via web from %s (restart=%v)", r.RemoteAddr, restart)
		writeJSON(w, map[string]interface{}{"ok": true, "warnings": warnings})
		applyConfigAsync(&nc, restart)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// isLoopbackRequest reports whether the request came from the local machine.
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// mergeSecrets restores secret fields the editor left as the sentinel (meaning
// "unchanged") from the current config, so a round-trip never blanks a secret the
// dashboard masked. New slices are allocated so cur is never mutated.
func mergeSecrets(nc, cur *Config) {
	if nc.SNMP.Community == secretSentinel {
		nc.SNMP.Community = cur.SNMP.Community
	}
	if len(nc.SNMP.Users) > 0 {
		us := make([]SNMPUser, len(nc.SNMP.Users))
		copy(us, nc.SNMP.Users)
		for i := range us {
			if us[i].AuthPass == secretSentinel {
				us[i].AuthPass = snmpSecret(cur, us[i].Name, true)
			}
			if us[i].PrivPass == secretSentinel {
				us[i].PrivPass = snmpSecret(cur, us[i].Name, false)
			}
		}
		nc.SNMP.Users = us
	}
	if len(nc.SMB.Users) > 0 {
		us := make([]SMBUser, len(nc.SMB.Users))
		copy(us, nc.SMB.Users)
		for i := range us {
			if us[i].Password == secretSentinel {
				us[i].Password = smbSecret(cur, us[i].User)
			}
		}
		nc.SMB.Users = us
	}
	if nc.TLS.CertFile == secretSentinel {
		nc.TLS.CertFile = cur.TLS.CertFile
	}
	if nc.TLS.KeyFile == secretSentinel {
		nc.TLS.KeyFile = cur.TLS.KeyFile
	}
	if nc.Service.Password == secretSentinel {
		nc.Service.Password = cur.Service.Password
	}
}

// snmpSecret returns the stored auth (auth=true) or priv passphrase for the named
// SNMPv3 user in cur, or "" if not found.
func snmpSecret(cur *Config, name string, auth bool) string {
	for _, u := range cur.SNMP.Users {
		if u.Name == name {
			if auth {
				return u.AuthPass
			}
			return u.PrivPass
		}
	}
	return ""
}

// smbSecret returns the stored password for the named SMB user in cur, or "".
func smbSecret(cur *Config, user string) string {
	for _, u := range cur.SMB.Users {
		if u.User == user {
			return u.Password
		}
	}
	return ""
}

// apiJobData streams a captured spool file back to the browser as a download.
func apiJobData(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	j, ok := store.get(id)
	if !ok || j.SavedAs == "" {
		http.Error(w, "no saved data for that job", http.StatusNotFound)
		return
	}
	// SavedAs is a filename we generated; join to the output dir and confirm it
	// stays inside it (defense in depth against traversal).
	path := filepath.Join(captureDir(), filepath.Base(j.SavedAs))
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	safeServeHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(j.SavedAs)+"\"")
	http.ServeContent(w, r, j.SavedAs, time.Time{}, f)
}

func dashIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardHTML))
}
