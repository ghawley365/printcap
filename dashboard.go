package main

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// dashboardHandler builds the live web UI and its JSON API on its own HTTP mux
// so it never collides with the IPP endpoint.
func dashboardHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", dashIndex)
	mux.HandleFunc("/api/stats", apiStats)
	mux.HandleFunc("/api/jobs", apiJobs)
	mux.HandleFunc("/api/config", apiConfig)
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
	return mux
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
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
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
		c.SNMP.Community = "***"
	}
	if len(c.SNMP.Users) > 0 {
		us := make([]SNMPUser, len(c.SNMP.Users))
		copy(us, c.SNMP.Users)
		for i := range us {
			if us[i].AuthPass != "" {
				us[i].AuthPass = "***"
			}
			if us[i].PrivPass != "" {
				us[i].PrivPass = "***"
			}
		}
		c.SNMP.Users = us
	}
	if len(c.SMB.Users) > 0 {
		us := make([]SMBUser, len(c.SMB.Users))
		copy(us, c.SMB.Users)
		for i := range us {
			if us[i].Password != "" {
				us[i].Password = "***"
			}
		}
		c.SMB.Users = us
	}
	c.TLS.CertFile = ""
	c.TLS.KeyFile = ""
	return &c
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
