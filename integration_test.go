package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitFor polls cond until it returns true or the deadline passes. It returns
// whether cond ultimately held, so callers fail with a clear message rather than
// hanging on a fixed sleep.
func waitFor(t *testing.T, deadline time.Duration, cond func() bool) bool {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// captureFiles lists the spool/metadata files written into the capture dir.
func captureFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}

// dialReady waits until addr accepts a TCP connection (the listener is up),
// returning the open connection or failing the test.
func dialReady(t *testing.T, addr string, deadline time.Duration) net.Conn {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener at %s never became ready", addr)
	return nil
}

// httpReady waits until an HTTP GET to url returns any response (server up).
func httpReady(t *testing.T, url string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("HTTP server at %s never became ready", url)
}

// baseTestConfig returns a config bound to loopback with everything disabled;
// individual tests enable only the listeners they exercise.
func baseTestConfig(t *testing.T) {
	t.Helper()
	cfg = defaultConfig()
	cfg.Bind = "127.0.0.1"
	cfg.OutDir = t.TempDir()
	cfg.Ports = Ports{}
	cfg.SNMP.Enabled = false
	cfg.Dashboard.Enabled = false
	cfg.MDNS.Enabled = false
	cfg.Forward.Enabled = false
	cfg.SMB.Enabled = false
	cfg.WSD.Enabled = false
}

func TestRawCaptureEndToEnd(t *testing.T) {
	baseTestConfig(t)
	cfg.Ports.Raw9100 = 19100

	if _, err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(engine.Stop)

	payload := []byte("%!PS-Adobe-3.0\nprint me\n")
	c := dialReady(t, "127.0.0.1:19100", 2*time.Second)
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.Close()

	dir := captureDir()
	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("no job captured; files=%v", captureFiles(dir))
	}

	jobs := store.recent(10)
	var got *job
	for i := range jobs {
		if jobs[i].Protocol == "9100" {
			got = &jobs[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no 9100 job in store: %+v", jobs)
	}
	if got.Bytes != len(payload) {
		t.Fatalf("job bytes = %d, want %d", got.Bytes, len(payload))
	}
	if got.SavedAs == "" {
		t.Fatalf("job has no saved file")
	}
	saved, err := os.ReadFile(filepath.Join(dir, got.SavedAs))
	if err != nil {
		t.Fatalf("read capture file: %v", err)
	}
	if !bytes.Equal(saved, payload) {
		t.Fatalf("capture bytes = %q, want %q", saved, payload)
	}
}

func TestLPDCaptureEndToEnd(t *testing.T) {
	baseTestConfig(t)
	cfg.Ports.LPR = 19515

	if _, err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(engine.Stop)

	c := dialReady(t, "127.0.0.1:19515", 2*time.Second)
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c)

	readAck := func(what string) {
		b, err := br.ReadByte()
		if err != nil {
			t.Fatalf("%s: read ack: %v", what, err)
		}
		if b != 0x00 {
			t.Fatalf("%s: ack = 0x%02x, want 0x00", what, b)
		}
	}

	// 0x02 = receive a printer job for queue "queue".
	if _, err := c.Write([]byte("\x02queue\n")); err != nil {
		t.Fatalf("send recv-job: %v", err)
	}
	readAck("recv-job")

	// Control file sub-command (0x02): "<len> cfA001host\n" + content + 0x00.
	ctrl := "Hjhost\nPuser\nJmydoc\n"
	if _, err := fmt.Fprintf(c, "\x02%d cfA001host\n", len(ctrl)); err != nil {
		t.Fatalf("send ctrl header: %v", err)
	}
	readAck("ctrl-header")
	if _, err := io.WriteString(c, ctrl); err != nil {
		t.Fatalf("send ctrl body: %v", err)
	}
	c.Write([]byte{0x00})
	readAck("ctrl-body")

	// Data file sub-command (0x03): "<len> dfA001host\n" + data + 0x00.
	dataFile := []byte("PCL data file contents\f")
	if _, err := fmt.Fprintf(c, "\x03%d dfA001host\n", len(dataFile)); err != nil {
		t.Fatalf("send data header: %v", err)
	}
	readAck("data-header")
	if _, err := c.Write(dataFile); err != nil {
		t.Fatalf("send data body: %v", err)
	}
	c.Write([]byte{0x00})
	readAck("data-body")

	// Closing the connection ends the conversation; the daemon saves the job.
	c.Close()

	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("no LPD job captured; files=%v", captureFiles(captureDir()))
	}
	jobs := store.recent(10)
	got := jobs[0]
	if got.Protocol != "LPR" {
		t.Fatalf("protocol = %q, want LPR", got.Protocol)
	}
	if got.JobName != "mydoc" || got.User != "user" || got.Host != "jhost" {
		t.Fatalf("control parse: job=%q user=%q host=%q", got.JobName, got.User, got.Host)
	}
	if got.Bytes != len(dataFile) {
		t.Fatalf("bytes = %d, want %d", got.Bytes, len(dataFile))
	}
	saved, err := os.ReadFile(filepath.Join(captureDir(), got.SavedAs))
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	if !bytes.Equal(saved, dataFile) {
		t.Fatalf("capture bytes = %q, want %q", saved, dataFile)
	}
}

// buildIPPPrintJob assembles a minimal IPP/1.1 Print-Job request: operation
// attributes (charset, language, printer-uri, job-name) then the document.
func buildIPPPrintJob(printerURI, jobName string, doc []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x01})                            // version 1.1
	binary.Write(&b, binary.BigEndian, uint16(opPrintJob)) // Print-Job
	binary.Write(&b, binary.BigEndian, uint32(1))          // request-id
	b.WriteByte(tagOperationAttrs)                         // operation-attributes-tag
	writeStr(&b, tagCharset, "attributes-charset", "utf-8")
	writeStr(&b, tagLanguage, "attributes-natural-language", "en-us")
	writeStr(&b, tagURI, "printer-uri", printerURI)
	writeStr(&b, tagName, "job-name", jobName)
	b.WriteByte(tagEndOfAttrs) // end-of-attributes-tag
	b.Write(doc)
	return b.Bytes()
}

func TestIPPPrintEndToEnd(t *testing.T) {
	baseTestConfig(t)
	cfg.Ports.IPP = 19631

	if _, err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(engine.Stop)

	httpReady(t, "http://127.0.0.1:19631/ipp/print", 2*time.Second)

	doc := []byte("%PDF-1.4\nipp document body\n%%EOF\n")
	req := buildIPPPrintJob("ipp://127.0.0.1:19631/ipp/print", "ippdoc", doc)

	resp, err := http.Post("http://127.0.0.1:19631/ipp/print", "application/ipp", bytes.NewReader(req))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("no IPP job captured; files=%v", captureFiles(captureDir()))
	}
	got := store.recent(10)[0]
	if got.Protocol != "IPP" {
		t.Fatalf("protocol = %q, want IPP", got.Protocol)
	}
	if got.JobName != "ippdoc" {
		t.Fatalf("job_name = %q, want ippdoc", got.JobName)
	}
	if got.Bytes != len(doc) {
		t.Fatalf("bytes = %d, want %d", got.Bytes, len(doc))
	}
	saved, err := os.ReadFile(filepath.Join(captureDir(), got.SavedAs))
	if err != nil {
		t.Fatalf("read capture: %v", err)
	}
	if !bytes.Equal(saved, doc) {
		t.Fatalf("capture bytes = %q, want %q", saved, doc)
	}
}

func TestDashboardAPIEndpoints(t *testing.T) {
	baseTestConfig(t)
	cfg.Ports.Raw9100 = 19100
	cfg.Ports.Dashboard = 18631
	cfg.Dashboard.Enabled = true
	cfg.SNMP.Community = "topsecret" // must be redacted in /api/config

	if _, err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(engine.Stop)

	// Capture one raw job.
	payload := []byte("\x1b%-12345X@PJL\nraw dash job\n")
	c := dialReady(t, "127.0.0.1:19100", 2*time.Second)
	c.Write(payload)
	c.Close()
	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("no job captured for dashboard test")
	}
	got := store.recent(10)[0]

	httpReady(t, "http://127.0.0.1:18631/api/stats", 2*time.Second)

	// /api/stats — total >= 1.
	var stats struct {
		Stats storeStats `json:"stats"`
	}
	getJSON(t, "http://127.0.0.1:18631/api/stats", &stats)
	if stats.Stats.Total < 1 {
		t.Fatalf("stats total = %d, want >=1", stats.Stats.Total)
	}

	// /api/jobs — the captured job is listed with its fields (paged envelope).
	var jobsResp struct {
		Jobs  []job `json:"jobs"`
		Total int   `json:"total"`
	}
	getJSON(t, "http://127.0.0.1:18631/api/jobs", &jobsResp)
	jobs := jobsResp.Jobs
	if len(jobs) < 1 {
		t.Fatalf("no jobs from /api/jobs")
	}
	found := false
	for _, j := range jobs {
		if j.ID == got.ID {
			found = true
			if j.Protocol != "9100" || j.Bytes != len(payload) {
				t.Fatalf("job mismatch: %+v", j)
			}
		}
	}
	if !found {
		t.Fatalf("captured job id %d not in /api/jobs", got.ID)
	}

	// /api/config — 200, and the community string is redacted.
	resp, err := http.Get("http://127.0.0.1:18631/api/config")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config status = %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "topsecret") {
		t.Fatalf("/api/config leaked the community string: %s", body)
	}

	// /api/job?id=N — returns the exact captured bytes.
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:18631/api/job?id=%d", got.ID))
	if err != nil {
		t.Fatalf("get job data: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("job data status = %d", resp.StatusCode)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("job data = %q, want %q", data, payload)
	}
}

func getJSON(t *testing.T, url string, v interface{}) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}

func TestEngineStartStopStartIdempotent(t *testing.T) {
	baseTestConfig(t)
	cfg.Ports.Raw9100 = 19100
	dir := captureDir()

	sendRaw := func(payload []byte) {
		c := dialReady(t, "127.0.0.1:19100", 2*time.Second)
		c.Write(payload)
		c.Close()
	}

	// First start + capture.
	if _, err := engine.Start(); err != nil {
		t.Fatalf("start 1: %v", err)
	}
	first := []byte("first job bytes\n")
	sendRaw(first)
	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("first job not captured")
	}
	engine.Stop()

	// After a synchronous Stop the port must be released: a dial fails.
	if c, err := net.DialTimeout("tcp", "127.0.0.1:19100", 200*time.Millisecond); err == nil {
		c.Close()
		t.Fatalf("port still accepting connections after Stop")
	}

	// Second start + capture (note: Start resets the store, so we assert on disk).
	if _, err := engine.Start(); err != nil {
		t.Fatalf("start 2: %v", err)
	}
	t.Cleanup(engine.Stop)
	second := []byte("second job bytes\n")
	sendRaw(second)
	if !waitFor(t, 2*time.Second, func() bool { return len(store.recent(10)) > 0 }) {
		t.Fatalf("second job not captured")
	}

	// Both captures must exist on disk.
	files := captureFiles(dir)
	var sawFirst, sawSecond bool
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if bytes.Equal(b, first) {
			sawFirst = true
		}
		if bytes.Equal(b, second) {
			sawSecond = true
		}
	}
	if !sawFirst || !sawSecond {
		t.Fatalf("captures on disk: first=%v second=%v files=%v", sawFirst, sawSecond, files)
	}
}

func TestForwardBestEffortAndBlock(t *testing.T) {
	// Drive the forwarder + sink directly; no listeners needed.
	cfg = defaultConfig()
	cfg.Bind = "127.0.0.1"
	cfg.OutDir = t.TempDir()
	cfg.Storage.SpoolDir = t.TempDir()

	if err := ensureStorageDirs(); err != nil {
		t.Fatalf("ensure dirs: %v", err)
	}

	// A refused target: 127.0.0.1:1 (privileged, nothing listening) reliably
	// refuses on loopback.
	const deadTarget = "127.0.0.1:1"

	run := func(policy string) *job {
		sink = &captureSink{dir: captureDir()}
		store = newJobStore(10)
		fwd, err := newForwarder(ForwardConf{
			Enabled: true, Capture: "both",
			Targets: []ForwardTarget{{
				Name: "dead", Transport: "raw", Address: deadTarget,
				TimeoutMS: 300, Failure: policy,
			}},
		})
		if err != nil {
			t.Fatalf("%s: newForwarder: %v", policy, err)
		}
		forward = fwd
		defer func() { forward.Close(); forward = nil }()

		j := newJob("9100", "127.0.0.1:5555")
		j.data = []byte("forward policy test payload\n")
		j.Bytes = len(j.data)
		saveErr := sink.save(j)

		switch policy {
		case "best_effort":
			if saveErr != nil {
				t.Fatalf("best_effort: save returned error %v (should be swallowed)", saveErr)
			}
		case "block":
			if saveErr == nil {
				t.Fatalf("block: save returned nil, want forward error")
			}
		}
		return j
	}

	// best_effort: capture succeeds despite the dead target.
	je := run("best_effort")
	if je.SavedAs == "" {
		t.Fatalf("best_effort: job not saved to disk")
	}
	if got, err := os.ReadFile(filepath.Join(captureDir(), je.SavedAs)); err != nil || !bytes.Equal(got, je.data) {
		t.Fatalf("best_effort: capture bytes wrong: err=%v", err)
	}
	if len(je.Forwards) != 1 || je.Forwards[0].Status != "failed" {
		t.Fatalf("best_effort: forwards = %+v, want one 'failed'", je.Forwards)
	}

	// block: inbound returns an error but the capture file is still written and
	// nothing panics.
	jb := run("block")
	if jb.SavedAs == "" {
		t.Fatalf("block: job not saved to disk")
	}
	if len(jb.Forwards) != 1 || jb.Forwards[0].Status != "failed" {
		t.Fatalf("block: forwards = %+v, want one 'failed'", jb.Forwards)
	}
}
