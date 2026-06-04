package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// dashTestSetup points cfg at a temp capture dir and seeds the store with a few
// jobs. It returns the temp dir.
func dashTestSetup(t *testing.T) string {
	t.Helper()
	cfg = defaultConfig()
	dir := t.TempDir()
	cfg.OutDir = dir
	// Zero every port so any async engine.Start() the control handlers fire binds
	// nothing — the tests assert the HTTP handler, not real listeners.
	cfg.Ports = Ports{}
	cfg.SNMP.Enabled = false
	cfg.MDNS.Enabled = false
	cfg.SMB.Enabled = false
	cfg.WSD.Enabled = false
	store = newJobStore(200)
	seed := []job{
		{ID: 1, Protocol: "9100", Source: "10.0.0.1:5000", Received: "2026-06-03 10:00:00", JobName: "invoice", User: "alice", Host: "ws1", Bytes: 100, SavedAs: "j1.prn", PDL: "PCL"},
		{ID: 2, Protocol: "IPP", Source: "10.0.0.2:5001", Received: "2026-06-03 10:01:00", JobName: "report", User: "bob", Host: "ws2", Bytes: 5000, SavedAs: "j2.ipp", PDL: "PS", DLPMatches: []string{"SSN"}},
		{ID: 3, Protocol: "LPR", Source: "10.0.0.3:5002", Received: "2026-06-03 10:02:00", JobName: "memo", User: "alice", Host: "ws3", Bytes: 250, SavedAs: "j3.lpr"},
	}
	for i := range seed {
		j := seed[i]
		store.add(&j)
	}
	return dir
}

func TestDashIndexRenders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	dashIndex(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, id := range []string{`id="cards"`, `id="jobs"`, `id="listeners"`, `id="logs"`, `id="overlay"`, `id="themeBtn"`, `api/events`} {
		if !strings.Contains(body, id) {
			t.Fatalf("dashboard HTML missing %q", id)
		}
	}
	// Self-contained: no external resource URLs.
	if strings.Contains(body, "http://") || strings.Contains(body, "https://") {
		t.Fatalf("dashboard HTML references an external URL")
	}
}

func TestStoreQuery(t *testing.T) {
	dashTestSetup(t)

	// default: newest first, all jobs.
	page, total := store.query(jobFilter{Desc: true})
	if total != 3 || len(page) != 3 {
		t.Fatalf("default query: total=%d len=%d", total, len(page))
	}
	if page[0].ID != 3 || page[2].ID != 1 {
		t.Fatalf("default sort not newest-first: %d..%d", page[0].ID, page[2].ID)
	}

	// protocol filter.
	page, total = store.query(jobFilter{Protocol: "IPP", Desc: true})
	if total != 1 || page[0].ID != 2 {
		t.Fatalf("protocol filter: total=%d", total)
	}

	// text query (case-insensitive) over user.
	page, total = store.query(jobFilter{Q: "ALICE", Desc: true})
	if total != 2 {
		t.Fatalf("text query alice: total=%d", total)
	}

	// sort by bytes ascending.
	page, _ = store.query(jobFilter{Sort: "bytes", Desc: false})
	if page[0].ID != 1 || page[2].ID != 2 {
		t.Fatalf("bytes asc order wrong: %d..%d", page[0].ID, page[2].ID)
	}

	// pagination.
	page, total = store.query(jobFilter{Sort: "received", Desc: false, Offset: 1, Limit: 1})
	if total != 3 || len(page) != 1 || page[0].ID != 2 {
		t.Fatalf("pagination: total=%d len=%d id=%v", total, len(page), page)
	}
}

func TestApiJobs(t *testing.T) {
	dashTestSetup(t)

	req := httptest.NewRequest("GET", "/api/jobs?q=alice&sort=bytes&order=asc&offset=0&limit=1", nil)
	rec := httptest.NewRecorder()
	apiJobs(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var resp struct {
		Jobs   []job `json:"jobs"`
		Total  int   `json:"total"`
		Offset int   `json:"offset"`
		Limit  int   `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 {
		t.Fatalf("total=%d want 2", resp.Total)
	}
	if len(resp.Jobs) != 1 || resp.Jobs[0].ID != 1 {
		t.Fatalf("page wrong: %+v", resp.Jobs)
	}
	if resp.Limit != 1 {
		t.Fatalf("limit=%d", resp.Limit)
	}

	// protocol filter.
	req = httptest.NewRequest("GET", "/api/jobs?protocol=LPR", nil)
	rec = httptest.NewRecorder()
	apiJobs(rec, req)
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total != 1 || resp.Jobs[0].Protocol != "LPR" {
		t.Fatalf("protocol filter via api: %+v", resp)
	}
}

func TestApiJobDelete(t *testing.T) {
	dir := dashTestSetup(t)

	// Create on-disk artifacts for job 1.
	j, _ := store.get(1)
	j.captureBase = "j1"
	// re-add with captureBase set (store clones on add); easier: mutate in ring via remove+add.
	store.remove(1)
	store.add(&j)

	must := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("j1.prn")
	must("j1.json")
	must("j1-sent-raw.bin")

	req := httptest.NewRequest("POST", "/api/jobdelete?id=1", nil)
	rec := httptest.NewRecorder()
	apiJobDelete(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := store.get(1); ok {
		t.Fatal("job 1 still in store after delete")
	}
	for _, f := range []string{"j1.prn", "j1.json", "j1-sent-raw.bin"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("file %s not deleted", f)
		}
	}

	// Traversal safety: a SavedAs trying to escape must be confined by filepath.Base.
	evil := job{ID: 9, Protocol: "9100", SavedAs: "../escape.txt", Bytes: 1}
	store.add(&evil)
	outside := filepath.Join(filepath.Dir(dir), "escape.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("POST", "/api/jobdelete?id=9", nil)
	rec = httptest.NewRecorder()
	apiJobDelete(rec, req)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("traversal delete escaped captureDir: %v", err)
	}
	os.Remove(outside)
}

func TestApiExport(t *testing.T) {
	dashTestSetup(t)

	req := httptest.NewRequest("GET", "/api/export?format=csv", nil)
	rec := httptest.NewRecorder()
	apiExport(rec, req)
	if rec.Code != 200 {
		t.Fatalf("csv status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "id,received,protocol,source,user,host,job_name,bytes,pdl,dlp_matches,saved_as") {
		t.Fatalf("csv header missing: %q", body[:60])
	}
	if strings.Count(strings.TrimSpace(body), "\n") != 3 { // header + 3 rows
		t.Fatalf("csv row count wrong:\n%s", body)
	}
	if ct := rec.Header().Get("Content-Disposition"); !strings.Contains(ct, "printcap-jobs.csv") {
		t.Fatalf("csv disposition: %q", ct)
	}

	req = httptest.NewRequest("GET", "/api/export?format=json", nil)
	rec = httptest.NewRecorder()
	apiExport(rec, req)
	var arr []job
	if err := json.Unmarshal(rec.Body.Bytes(), &arr); err != nil {
		t.Fatalf("json export not an array: %v", err)
	}
	if len(arr) != 3 {
		t.Fatalf("json export len=%d", len(arr))
	}
}

func TestApiListeners(t *testing.T) {
	dashTestSetup(t)
	req := httptest.NewRequest("GET", "/api/listeners", nil)
	rec := httptest.NewRecorder()
	apiListeners(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var ls []listenerStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &ls); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, l := range ls {
		names[l.Name] = true
	}
	for _, want := range []string{"9100", "LPR", "IPP", "IPPS", "dashboard"} {
		if !names[want] {
			t.Fatalf("listener %s missing from statuses", want)
		}
	}
}

func TestApiLogLevel(t *testing.T) {
	dashTestSetup(t)
	orig := logger.Level()
	defer logger.SetLevel(orig)

	req := httptest.NewRequest("POST", "/api/loglevel?level=debug", nil)
	rec := httptest.NewRecorder()
	apiLogLevel(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if logger.Level() != LevelDebug {
		t.Fatalf("level not set: %v", logger.Level())
	}

	req = httptest.NewRequest("POST", "/api/loglevel?level=bogus", nil)
	rec = httptest.NewRecorder()
	apiLogLevel(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown level should be 400, got %d", rec.Code)
	}
}

func TestApiControl(t *testing.T) {
	dashTestSetup(t)
	// Stub the async engine bounce so the test asserts the handler contract
	// (respond {ok:true} without blocking) without binding real listeners or
	// racing on the global store/sink the real engine reinitializes.
	var mu sync.Mutex
	var got []string
	orig := engineAction
	engineAction = func(a string) { mu.Lock(); got = append(got, a); mu.Unlock() }
	defer func() { engineAction = orig }()

	for _, action := range []string{"stop", "start", "restart"} {
		req := httptest.NewRequest("POST", "/api/control?action="+action, nil)
		rec := httptest.NewRecorder()
		apiControl(rec, req)
		if rec.Code != 200 {
			t.Fatalf("control %s status %d", action, rec.Code)
		}
		var resp map[string]bool
		json.Unmarshal(rec.Body.Bytes(), &resp)
		if !resp["ok"] {
			t.Fatalf("control %s not ok", action)
		}
	}
	// bad action -> 400.
	req := httptest.NewRequest("POST", "/api/control?action=nuke", nil)
	rec := httptest.NewRecorder()
	apiControl(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad action should be 400, got %d", rec.Code)
	}

	// /api/listener responds ok without blocking.
	req = httptest.NewRequest("POST", "/api/listener?name=IPP&enabled=false", nil)
	rec = httptest.NewRecorder()
	apiListener(rec, req)
	if rec.Code != 200 {
		t.Fatalf("listener status %d", rec.Code)
	}
	if !listenerDisabled("IPP") {
		t.Fatal("IPP not marked disabled")
	}
	setListenerDisabled("IPP", false) // reset shared state
}
