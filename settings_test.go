package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// postSettings drives the apiSettings POST handler with a chosen remote address
// and CSRF header presence.
func postSettings(t *testing.T, body, remote string, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/settings?restart=false", strings.NewReader(body))
	req.RemoteAddr = remote
	if csrf {
		req.Header.Set("X-Requested-With", "printcap")
	}
	rec := httptest.NewRecorder()
	apiSettings(rec, req)
	return rec
}

func TestApiSettingsGetMasksSecrets(t *testing.T) {
	dashTestSetup(t)
	cfg.SNMP.Community = "topsecret"
	req := httptest.NewRequest("GET", "/api/settings", nil)
	rec := httptest.NewRecorder()
	apiSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var got Config
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SNMP.Community != secretSentinel {
		t.Fatalf("community not masked: %q", got.SNMP.Community)
	}
}

func TestApiSettingsSaveRoundTripsSecrets(t *testing.T) {
	dashTestSetup(t)
	cfg.SNMP.Community = "topsecret"

	var captured *Config
	orig := applyConfigAsync
	applyConfigAsync = func(nc *Config, restart bool) { captured = nc }
	defer func() { applyConfigAsync = orig }()

	// Client edits the masked config (community stays "***") and posts it back.
	masked := redactedConfig()
	masked.Bind = "10.1.2.3"
	b, _ := json.Marshal(masked)

	rec := postSettings(t, string(b), "127.0.0.1:5000", true)
	if rec.Code != 200 {
		t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
	}
	if captured == nil {
		t.Fatal("applyConfigAsync was not called")
	}
	if captured.Bind != "10.1.2.3" {
		t.Fatalf("bind not applied: %q", captured.Bind)
	}
	if captured.SNMP.Community != "topsecret" {
		t.Fatalf("masked secret not restored from stored config: %q", captured.SNMP.Community)
	}
}

func TestApiSettingsRejectsInvalidConfig(t *testing.T) {
	dashTestSetup(t)
	var called bool
	orig := applyConfigAsync
	applyConfigAsync = func(nc *Config, restart bool) { called = true }
	defer func() { applyConfigAsync = orig }()

	bad := redactedConfig()
	bad.Ports.IPP = 99999 // out of range -> hard validation error
	b, _ := json.Marshal(bad)

	rec := postSettings(t, string(b), "127.0.0.1:5000", true)
	if rec.Code != 400 {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if called {
		t.Fatal("invalid config must not be applied")
	}
	if !strings.Contains(rec.Body.String(), "ports.ipp") {
		t.Fatalf("error body should name the bad field: %s", rec.Body.String())
	}
}

func TestApiSettingsRemoteAdminGate(t *testing.T) {
	dashTestSetup(t)
	cfg.Dashboard.AllowRemoteAdmin = false
	orig := applyConfigAsync
	applyConfigAsync = func(nc *Config, restart bool) {}
	defer func() { applyConfigAsync = orig }()

	b, _ := json.Marshal(redactedConfig())

	// Non-loopback client is refused.
	if rec := postSettings(t, string(b), "192.0.2.50:4000", true); rec.Code != 403 {
		t.Fatalf("remote write status %d, want 403", rec.Code)
	}
	// With remote admin enabled, the same request is accepted.
	cfg.Dashboard.AllowRemoteAdmin = true
	if rec := postSettings(t, string(b), "192.0.2.50:4000", true); rec.Code != 200 {
		t.Fatalf("remote write (allowed) status %d, want 200", rec.Code)
	}
}

func TestApiSettingsRequiresCSRFHeader(t *testing.T) {
	dashTestSetup(t)
	orig := applyConfigAsync
	applyConfigAsync = func(nc *Config, restart bool) {}
	defer func() { applyConfigAsync = orig }()
	b, _ := json.Marshal(redactedConfig())
	if rec := postSettings(t, string(b), "127.0.0.1:5000", false); rec.Code != 403 {
		t.Fatalf("missing CSRF header status %d, want 403", rec.Code)
	}
}
