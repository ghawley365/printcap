package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateARPScopeDisabled(t *testing.T) {
	_, _, active, err := validateARPScope(ARPConf{Enabled: false, Targets: []string{"10.0.0.5"}}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatal("active should be false when ARP.Enabled is false")
	}
}

func TestValidateARPScopeFailClosedNoTargets(t *testing.T) {
	// Enabled but no targets => poisoning must stay OFF (no whole-subnet mode).
	_, _, active, err := validateARPScope(ARPConf{Enabled: true, Targets: nil}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if active {
		t.Fatal("active must be false with an empty target allow-list")
	}
}

func TestValidateARPScopeRejectsBadTarget(t *testing.T) {
	if _, _, _, err := validateARPScope(ARPConf{Enabled: true, Targets: []string{"not-an-ip"}}, ""); err == nil {
		t.Fatal("expected error for invalid target IP")
	}
}

func TestValidateARPScopeRejectsLoopbackAndMulticast(t *testing.T) {
	for _, bad := range []string{"127.0.0.1", "224.0.0.1", "0.0.0.0"} {
		if _, _, _, err := validateARPScope(ARPConf{Enabled: true, Targets: []string{bad}}, ""); err == nil {
			t.Errorf("target %q should be refused", bad)
		}
	}
}

func TestValidateARPScopeDedupAndGateway(t *testing.T) {
	targets, gw, active, err := validateARPScope(ARPConf{
		Enabled: true,
		Gateway: "192.168.1.1",
		Targets: []string{"192.168.1.50", "192.168.1.50", "192.168.1.51"},
	}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active {
		t.Fatal("active should be true with valid targets")
	}
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2 (deduped)", len(targets))
	}
	if !gw.IsValid() || gw.String() != "192.168.1.1" {
		t.Fatalf("gateway = %v, want 192.168.1.1", gw)
	}
}

func TestValidateARPScopeRejectsBadGateway(t *testing.T) {
	if _, _, _, err := validateARPScope(ARPConf{Enabled: true, Gateway: "nope", Targets: []string{"10.0.0.2"}}, ""); err == nil {
		t.Fatal("expected error for invalid gateway IP")
	}
}

func TestValidateARPScopeIncludesMFP(t *testing.T) {
	// The MFP IP becomes an in-scope ARP target even with no explicit targets.
	targets, _, active, err := validateARPScope(ARPConf{Enabled: true}, "192.168.1.50")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !active || len(targets) != 1 || targets[0].String() != "192.168.1.50" {
		t.Fatalf("MFP not adopted as ARP target: active=%v targets=%v", active, targets)
	}
}

// authorizedConf returns an InterceptConf that passes the authorization gate, so
// tests can mutate one field to assert a specific rejection.
func authorizedConf() InterceptConf {
	return InterceptConf{
		Enabled: true,
		Authorization: AuthorizationConf{
			Acknowledged: true,
			Operator:     "tester",
			Engagement:   "ENG-1",
		},
	}
}

func TestAuthorizeInterceptOK(t *testing.T) {
	if err := authorizeIntercept(authorizedConf()); err != nil {
		t.Fatalf("fully-authorized config should pass, got: %v", err)
	}
}

func TestAuthorizeInterceptRequiresAcknowledgement(t *testing.T) {
	c := authorizedConf()
	c.Authorization.Acknowledged = false
	if err := authorizeIntercept(c); err == nil {
		t.Fatal("must refuse when authorization is not acknowledged")
	}
}

func TestAuthorizeInterceptRequiresOperatorAndEngagement(t *testing.T) {
	c := authorizedConf()
	c.Authorization.Operator = "   "
	if err := authorizeIntercept(c); err == nil {
		t.Fatal("must refuse when operator is blank")
	}
	c = authorizedConf()
	c.Authorization.Engagement = ""
	if err := authorizeIntercept(c); err == nil {
		t.Fatal("must refuse when engagement is blank")
	}
}

func TestAuthorizeInterceptExpiry(t *testing.T) {
	c := authorizedConf()
	c.Authorization.Expiry = "garbage"
	if err := authorizeIntercept(c); err == nil {
		t.Fatal("must refuse an unparseable expiry")
	}
	c.Authorization.Expiry = "2000-01-01"
	if err := authorizeIntercept(c); err == nil {
		t.Fatal("must refuse a past expiry")
	}
	c.Authorization.Expiry = "2999-12-31"
	if err := authorizeIntercept(c); err != nil {
		t.Fatalf("future expiry should pass, got: %v", err)
	}
}

func TestParseAuthExpiryForms(t *testing.T) {
	if _, ok := parseAuthExpiry(""); !ok {
		t.Fatal("blank expiry should be ok (no expiry)")
	}
	if _, ok := parseAuthExpiry("2026-12-31"); !ok {
		t.Fatal("YYYY-MM-DD should parse")
	}
	if _, ok := parseAuthExpiry("2026-12-31T23:59:59Z"); !ok {
		t.Fatal("RFC3339 should parse")
	}
	if _, ok := parseAuthExpiry("nope"); ok {
		t.Fatal("garbage should not parse")
	}
}

// TestStartInterceptorRefusesUnauthorized ensures the gate fires before any
// platform hook (live source) is touched.
func TestStartInterceptorRefusesUnauthorized(t *testing.T) {
	c := authorizedConf()
	c.Authorization.Acknowledged = false
	if _, err := startInterceptor(c); err == nil {
		t.Fatal("startInterceptor must refuse an unauthorized config")
	}
}

// TestInterceptorPumpWritesPcap drives the platform-neutral pump loop with an
// in-memory source and asserts the frames land in a readable pcap file. This is
// the loopback-style acceptance test for the capture pipeline minus the OS hook.
func TestInterceptorPumpWritesPcap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.pcap")
	pw, err := newPcapFile(path, 0, linkTypeEthernet)
	if err != nil {
		t.Fatalf("newPcapFile: %v", err)
	}
	ts := time.Unix(1717459200, 0)
	src := newSliceSource(linkTypeEthernet, []capturedPacket{
		{ts: ts, data: []byte{0xaa, 0xbb, 0xcc}},
		{ts: ts, data: []byte{0x01, 0x02}},
	})
	it := &interceptor{conf: InterceptConf{}, src: src, pw: pw, done: make(chan struct{})}
	it.wg.Add(1)
	go func() { defer it.wg.Done(); it.pump() }()

	// The slice source closes its channel after emitting; pump returns, then Close
	// flushes. Give the goroutine a moment, then tear down deterministically.
	time.Sleep(20 * time.Millisecond)
	if err := it.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if pkts, _ := pw.stats(); pkts != 2 {
		t.Fatalf("captured %d packets, want 2", pkts)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pcap: %v", err)
	}
	// 24 (global) + 2*(16 record hdr) + 3 + 2 payload = 61 bytes.
	if info.Size() != 61 {
		t.Errorf("pcap size = %d, want 61", info.Size())
	}
}
