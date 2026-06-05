package main

import "testing"

// hasFieldError reports whether issues contains an error for the given field.
func hasFieldError(issues []configIssue, field string) bool {
	for _, is := range issues {
		if is.Severity == sevError && is.Field == field {
			return true
		}
	}
	return false
}

func TestValidateInterceptCarvePortRange(t *testing.T) {
	c := defaultConfig()
	c.Intercept.Enabled = true
	c.Intercept.Authorization = AuthorizationConf{Acknowledged: true, Operator: "t", Engagement: "E"}
	c.Intercept.Carve.Enabled = true
	c.Intercept.Carve.Ports = []int{9100, 70000} // second is out of range
	if !hasFieldError(validateIntercept(c), "intercept.carve.ports[1]") {
		t.Fatal("expected out-of-range carve port to be a hard error")
	}
}

func TestValidateInterceptNegativeNumerics(t *testing.T) {
	c := defaultConfig()
	c.Intercept.Enabled = true
	c.Intercept.Authorization = AuthorizationConf{Acknowledged: true, Operator: "t", Engagement: "E"}
	c.Intercept.Carve.MaxStreamMB = -1
	if !hasFieldError(validateIntercept(c), "intercept.carve.max_stream_mb") {
		t.Fatal("expected negative max_stream_mb to be a hard error")
	}
}

func TestValidateInterceptBadARPIP(t *testing.T) {
	c := defaultConfig()
	c.Intercept.Enabled = true
	c.Intercept.Authorization = AuthorizationConf{Acknowledged: true, Operator: "t", Engagement: "E"}
	c.Intercept.ARP.Enabled = true
	c.Intercept.ARP.Targets = []string{"10.0.0.5", "not-an-ip"}
	c.Intercept.ARP.Gateway = "also-bad"
	issues := validateIntercept(c)
	if !hasFieldError(issues, "intercept.arp.targets[1]") {
		t.Fatal("expected bad ARP target IP to be a hard error")
	}
	if !hasFieldError(issues, "intercept.arp.gateway") {
		t.Fatal("expected bad ARP gateway IP to be a hard error")
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, want int64 }{
		{5, 0, 10, 5}, {-3, 0, 10, 0}, {99, 0, 10, 10}, {10, 0, 10, 10},
	}
	for _, c := range cases {
		if got := clampInt(c.v, c.lo, c.hi); got != c.want {
			t.Errorf("clampInt(%d,%d,%d)=%d want %d", c.v, c.lo, c.hi, got, c.want)
		}
	}
}

func TestEngineStoppingClosedWhenIdle(t *testing.T) {
	// A never-started engine reports an already-closed stopping channel so SSE
	// handlers never block on a nil channel.
	e := &Engine{}
	select {
	case <-e.Stopping():
	default:
		t.Fatal("Stopping() on an unstarted engine should be already closed")
	}
}
