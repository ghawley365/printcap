package main

import (
	"strings"
	"testing"
)

// hasIssue reports whether any issue matches the given severity and contains
// substr (case-insensitive) in its Field, Message, or Fix.
func hasIssue(issues []configIssue, sev validationSeverity, substr string) bool {
	s := strings.ToLower(substr)
	for _, is := range issues {
		if is.Severity != sev {
			continue
		}
		if strings.Contains(strings.ToLower(is.Field), s) ||
			strings.Contains(strings.ToLower(is.Message), s) ||
			strings.Contains(strings.ToLower(is.Fix), s) {
			return true
		}
	}
	return false
}

func TestValidateDuplicatePorts(t *testing.T) {
	c := defaultConfig()
	c.Ports.IPP = 9000
	c.Ports.Dashboard = 9000 // clash
	issues := validateConfig(c)
	if !hasIssue(issues, sevError, "9000") {
		t.Fatalf("expected duplicate-port error, got %v", issues)
	}
}

func TestValidateAutoTLSNotAClash(t *testing.T) {
	c := defaultConfig()
	c.Ports.AutoTLS = 6310
	c.Ports.IPP = 6310 // intentional merge, not a clash
	c.Ports.IPPS = 0
	c.Ports.Dashboard = 0
	for _, is := range validateConfig(c) {
		if is.Severity == sevError && strings.Contains(is.Message, "6310") {
			t.Fatalf("auto-tls/ipp merge must not be a clash: %v", is)
		}
	}
}

func TestValidateBadEnums(t *testing.T) {
	c := defaultConfig()
	c.Save = "everything"     // invalid
	c.Log.Level = "screaming" // invalid
	issues := validateConfig(c)
	if !hasIssue(issues, sevError, "save") || !hasIssue(issues, sevError, "level") {
		t.Fatalf("expected enum errors, got %v", issues)
	}
}

func TestValidatePortRange(t *testing.T) {
	c := defaultConfig()
	c.Ports.IPP = 70000
	if !hasIssue(validateConfig(c), sevError, "65535") {
		t.Fatal("expected out-of-range port error")
	}
}

func TestValidateMissingCert(t *testing.T) {
	c := defaultConfig()
	c.TLS.CertFile = "/nonexistent/cert.pem"
	c.TLS.KeyFile = "/nonexistent/key.pem"
	if !hasIssue(validateConfig(c), sevError, "cert") {
		t.Fatal("expected missing-cert error")
	}
}

func TestValidateCleanConfigNoErrors(t *testing.T) {
	c := defaultConfig()
	c.OutDir = t.TempDir()
	c.Storage.SpoolDir = t.TempDir()
	if hasErrors(validateConfig(c)) {
		t.Fatalf("default config should have no errors: %v", validateConfig(c))
	}
}
