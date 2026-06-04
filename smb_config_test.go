package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSMBDefaultsAndRedaction(t *testing.T) {
	cfg = defaultConfig()
	if cfg.SMB.Enabled || cfg.SMB.Port != 4445 {
		t.Fatalf("unexpected SMB defaults: %+v", cfg.SMB)
	}
	cfg.SMB.Users = []SMBUser{{User: "print", Password: "secret", Domain: "WORKGROUP"}}
	b, _ := json.Marshal(redactedConfig())
	if strings.Contains(string(b), "secret") {
		t.Fatal("SMB password leaked in redacted config")
	}
}
