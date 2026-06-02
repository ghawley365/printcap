package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSNMPv3DefaultsAndRedaction(t *testing.T) {
	cfg = defaultConfig()
	cfg.SNMP.V3Enabled = true
	cfg.SNMP.Users = []SNMPUser{{Name: "admin", Level: "authPriv",
		AuthProtocol: "SHA-256", AuthPass: "topsecret", PrivProtocol: "AES-128", PrivPass: "topsecret2"}}

	red := redactedConfig()
	b, _ := json.Marshal(red)
	s := string(b)
	if strings.Contains(s, "topsecret") {
		t.Fatalf("passphrase leaked in redacted config: %s", s)
	}
}

func TestEngineIDGeneration(t *testing.T) {
	id := generateEngineID("printhost")
	if len(id) < 5 || len(id) > 32 {
		t.Fatalf("engineID length %d out of RFC range", len(id))
	}
	if id[0]&0x80 == 0 {
		t.Fatal("engineID high bit must be set (RFC 3411 new format)")
	}
}
