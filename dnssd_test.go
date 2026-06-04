package main

import (
	"strings"
	"testing"
)

func testCfg() *Config {
	c := defaultConfig()
	c.Printer.Name = "printcap"
	c.Printer.MakeAndModel = "printcap Virtual MFP"
	c.Printer.Location = "lab"
	c.Printer.Color = true
	return c
}

func TestBuildServicesMirrorsListeners(t *testing.T) {
	cfg = testCfg()
	bl := boundListeners{IPP: 631, Raw9100: 9100, LPR: 515}
	svcs := buildServices(bl, true, "printcap")
	types := map[string]service{}
	for _, s := range svcs {
		types[s.svcType] = s
	}
	if _, ok := types["_ipp._tcp"]; !ok {
		t.Error("expected _ipp._tcp advertised")
	}
	if _, ok := types["_pdl-datastream._tcp"]; !ok {
		t.Error("expected _pdl-datastream._tcp advertised")
	}
	if _, ok := types["_printer._tcp"]; !ok {
		t.Error("expected _printer._tcp advertised")
	}
	if _, ok := types["_ipps._tcp"]; ok {
		t.Error("_ipps._tcp must NOT be advertised when IPPS is off")
	}
}

func TestIPPTxtHasURFButPrinterDoesNot(t *testing.T) {
	cfg = testCfg()
	svcs := buildServices(boundListeners{IPP: 631, LPR: 515}, true, "printcap")
	for _, s := range svcs {
		joined := strings.Join(s.txt, ",")
		switch s.svcType {
		case "_ipp._tcp":
			if !strings.Contains(joined, "URF=") {
				t.Errorf("_ipp TXT missing URF: %v", s.txt)
			}
			if !strings.Contains(joined, "rp=ipp/print") {
				t.Errorf("_ipp TXT missing rp=ipp/print: %v", s.txt)
			}
			if !hasPair(s.txt, "Color", "T") {
				t.Errorf("_ipp TXT missing Color=T: %v", s.txt)
			}
		case "_printer._tcp":
			if strings.Contains(joined, "URF=") {
				t.Errorf("_printer TXT must not contain URF: %v", s.txt)
			}
		}
	}
}

func TestIPPSubtypesIncludeAirPrint(t *testing.T) {
	cfg = testCfg()
	svcs := buildServices(boundListeners{IPP: 631}, true, "printcap")
	for _, s := range svcs {
		if s.svcType == "_ipp._tcp" {
			if !containsStr(s.subtypes, "_universal") {
				t.Errorf("expected _universal sub-type, got %v", s.subtypes)
			}
		}
	}
}

func TestURFTxtDerivesFromURFSupported(t *testing.T) {
	if urfTxt() != strings.Join(urfSupported(), ",") {
		t.Fatalf("urfTxt %q must equal join(urfSupported())", urfTxt())
	}
}

func TestResolveInstanceDefaultsToPrinterName(t *testing.T) {
	cfg = testCfg()
	cfg.MDNS = MDNSConf{Enabled: true}
	if got := resolveInstance(); got != "printcap" {
		t.Fatalf("got %q", got)
	}
	cfg.MDNS.Instance = "Lobby MFP"
	if got := resolveInstance(); got != "Lobby MFP" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveHostSanitizes(t *testing.T) {
	cfg = testCfg()
	cfg.MDNS = MDNSConf{}
	cfg.Printer.Name = "Lobby MFP #2"
	if got := resolveHost(); got != "Lobby-MFP-2.local" {
		t.Fatalf("got %q", got)
	}
}

func hasPair(txt []string, k, v string) bool {
	for _, p := range txt {
		if p == k+"="+v {
			return true
		}
	}
	return false
}

// containsStr is a test-only helper (string-slice membership). The production
// code uses contains-by-byte in pdl.go; this lives with the tests that need it.
func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
