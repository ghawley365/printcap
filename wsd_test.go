package main

import "testing"

func TestWSDDefaults(t *testing.T) {
	cfg = defaultConfig()
	if cfg.WSD.Enabled || cfg.WSD.Port != 3911 || !cfg.WSD.Discovery {
		t.Fatalf("unexpected WSD defaults: %+v", cfg.WSD)
	}
}

func TestDeviceUUIDStable(t *testing.T) {
	a := deviceUUID("printhost")
	b := deviceUUID("printhost")
	if a != b {
		t.Fatalf("uuid unstable: %q vs %q", a, b)
	}
	if len(a) != len("urn:uuid:00000000-0000-0000-0000-000000000000") {
		t.Fatalf("uuid malformed length: %q", a)
	}
	// Different hosts → different UUIDs.
	if deviceUUID("other") == a {
		t.Fatal("uuid should vary by host")
	}
}
