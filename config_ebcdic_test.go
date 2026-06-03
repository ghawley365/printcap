package main

import "testing"

func TestEBCDICDefaults(t *testing.T) {
	c := defaultConfig()
	if !c.EBCDIC.Enabled || c.EBCDIC.DefaultCodePage != "CP037" {
		t.Fatalf("unexpected EBCDIC defaults: %+v", c.EBCDIC)
	}
	if c.LPD.QueueDefaults == nil {
		t.Fatal("QueueDefaults map should be initialized")
	}
}
