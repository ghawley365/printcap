package main

import "testing"

func TestParseControlFileRicherFields(t *testing.T) {
	ctrl := []byte("Hmainframe\nProot\nJPayroll\nCblue\nTReport Title\nNdfA001host\nrdfA001host\n")
	j := &job{}
	parseControlFile(ctrl, j)
	if j.Host != "mainframe" || j.User != "root" || j.JobName != "Payroll" {
		t.Fatalf("base fields: %+v", j)
	}
	if j.Class != "blue" || j.Title != "Report Title" {
		t.Fatalf("rich fields: class=%q title=%q", j.Class, j.Title)
	}
}

func TestControlFormatLetterHintsASA(t *testing.T) {
	if controlCarriageHint([]byte("Hh\nrdfA001\n")) != "asa" {
		t.Fatal("expected 'r' to hint asa")
	}
	if controlCarriageHint([]byte("Hh\nfdfA001\n")) != "" {
		t.Fatal("expected no hint for 'f'")
	}
}
