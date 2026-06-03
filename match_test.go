package main

import "testing"

func mkCond(t *testing.T, c ForwardCond) *compiledCond {
	cc, err := compileCond(c)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

func TestCondEmptyMatchesAlways(t *testing.T) {
	if !mkCond(t, ForwardCond{}).matches(&job{}, nil) {
		t.Fatal("empty condition should always match")
	}
}

func TestCondProtocolAndSource(t *testing.T) {
	c := mkCond(t, ForwardCond{Protocols: []string{"IPP"}, SourceCIDRs: []string{"10.0.0.0/24"}})
	j := &job{Protocol: "IPP", Source: "10.0.0.5:5000"}
	if !c.matches(j, nil) {
		t.Fatal("should match IPP from 10.0.0.5")
	}
	j2 := &job{Protocol: "IPP", Source: "192.168.1.5:5000"}
	if c.matches(j2, nil) {
		t.Fatal("should not match wrong subnet")
	}
}

func TestCondJobNameGlobAndRegex(t *testing.T) {
	g := mkCond(t, ForwardCond{JobName: "*invoice*"})
	if !g.matches(&job{JobName: "april-invoice.pdf"}, nil) {
		t.Fatal("glob should match")
	}
	r := mkCond(t, ForwardCond{JobName: `/^INV\d+/`})
	if !r.matches(&job{JobName: "INV42"}, nil) {
		t.Fatal("regex should match")
	}
}

func TestCondContainsModes(t *testing.T) {
	lit := mkCond(t, ForwardCond{Contains: "@PJL"})
	if !lit.matches(&job{}, []byte("\x1b%-12345X@PJL SET")) {
		t.Fatal("literal contains should match")
	}
	hx := mkCond(t, ForwardCond{Contains: "hex:1b45"})
	if !hx.matches(&job{}, []byte{0x00, 0x1b, 0x45}) {
		t.Fatal("hex contains should match")
	}
	re := mkCond(t, ForwardCond{Contains: `/PJL\s+SET/`})
	if !re.matches(&job{}, []byte("@PJL  SET")) {
		t.Fatal("regex contains should match")
	}
}

func TestCondSizeBounds(t *testing.T) {
	c := mkCond(t, ForwardCond{MinBytes: 2, MaxBytes: 4})
	if c.matches(&job{}, []byte("x")) {
		t.Fatal("under min should not match")
	}
	if !c.matches(&job{}, []byte("xxx")) {
		t.Fatal("in range should match")
	}
	if c.matches(&job{}, []byte("xxxxx")) {
		t.Fatal("over max should not match")
	}
}

func TestCondPDLAndDocFormat(t *testing.T) {
	c := mkCond(t, ForwardCond{PDLs: []string{"PCL"}, DocFormats: []string{"application/pdf"}})
	if !c.matches(&job{PDL: "PCL", DocFormat: "application/pdf"}, nil) {
		t.Fatal("should match PDL+docformat")
	}
}
