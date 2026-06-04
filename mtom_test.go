package main

import (
	"bytes"
	"testing"
)

func TestExtractMTOM(t *testing.T) {
	ct := `multipart/related; boundary=BND; type="application/xop+xml"; start="<root>"`
	body := "--BND\r\nContent-ID: <root>\r\n\r\n<env><xop:Include href=\"cid:doc\"/></env>\r\n" +
		"--BND\r\nContent-ID: <doc>\r\n\r\nDOCBYTES\r\n--BND--\r\n"
	root, parts, err := extractMTOM(ct, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if string(parts["doc"]) != "DOCBYTES" {
		t.Fatalf("attachment bytes wrong: %q", parts["doc"])
	}
	if !bytes.Contains(root, []byte("Include")) {
		t.Fatalf("root part wrong: %s", root)
	}
}

func TestExtractMTOMNotMultipart(t *testing.T) {
	if _, _, err := extractMTOM("application/soap+xml", []byte("<x/>")); err == nil {
		t.Fatal("non-multipart content type should error")
	}
}
