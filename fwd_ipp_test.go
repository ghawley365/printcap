package main

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestIPPTransportToOwnHandler(t *testing.T) {
	cfg = defaultConfig()
	cfg.OutDir = t.TempDir()
	sink = &captureSink{dir: cfg.OutDir}
	store = newJobStore(10)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(ippHandler)}
	go srv.Serve(ln)
	defer srv.Close()

	tr := ippTransport{}
	tg := &target{
		transport: "ipp",
		address:   "ipp://" + ln.Addr().String() + "/ipp/print",
		timeout:   2 * time.Second,
		docFormat: "application/pdf",
	}
	j := &job{User: "bob", JobName: "memo"}
	if err := tr.send(tg, []byte("%PDF-1.4 hi"), j); err != nil {
		t.Fatalf("send: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.recent(10)) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	jobs := store.recent(10)
	if len(jobs) == 0 {
		t.Fatal("IPP handler captured no job from the IPP client")
	}
	if jobs[0].User != "bob" || jobs[0].DocFormat != "application/pdf" {
		t.Fatalf("IPP attributes not delivered: %+v", jobs[0])
	}
}
