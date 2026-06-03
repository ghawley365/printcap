package main

import (
	"net"
	"testing"
	"time"
)

func TestRawTransportDelivers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()

	tr := rawTransport{}
	tg := &target{address: ln.Addr().String(), timeout: 2 * time.Second}
	if err := tr.send(tg, []byte("HELLO"), &job{}); err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case b := <-got:
		if string(b) != "HELLO" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for bytes")
	}
}

func TestRawTransportDeadAddressErrors(t *testing.T) {
	tr := rawTransport{}
	tg := &target{address: "127.0.0.1:1", timeout: 500 * time.Millisecond}
	if err := tr.send(tg, []byte("X"), &job{}); err == nil {
		t.Fatal("expected error dialing dead address")
	}
}
