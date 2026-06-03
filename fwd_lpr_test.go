package main

import (
    "net"
    "testing"
    "time"
)

func TestLPRTransportToOwnServer(t *testing.T) {
    cfg = defaultConfig()
    cfg.OutDir = t.TempDir()
    sink = &captureSink{dir: cfg.OutDir}
    store = newJobStore(10)

    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    go serveLPD(ln)

    tr := lprTransport{}
    tg := &target{address: ln.Addr().String(), timeout: 2 * time.Second, queue: "lp"}
    j := &job{Host: "client1", User: "alice", JobName: "report"}
    if err := tr.send(tg, []byte("PCL-DATA"), j); err != nil {
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
        t.Fatal("LPD server captured no job from the LPR client")
    }
    if jobs[0].User != "alice" || jobs[0].Host != "client1" {
        t.Fatalf("control-file metadata not delivered: %+v", jobs[0])
    }
}
