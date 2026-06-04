package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestEngineRestartUnderLoadNoRace(t *testing.T) {
	cfg = defaultConfig()
	cfg.Bind = "127.0.0.1"
	cfg.OutDir = t.TempDir()
	// Disable everything except a raw/9100 listener on a high port to keep the
	// test hermetic and privileged-port-free.
	cfg.Ports = Ports{Raw9100: 19100}
	cfg.SNMP.Enabled = false
	cfg.Dashboard.Enabled = false
	cfg.MDNS.Enabled = false
	cfg.Forward.Enabled = false

	if _, err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	// Hammer the raw port with concurrent jobs while restarting the engine.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := net.DialTimeout("tcp", "127.0.0.1:19100", 200*time.Millisecond)
				if err != nil {
					continue // listener may be momentarily down during restart
				}
				_, _ = c.Write([]byte(fmt.Sprintf("PCL job %d\n", i)))
				_ = c.Close()
			}
		}()
	}
	// Restart a few times while under load.
	for i := 0; i < 3; i++ {
		time.Sleep(50 * time.Millisecond)
		engine.Stop()
		if _, err := engine.Start(); err != nil {
			t.Errorf("restart %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	engine.Stop()
}
