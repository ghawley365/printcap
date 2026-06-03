package main

import (
	"net"
	"time"
)

type rawTransport struct{}

func (rawTransport) send(t *target, data []byte, j *job) error {
	to := t.timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	conn, err := net.DialTimeout("tcp", t.address, to)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(to))
	_, err = conn.Write(data)
	return err
}
