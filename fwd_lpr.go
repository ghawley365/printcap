package main

import (
	"bufio"
	"fmt"
	"net"
	"time"
)

type lprTransport struct{}

// send implements the RFC 1179 client side: receive-job, then control file then
// data file, reading the single-byte ACK after each step.
func (lprTransport) send(t *target, data []byte, j *job) error {
	to := t.timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	queue := t.queue
	if queue == "" || queue == "auto" {
		queue = orElse(j.Queue, "lp")
	}

	conn, err := dialMaybePrivileged(t.address, t.privPort, to)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(to))
	r := bufio.NewReader(conn)

	// 0x02 <queue>\n  — receive a printer job.
	if _, err := fmt.Fprintf(conn, "\x02%s\n", queue); err != nil {
		return err
	}
	if err := expectAck(r); err != nil {
		return fmt.Errorf("receive-job rejected: %w", err)
	}

	host := orElse(j.Host, "printcap")
	user := orElse(j.User, "printcap")
	name := orElse(j.JobName, "job")
	dfName := "dfA001" + host
	cfName := "cfA001" + host
	ctrl := fmt.Sprintf("H%s\nP%s\nJ%s\nf%s\n", host, user, name, dfName)

	// 0x02 <len> <cfname>\n  (control file sub-command)
	if err := sendLPRFile(conn, r, 0x02, cfName, []byte(ctrl)); err != nil {
		return fmt.Errorf("control file: %w", err)
	}
	// 0x03 <len> <dfname>\n  (data file sub-command)
	if err := sendLPRFile(conn, r, 0x03, dfName, data); err != nil {
		return fmt.Errorf("data file: %w", err)
	}
	return nil
}

func sendLPRFile(conn net.Conn, r *bufio.Reader, sub byte, name string, body []byte) error {
	if _, err := fmt.Fprintf(conn, "%c%d %s\n", sub, len(body), name); err != nil {
		return err
	}
	if err := expectAck(r); err != nil {
		return err
	}
	if _, err := conn.Write(body); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x00}); err != nil { // terminator
		return err
	}
	return expectAck(r)
}

func expectAck(r *bufio.Reader) error {
	b, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b != 0x00 {
		return fmt.Errorf("negative acknowledgement 0x%02x", b)
	}
	return nil
}

// dialMaybePrivileged optionally binds a privileged local source port (721-731)
// for strict downstream daemons; falls back to an ephemeral port.
func dialMaybePrivileged(addr string, priv bool, to time.Duration) (net.Conn, error) {
	if !priv {
		return net.DialTimeout("tcp", addr, to)
	}
	d := net.Dialer{Timeout: to}
	for p := 721; p <= 731; p++ {
		d.LocalAddr = &net.TCPAddr{Port: p}
		if c, err := d.Dial("tcp", addr); err == nil {
			return c, nil
		}
	}
	return net.DialTimeout("tcp", addr, to)
}
