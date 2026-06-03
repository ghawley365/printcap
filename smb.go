package main

import "net"

// serveSMB accepts connections on the SMB print-share listener. The per-
// connection SMB2/3 + NTLMv2 + spoolss state machine is implemented in later
// stages; for now each connection is accepted and immediately closed.
func serveSMB(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSMBConn(c)
	}
}

// handleSMBConn drives one SMB connection. Stub until the protocol stages land.
func handleSMBConn(c net.Conn) {
	defer c.Close()
}
