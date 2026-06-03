package main

import (
	"net"
)

// serveRaw9100 implements the "raw", "JetDirect" or "AppSocket" protocol used
// on TCP 9100. There is no protocol at all: the sender opens a socket, streams
// the page-description-language data, and closes the connection. We simply read
// to EOF and treat the entire stream as one job. The accept loop exits when the
// Engine closes the listener.
func serveRaw9100(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleRaw9100(conn)
	}
}

func handleRaw9100(conn net.Conn) {
	defer conn.Close()
	src := conn.RemoteAddr().String()
	logProto("9100", "connection from %s", src)
	// Read until the client closes, bounded by an idle timeout (no goroutine
	// leak on half-open sockets) and the per-job byte cap (bounded memory).
	data := readStream(idleConn{Conn: conn, idle: idleReadTimeout}, jobByteCap())
	if len(data) == 0 {
		logDebug("9100", "connection from %s closed with no data (probe)", src)
		return // a bare TCP probe (e.g. a port scanner) — nothing to save
	}
	logProto("9100", "read %d bytes from %s", len(data), src)
	saveRawStream("9100", src, data)
}

// saveRawStream applies the configured raw-protocol options (PJL metadata
// parsing, optional UEL job splitting) and persists the resulting job(s). Many
// enterprise spoolers send several print jobs back-to-back on one 9100
// connection, each framed by the Universal Exit Language — split_on_uel
// captures each as its own job.
func saveRawStream(proto, src string, data []byte) {
	segments := [][]byte{data}
	if cfg.Raw.SplitOnUEL {
		segments = splitUEL(data)
		if len(segments) > 1 {
			logDebug(proto, "split connection into %d jobs at UEL boundaries", len(segments))
		}
	}
	for _, seg := range segments {
		j := newJob(proto, src)
		if cfg.Raw.ParsePJL {
			if name, user := parsePJL(seg); name != "" || user != "" {
				j.JobName, j.User = name, user
			}
		}
		j.data = seg
		j.Bytes = len(seg)
		if err := sink.save(j); err != nil {
			logWarn(proto, "forward (block) failed, dropping connection: %v", err)
			return
		}
	}
}
