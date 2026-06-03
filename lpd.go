package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
)

// serveLPD implements just enough of the LPD protocol (RFC 1179) to accept a
// job from an LPR client. Unlike raw/9100, LPD is a conversation: for every
// sub-command the daemon must reply with a single 0x00 "positive acknowledge"
// byte or the client tears the connection down. The job arrives as two parts —
// a *control file* (ASCII metadata: host, user, job name) and a *data file*
// (the actual spool bytes).
func serveLPD(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleLPD(conn)
	}
}

func handleLPD(conn net.Conn) {
	defer conn.Close()
	// Read through an idle-timeout wrapper so a stalled client can't pin this
	// goroutine open forever.
	r := bufio.NewReader(idleConn{Conn: conn, idle: idleReadTimeout})
	j := newJob("LPR", conn.RemoteAddr().String())

	// First byte selects the top-level command. 0x02 = "receive a printer job";
	// the query/remove commands (0x01,0x03,0x04,0x05) we just acknowledge.
	src := conn.RemoteAddr().String()
	logProto("LPR", "connection from %s", src)

	// Source-port policy. RFC 1179 says clients should use privileged source
	// ports 721-731, but enterprise senders (SAP, AS/400, appliances) vary, so
	// we accept any source port by default and only enforce when configured.
	if cfg.LPD.RequirePrivilegedSourcePort && !isPrivilegedSource(conn) {
		logWarn("LPR", "rejected %s: non-privileged source port (policy requires 721-731)", src)
		return
	}

	cmd, err := r.ReadByte()
	if err != nil {
		return
	}
	if cmd != 0x02 {
		logDebug("LPR", "non-job command 0x%02x from %s (status/query)", cmd, src)
		ackOK(conn) // status/query commands (1,3,4,5): be polite, then drop
		return
	}
	queue := strings.TrimSpace(readLine(r))
	if !queueAllowed(queue) {
		logWarn("LPR", "rejected job from %s: queue %q not in allow-list", src, queue)
		conn.Write([]byte{0x01}) // negative acknowledgement: queue not accepted
		return
	}
	j.Queue = queue
	logProto("LPR", "accepted job for queue %q from %s", queue, src)
	ackOK(conn)

	for {
		sub, err := r.ReadByte()
		if err != nil {
			break
		}
		switch sub {
		case 0x01: // abort
			logTrace("LPR", "subcommand: abort")
			ackOK(conn)
		case 0x02: // receive control file: "<count> <name>\n"
			count, _ := parseCountName(readLine(r))
			logTrace("LPR", "subcommand: receive control file (%d bytes)", count)
			ackOK(conn)
			ctrl, _ := readChunk(r, count, maxControlFileBytes) // metadata is tiny
			r.ReadByte()                                        // trailing 0x00 terminator
			ackOK(conn)
			parseControlFile(ctrl, j)
			logTrace("LPR", "control file: host=%q user=%q job=%q", j.Host, j.User, j.JobName)
		case 0x03: // receive data file: "<count> <name>\n"
			count, _ := parseCountName(readLine(r))
			logTrace("LPR", "subcommand: receive data file (declared %d bytes)", count)
			ackOK(conn)
			data, capped := readChunk(r, count, jobByteCap())
			j.data = data
			j.Bytes = len(data)
			if capped {
				// We hit the byte cap mid-stream; the connection is no longer
				// in sync with the protocol, so save what we have and stop.
				ackOK(conn)
				if len(j.data) > 0 {
					if err := sink.save(j); err != nil {
						logWarn("LPR", "forward (block) failed: %v", err)
						return
					}
				}
				return
			}
			if count > 0 {
				r.ReadByte() // trailing 0x00 terminator
			}
			ackOK(conn)
		default:
			return
		}
	}

	if len(j.data) > 0 {
		// Control-file H/P/J win; PJL inside the data fills any gaps.
		if cfg.LPD.ParsePJL && (j.JobName == "" || j.User == "") {
			name, user := parsePJL(j.data)
			if j.JobName == "" {
				j.JobName = name
			}
			if j.User == "" {
				j.User = user
			}
		}
		if err := sink.save(j); err != nil {
			logWarn("LPR", "forward (block) failed: %v", err)
			return
		}
	}
}

// isPrivilegedSource reports whether the client's source port is < 1024
// (RFC 1179 specifies 721-731; we accept the whole privileged range).
func isPrivilegedSource(conn net.Conn) bool {
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return ta.Port > 0 && ta.Port < 1024
	}
	return false
}

// queueAllowed applies the configured queue-name policy. The default is fully
// permissive (accept any queue) so jobs from any spooler are captured; the
// queue name itself is always recorded.
func queueAllowed(queue string) bool {
	if cfg.LPD.AcceptAnyQueue || len(cfg.LPD.AllowedQueues) == 0 {
		return true
	}
	for _, q := range cfg.LPD.AllowedQueues {
		if strings.EqualFold(q, queue) {
			return true
		}
	}
	return false
}

// readChunk reads an LPD file part. It NEVER pre-allocates from the untrusted
// count — the buffer grows only as bytes actually arrive (io.CopyN uses a fixed
// internal buffer), so a bogus "count=2000000000" can't exhaust memory. When
// count > 0 it reads exactly that many bytes; when count <= 0 the length is
// unknown and it streams to EOF. It never exceeds cap bytes (0 = unlimited);
// the bool reports whether the cap clipped the data.
func readChunk(r *bufio.Reader, count int, cap int64) ([]byte, bool) {
	var buf bytes.Buffer
	if count > 0 {
		if cap > 0 && int64(count) > cap {
			io.CopyN(&buf, r, cap) // oversized claim: stop at the cap
			return buf.Bytes(), true
		}
		io.CopyN(&buf, r, int64(count))
		return buf.Bytes(), false
	}
	// Unknown length: stream to EOF, bounded by cap when set.
	if cap > 0 {
		n, _ := io.CopyN(&buf, r, cap)
		return buf.Bytes(), n == cap // capped only if we actually reached the cap
	}
	io.Copy(&buf, r)
	return buf.Bytes(), false
}

// ackOK sends the single-byte positive acknowledgement the protocol requires.
func ackOK(conn net.Conn) { conn.Write([]byte{0x00}) }

// readLine reads through the next '\n', returning the line without its CR/LF.
func readLine(r *bufio.Reader) string {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

// parseCountName splits an LPD sub-command argument "<count> <name>".
func parseCountName(s string) (int, string) {
	parts := strings.SplitN(strings.TrimSpace(s), " ", 2)
	n, _ := strconv.Atoi(parts[0])
	name := ""
	if len(parts) > 1 {
		name = parts[1]
	}
	return n, name
}

// parseControlFile reads the ASCII control file. Each line begins with a
// single command letter; we care about H (host), P (user), and J (job name).
func parseControlFile(ctrl []byte, j *job) {
	for _, line := range strings.Split(string(ctrl), "\n") {
		if line == "" {
			continue
		}
		key, val := line[0], strings.TrimRight(line[1:], "\r")
		switch key {
		case 'H':
			j.Host = val
		case 'P':
			j.User = val
		case 'J':
			j.JobName = val
		}
	}
}
