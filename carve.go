package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The pcap-carver turns reassembled print-port TCP streams back into jobs and
// hands them to the same captureSink the live listeners use, so a stream pulled
// off the wire in intercept mode gets the identical detectPDL/extForFormat
// treatment: a .jpg is saved as .jpg, a PCL stream as .pcl, and so on, with the
// same dashboard/DLP/forwarding feed. It is the bridge between the L2 capture
// path and the L7 capture path.

// carver consumes frames, reassembles client->printer streams, and emits a job
// per completed stream via save. save is injected so the carver is testable
// without the global sink.
type carver struct {
	re   *streamReassembler
	link int
	save func(*job)
}

// newCarver builds a carver for the given config. link is the capture link type
// (so frames parse correctly); save receives one job per carved stream.
func newCarver(c CarveConf, link int, save func(*job)) *carver {
	ports := map[uint16]bool{}
	for _, p := range c.Ports {
		if p > 0 && p <= 65535 {
			ports[uint16(p)] = true
		}
	}
	maxFlow := 0
	if c.MaxStreamMB > 0 {
		maxFlow = c.MaxStreamMB * 1024 * 1024
	}
	idle := time.Duration(c.IdleFlushSec) * time.Second
	cv := &carver{link: link, save: save}
	cv.re = newStreamReassembler(ports, maxFlow, idle, cv.onStream)
	return cv
}

// consume dissects one captured frame and feeds it to the reassembler. Frames
// that are not TCP toward a print port are silently ignored.
func (cv *carver) consume(frame []byte, ts time.Time) {
	seg, ok := parseTCPSegment(cv.link, frame)
	if !ok {
		return
	}
	cv.re.consume(seg, ts)
}

// flush emits any stream still in flight (call at capture teardown).
func (cv *carver) flush() { cv.re.flush() }

// onStream turns one completed flow into a job. For IPP (port 631) the HTTP/IPP
// envelope is peeled off so only the document bytes are carved; other ports carry
// the document directly (raw 9100) or with light protocol framing that detectPDL
// sees through (it skips any PJL preamble).
func (cv *carver) onStream(fs *flowState) {
	if cv.save == nil || len(fs.buf) == 0 {
		return
	}
	data := fs.buf
	port := fs.dst.Port()
	docFmt := ""
	if port == 631 {
		if doc, fmtHint, ok := unwrapIPP(data); ok {
			data = doc
			docFmt = fmtHint
		}
	}
	if len(data) == 0 {
		return
	}

	j := newJob(fmt.Sprintf("intercept/%d", port), fs.src.String())
	j.Host = fs.dst.Addr().String()
	j.data = data
	j.Bytes = len(data)
	j.DocFormat = docFmt
	if jobName, user := parsePJL(data); jobName != "" || user != "" {
		j.JobName, j.User = jobName, user
	}
	if fs.overflow {
		logWarn("carve", "stream %s -> %s exceeded the per-stream cap; carved file is truncated", fs.src, fs.dst)
	}
	cv.save(j)
}

// unwrapIPP peels the HTTP request and IPP envelope off a carved port-631 stream,
// returning the trailing document bytes and the advertised document-format. It
// reuses parseIPP (the listener's IPP body parser). Returns ok=false if the
// stream is not a recognizable HTTP/IPP request, so the caller can fall back to
// carving the raw bytes.
func unwrapIPP(stream []byte) (doc []byte, docFormat string, ok bool) {
	sep := []byte("\r\n\r\n")
	hdrEnd := bytes.Index(stream, sep)
	if hdrEnd < 0 {
		return nil, "", false
	}
	headers := stream[:hdrEnd]
	body := stream[hdrEnd+len(sep):]
	// Only HTTP requests carry an IPP body; a quick sanity check on the first line.
	if !bytes.HasPrefix(headers, []byte("POST ")) && !bytes.Contains(headers, []byte("application/ipp")) {
		return nil, "", false
	}
	if isChunked(headers) {
		body = dechunk(body)
	}
	if len(body) < 8 {
		return nil, "", false
	}
	attrs, docData := parseIPP(body[8:]) // body[:8] is the IPP version/op/request-id header
	if len(docData) == 0 {
		return nil, "", false
	}
	return docData, attrs["document-format"], true
}

// isChunked reports whether the HTTP headers declare chunked transfer-encoding.
func isChunked(headers []byte) bool {
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		k, v, found := bytes.Cut(line, []byte(":"))
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(k)), "transfer-encoding") &&
			strings.Contains(strings.ToLower(string(v)), "chunked") {
			return true
		}
	}
	return false
}

// dechunk decodes an HTTP/1.1 chunked body into the underlying bytes. Malformed
// input stops decoding and returns whatever was decoded so far (best-effort, so a
// partially-captured stream still yields a usable document prefix).
func dechunk(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		nl := bytes.Index(b, []byte("\r\n"))
		if nl < 0 {
			break
		}
		sizeField := string(b[:nl])
		if semi := strings.IndexByte(sizeField, ';'); semi >= 0 { // chunk extensions
			sizeField = sizeField[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeField), 16, 64)
		if err != nil || size < 0 {
			break
		}
		b = b[nl+2:]
		if size == 0 {
			break // last chunk
		}
		if int64(len(b)) < size {
			out = append(out, b...) // truncated capture: take what we have
			break
		}
		out = append(out, b[:size]...)
		b = b[size:]
		if len(b) >= 2 && b[0] == '\r' && b[1] == '\n' {
			b = b[2:] // trailing CRLF after the chunk data
		}
	}
	return out
}
