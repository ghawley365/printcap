package main

import (
	"bytes"
	"regexp"
	"strings"
)

// Page-Description-Language detection and PJL parsing.
//
// Enterprise print jobs rarely begin with the raw PDL. They usually start with
// the Universal Exit Language (UEL) escape sequence followed by an @PJL
// preamble that sets the job name/user and selects a personality; the actual
// PostScript/PCL/PCL-XL data begins after a second UEL. So detection skips the
// PJL preamble first, then matches magic bytes.

// uel is the Universal Exit Language sequence: ESC %-12345X
var uel = []byte{0x1b, '%', '-', '1', '2', '3', '4', '5', 'X'}

// pdlSig maps a detected PDL to its display name, file extension, and a
// best-guess document format. Order matters: more specific first.
type pdlSig struct {
	name string
	ext  string
	mime string
	// match returns true if b (already advanced past any PJL preamble) is this PDL.
	match func(b []byte) bool
}

func hasPrefix(p ...byte) func([]byte) bool {
	return func(b []byte) bool { return bytes.HasPrefix(b, p) }
}
func contains(sub string) func([]byte) bool {
	s := []byte(sub)
	return func(b []byte) bool { return bytes.Contains(b, s) }
}

// pdlTable is consulted in order against the bytes after the PJL preamble.
var pdlTable = []pdlSig{
	{"PDF", ".pdf", "application/pdf", hasPrefix('%', 'P', 'D', 'F')},
	{"PostScript", ".ps", "application/postscript", hasPrefix('%', '!')},
	{"PCL-XL (PCL6)", ".pclxl", "application/vnd.hp-PCLXL", func(b []byte) bool {
		// ") HP-PCL XL" appears at the start of the PCL-XL data stream.
		head := b
		if len(head) > 64 {
			head = head[:64]
		}
		return bytes.Contains(head, []byte("HP-PCL XL"))
	}},
	{"PCL", ".pcl", "application/vnd.hp-PCL", func(b []byte) bool {
		return len(b) >= 2 && b[0] == 0x1b && (b[1] == 'E' || b[1] == '&' || b[1] == '(' || b[1] == '*')
	}},
	{"PWG Raster", ".pwg", "image/pwg-raster", func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("RaS2")) || bytes.HasPrefix(b, []byte("RaS3")) ||
			bytes.HasPrefix(b, []byte("2SaR")) || bytes.HasPrefix(b, []byte("3SaR"))
	}},
	{"Apple Raster (URF)", ".urf", "image/urf", hasPrefix('U', 'N', 'I', 'R', 'A', 'S', 'T')},
	{"XPS / OpenXPS", ".xps", "application/oxps", hasPrefix('P', 'K', 0x03, 0x04)}, // ZIP container
	{"ZPL (Zebra)", ".zpl", "application/vnd.zebra-zpl", func(b []byte) bool {
		return bytes.HasPrefix(bytes.TrimLeft(b, " \r\n\t"), []byte("^XA")) || bytes.Contains(headN(b, 32), []byte("^XA"))
	}},
	{"EPL (Eltron)", ".epl", "application/vnd.eltron-epl", func(b []byte) bool {
		t := bytes.TrimLeft(b, " \r\n\t")
		return len(t) > 1 && (t[0] == 'N' || t[0] == 'O') && (t[1] == '\n' || t[1] == '\r')
	}},
	{"Prescribe (Kyocera)", ".pre", "application/vnd.kyocera-prescribe", hasPrefix('!', 'R', '!')},
	{"AFP (MO:DCA)", ".afp", "application/vnd.ibm.modcap", hasPrefix(0x5a)}, // structured fields start with 0x5A
	{"TIFF", ".tif", "image/tiff", func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("II*\x00")) || bytes.HasPrefix(b, []byte("MM\x00*"))
	}},
	{"JPEG", ".jpg", "image/jpeg", hasPrefix(0xff, 0xd8, 0xff)},
	{"PNG", ".png", "image/png", hasPrefix(0x89, 'P', 'N', 'G')},
	{"ESC/P or ESC/POS", ".escp", "application/octet-stream", hasPrefix(0x1b, '@')},
}

func headN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// skipPJL returns the slice starting at the actual PDL data, stepping over a
// leading UEL and the entire @PJL preamble (which can be many lines: SET
// JOBNAME, SET USERNAME, ENTER LANGUAGE, …). The real PostScript/PCL/PCL-XL
// data begins right after the last @PJL line.
func skipPJL(b []byte) []byte {
	if !bytes.HasPrefix(b, uel) && !bytes.Contains(headN(b, 16), []byte("@PJL")) {
		return b
	}
	i := 0
	pjl := []byte("@PJL")
	for i < len(b) {
		// Skip any UEL sequence and surrounding whitespace/newlines.
		if bytes.HasPrefix(b[i:], uel) {
			i += len(uel)
			continue
		}
		if b[i] == '\r' || b[i] == '\n' || b[i] == ' ' || b[i] == '\t' {
			i++
			continue
		}
		// Skip a whole @PJL line.
		if bytes.HasPrefix(b[i:], pjl) {
			nl := bytes.IndexByte(b[i:], '\n')
			if nl < 0 {
				return b[i:] // malformed: no newline, give up here
			}
			i += nl + 1
			continue
		}
		break // first byte of real PDL data
	}
	return b[i:]
}

// detectPDL identifies the page-description language of a spool, returning the
// PDL name, file extension, and a guessed document format. Falls back to plain
// text or octet-stream.
func detectPDL(data []byte) (name, ext, mime string) {
	b := skipPJL(data)
	for _, sig := range pdlTable {
		if sig.match(b) {
			return sig.name, sig.ext, sig.mime
		}
	}
	if isText(b) {
		return "Text", ".txt", "text/plain"
	}
	return "Unknown", ".prn", "application/octet-stream"
}

// isText reports whether the first chunk looks like printable text.
func isText(b []byte) bool {
	n := len(b)
	if n == 0 {
		return false
	}
	if n > 512 {
		n = 512
	}
	for _, c := range b[:n] {
		if c == 0x00 {
			return false
		}
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			if c != 0x1b { // allow ESC (could be light formatting)
				return false
			}
		}
	}
	return true
}

// --- PJL metadata parsing ---------------------------------------------------

var (
	reJobName  = regexp.MustCompile(`(?i)@PJL\s+(?:SET\s+JOBNAME|JOB\s+NAME)\s*=\s*"?([^"\r\n]+?)"?\s*[\r\n]`)
	reUserName = regexp.MustCompile(`(?i)@PJL\s+SET\s+(?:USERNAME|JOBATTR\s*=\s*"?[^"]*USERID)\s*=?\s*"?([^"\r\n]+?)"?\s*[\r\n]`)
	reUser2    = regexp.MustCompile(`(?i)@PJL\s+SET\s+USERNAME\s*=\s*"?([^"\r\n]+?)"?\s*[\r\n]`)
)

// parsePJL extracts job name and user name from a PJL preamble, if present.
// Only the first ~16 KiB is scanned (the preamble is always at the front).
func parsePJL(data []byte) (jobName, user string) {
	head := data
	if len(head) > 16384 {
		head = head[:16384]
	}
	if !bytes.Contains(head, []byte("@PJL")) {
		return "", ""
	}
	if m := reJobName.FindSubmatch(head); m != nil {
		jobName = strings.TrimSpace(string(m[1]))
	}
	if m := reUser2.FindSubmatch(head); m != nil {
		user = strings.TrimSpace(string(m[1]))
	}
	return jobName, user
}

// splitUEL splits a stream containing multiple PJL jobs into individual job
// byte slices on UEL boundaries. Empty segments are dropped. If no UEL is
// present, the whole stream is returned as a single segment.
func splitUEL(data []byte) [][]byte {
	if !bytes.Contains(data, uel) {
		return [][]byte{data}
	}
	parts := bytes.Split(data, uel)
	var out [][]byte
	for _, p := range parts {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		// Re-prepend the UEL so each segment is a well-formed job for detection.
		seg := append(append([]byte{}, uel...), p...)
		out = append(out, seg)
	}
	if len(out) == 0 {
		return [][]byte{data}
	}
	return out
}
