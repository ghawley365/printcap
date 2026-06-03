package main

import (
	"bytes"
	"regexp"
	"strings"
)

// condMatcher is satisfied by *compiledCond (Task 3). A nil matcher always
// applies.
type condMatcher interface {
	matches(j *job, data []byte) bool
}

type compiledStep struct {
	kind  string         // inject_prefix | inject_suffix | replace
	mode  string         // replace: literal | regex | hex
	match []byte         // literal/hex match bytes
	re    *regexp.Regexp // regex mode
	with  []byte         // replacement (literal/hex)
	withS string         // regex replacement template (supports $1)
	all   bool
	data  []byte      // inject_* bytes (already decoded)
	when  condMatcher // nil = always
}

// applyTransforms runs steps in order over a copy of data.
func applyTransforms(steps []compiledStep, data []byte, j *job) []byte {
	out := append([]byte{}, data...)
	for _, s := range steps {
		if s.when != nil && !s.when.matches(j, out) {
			logDebug("fwd", "skip transform %s (condition not met)", s.kind)
			continue
		}
		before := len(out)
		switch s.kind {
		case "inject_prefix":
			out = append(append([]byte{}, s.data...), out...)
		case "inject_suffix":
			out = append(out, s.data...)
		case "replace":
			out = applyReplace(s, out)
		}
		logDebug("fwd", "transform %s: %d -> %d bytes", s.kind, before, len(out))
	}
	return out
}

func applyReplace(s compiledStep, data []byte) []byte {
	switch s.mode {
	case "regex":
		if s.re == nil {
			return data
		}
		return s.re.ReplaceAll(data, []byte(s.withS))
	default: // literal or hex — both already-decoded byte slices
		if len(s.match) == 0 {
			return data
		}
		if s.all {
			return bytes.ReplaceAll(data, s.match, s.with)
		}
		return bytes.Replace(data, s.match, s.with, 1)
	}
}

// decodeBytes resolves a configured byte string. A leading "macro:NAME" expands
// to that macro's already-decoded bytes (empty if unknown). Otherwise it decodes
// \xNN hex escapes; all other characters are literal.
func decodeBytes(s string, macros map[string][]byte) []byte {
	if strings.HasPrefix(s, "macro:") {
		return append([]byte{}, macros[strings.TrimPrefix(s, "macro:")]...)
	}
	var out []byte
	for i := 0; i < len(s); {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			if b, ok := hexByte(s[i+2], s[i+3]); ok {
				out = append(out, b)
				i += 4
				continue
			}
		}
		out = append(out, s[i])
		i++
	}
	return out
}

func hexByte(hi, lo byte) (byte, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
