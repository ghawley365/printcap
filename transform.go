package main

import "strings"

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
