package main

import "strings"

// applyCarriageControl converts mainframe carriage-control to plain text. It
// handles ASA on already-decoded text. NOTE: "machine" carriage-control is NOT
// handled here — machine (FCFC) codes are raw EBCDIC control bytes that no longer
// exist after EBCDIC decode (they were mapped through the code page). Machine mode
// is handled by convertMachineRaw on the RAW bytes BEFORE decode (see sink
// integration, Task 6). Here:
//
//	asa:     first char of each record is the ASA control (' '=single, '0'=double,
//	         '-'=triple, '1'=form feed, '+'=overprint); it is stripped.
//	none:    returned unchanged.   auto: detect asa, else none.
func applyCarriageControl(text, mode string) string {
	switch mode {
	case "asa":
		return convertASA(text)
	case "auto":
		if detectCarriage(text) == "asa" {
			return convertASA(text)
		}
		return text
	default: // none (and "machine", which is applied on raw bytes elsewhere)
		return text
	}
}

func convertASA(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		ctrl, rest := line[0], line[1:]
		switch ctrl {
		case '0':
			b.WriteString("\n")
		case '-':
			b.WriteString("\n\n")
		case '1':
			b.WriteString("\f")
		case '+':
			b.WriteString("\r")
		}
		b.WriteString(rest)
		b.WriteString("\n")
	}
	return b.String()
}

// convertMachineRaw applies machine (FCFC) carriage-control to the RAW EBCDIC byte
// stream, BEFORE EBCDIC decode. Machine control bytes are raw EBCDIC values (e.g.
// 0x8B/0x89 skip-to-channel) that would be destroyed by decoding through a
// code-page table, so this MUST run on the raw bytes. It splits the stream on
// EBCDIC line delimiters (NEL 0x15 and/or LF 0x25), strips the first (control)
// byte of each record, and inserts an ASCII form-feed (\f, 0x0C) where the control
// byte is a skip-to-channel code (0x8B/0x89). The delimiter byte is preserved so
// the subsequent decodeEBCDIC pass maps it to a newline.
func convertMachineRaw(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	rec := make([]byte, 0, 256)
	flush := func(delim byte, haveDelim bool) {
		if len(rec) == 0 && !haveDelim {
			return
		}
		ctrl := byte(0)
		body := rec
		if len(rec) > 0 {
			ctrl, body = rec[0], rec[1:]
		}
		if ctrl == 0x8B || ctrl == 0x89 {
			out = append(out, '\f')
		}
		out = append(out, body...)
		if haveDelim {
			out = append(out, delim)
		}
		rec = rec[:0]
	}
	for _, b := range raw {
		if b == 0x15 || b == 0x25 {
			flush(b, true)
			continue
		}
		rec = append(rec, b)
	}
	flush(0, false)
	return out
}

func detectCarriage(text string) string {
	lines := strings.Split(text, "\n")
	asa := 0
	total := 0
	for _, l := range lines {
		if l == "" {
			continue
		}
		total++
		switch l[0] {
		case ' ', '0', '-', '1', '+':
			asa++
		}
	}
	if total > 0 && asa == total {
		return "asa"
	}
	return "none"
}
