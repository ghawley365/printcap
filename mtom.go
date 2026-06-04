package main

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"strings"
)

// extractMTOM parses an MTOM/XOP (multipart/related) HTTP body, returning the
// root part (the SOAP envelope, an application/xop+xml part) and a map of
// Content-ID -> bytes for every part (the root included, keyed by its CID).
//
// The root part is the one whose Content-ID matches the multipart "start"
// parameter; if "start" is absent, the FIRST part is treated as root.
//
// Untrusted input is handled defensively: a non-multipart content type is an
// error, total bytes read across all parts are capped at maxWSDBody so a hostile
// multipart cannot exhaust memory, and the function never panics.
func extractMTOM(contentType string, body []byte) (root []byte, parts map[string][]byte, err error) {
	mediatype, params, perr := mime.ParseMediaType(contentType)
	if perr != nil {
		return nil, nil, perr
	}
	if mediatype != "multipart/related" {
		return nil, nil, errors.New("mtom: not multipart/related")
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, nil, errors.New("mtom: missing boundary")
	}

	startCID := stripAngle(params["start"])

	parts = map[string][]byte{}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)

	var firstData []byte
	var budget int64 = maxWSDBody
	first := true
	for {
		p, nerr := mr.NextPart()
		if nerr == io.EOF {
			break
		}
		if nerr != nil {
			return nil, nil, nerr
		}
		cid := stripAngle(p.Header.Get("Content-ID"))

		// Bounded read so the cumulative payload cannot exceed maxWSDBody.
		var buf bytes.Buffer
		n, cerr := io.Copy(&buf, io.LimitReader(p, budget+1))
		_ = p.Close()
		if cerr != nil {
			return nil, nil, cerr
		}
		if n > budget {
			return nil, nil, errors.New("mtom: parts exceed size limit")
		}
		budget -= n

		data := buf.Bytes()
		if cid != "" {
			parts[cid] = data
		}
		if first {
			firstData = data
			first = false
		}
		// Record the root part bytes when we can identify it.
		if startCID != "" && cid == startCID {
			root = data
		}
	}

	if root == nil && startCID == "" {
		// No "start" parameter: the first part is the root.
		root = firstData
	}
	return root, parts, nil
}

// stripAngle removes a single surrounding pair of angle brackets and trims
// whitespace, normalising Content-ID / start header values.
func stripAngle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")
	return s
}
