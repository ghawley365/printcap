package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ippTransport struct{}

func (ippTransport) send(t *target, data []byte, j *job) error {
	to := t.timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	// Build a Print-Job (0x0002) request envelope.
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0x00})                        // version 2.0
	binary.Write(&buf, binary.BigEndian, uint16(0x0002)) // operation
	binary.Write(&buf, binary.BigEndian, uint32(1))      // request-id

	buf.WriteByte(tagOperationAttrs)
	writeStr(&buf, tagCharset, "attributes-charset", "utf-8")
	writeStr(&buf, tagLanguage, "attributes-natural-language", "en-us")
	writeStr(&buf, tagURI, "printer-uri", t.address)
	writeStr(&buf, tagName, "requesting-user-name", orElse(j.User, "printcap"))
	writeStr(&buf, tagName, "job-name", orElse(j.JobName, "job"))
	docFmt := t.docFormat
	if docFmt == "" {
		docFmt = orElse(j.DocFormat, "application/octet-stream")
	}
	writeStr(&buf, tagMime, "document-format", docFmt)
	buf.WriteByte(tagEndOfAttrs)
	buf.Write(data) // document follows the envelope

	httpURL, err := ippToHTTP(t.address)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, httpURL, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/ipp")

	client := &http.Client{Timeout: to}
	if strings.HasPrefix(t.address, "ipps://") {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: t.tlsSkip, MinVersion: tls.VersionTLS12},
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ipp HTTP %d", resp.StatusCode)
	}
	if len(body) >= 4 {
		status := binary.BigEndian.Uint16(body[2:4])
		if status >= 0x0400 {
			return fmt.Errorf("ipp status 0x%04x", status)
		}
	}
	return nil
}

// ippToHTTP converts an ipp(s):// URI to the http(s):// URL used for POST.
func ippToHTTP(uri string) (string, error) {
	switch {
	case strings.HasPrefix(uri, "ipps://"):
		return "https://" + strings.TrimPrefix(uri, "ipps://"), nil
	case strings.HasPrefix(uri, "ipp://"):
		return "http://" + strings.TrimPrefix(uri, "ipp://"), nil
	default:
		return "", fmt.Errorf("not an ipp(s) URI: %q", uri)
	}
}
