package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
)

// IPP operation codes we recognise (RFC 8011 §4.4.15).
const (
	opPrintJob             = 0x0002
	opValidateJob          = 0x0004
	opCreateJob            = 0x0005
	opSendDocument         = 0x0006
	opCancelJob            = 0x0008
	opGetJobs              = 0x000A
	opGetPrinterAttributes = 0x000B
)

// IPP value tags (RFC 8011 §4.1.4).
const (
	tagOperationAttrs = 0x01
	tagJobAttrs       = 0x02
	tagEndOfAttrs     = 0x03
	tagPrinterAttrs   = 0x04

	tagInteger    = 0x21
	tagBoolean    = 0x22
	tagEnum       = 0x23
	tagResolution = 0x32
	tagText       = 0x41
	tagName       = 0x42
	tagKeyword    = 0x44
	tagURI        = 0x45
	tagCharset    = 0x47
	tagLanguage   = 0x48
	tagMime       = 0x49
)

// ippHandler decodes the IPP envelope carried in an HTTP POST body. Everything
// after the end-of-attributes tag is the document (the actual spool data).
func ippHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Browsers and health checks hit this with GET; answer plainly.
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "printcap IPP endpoint\n")
		return
	}
	// Bound the request body so a huge POST can't exhaust memory.
	var reader io.Reader = r.Body
	if c := jobByteCap(); c > 0 {
		reader = io.LimitReader(r.Body, c)
	}
	body, err := io.ReadAll(reader)
	if err != nil || len(body) < 8 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	op := binary.BigEndian.Uint16(body[2:4])
	reqID := binary.BigEndian.Uint32(body[4:8])
	attrs, docData := parseIPP(body[8:])

	proto := "IPP"
	if r.TLS != nil {
		proto = "IPPS"
	}
	logProto(proto, "%s %s op=%s reqid=%d from %s", r.Method, r.URL.Path, ippOpName(op), reqID, r.RemoteAddr)

	// Optionally reject formats we don't advertise (lets the tool emulate a
	// device that only accepts certain PDLs).
	status := uint16(0x0000) // successful-ok
	docFmt := attrs["document-format"]
	if cfg.Printer.EnforceFormats && (op == opPrintJob || op == opValidateJob || op == opSendDocument) &&
		docFmt != "" && !formatAllowed(docFmt) {
		status = 0x040A // client-error-document-format-not-supported
		logWarn(proto, "rejected %s: document-format %q not supported", ippOpName(op), docFmt)
	}
	if op == opGetPrinterAttributes {
		logTrace(proto, "Get-Printer-Attributes from %s", r.RemoteAddr)
	}

	// Only the print operations carry a document, and only if we accepted it.
	if status == 0 && (op == opPrintJob || op == opSendDocument) && len(docData) > 0 {
		j := newJob(proto, r.RemoteAddr)
		j.JobName = attrs["job-name"]
		j.User = attrs["requesting-user-name"]
		j.Queue = r.URL.Path // the IPP resource path the client targeted
		j.DocFormat = docFmt
		j.data = docData
		j.Bytes = len(docData)
		if err := sink.save(j); err != nil {
			logWarn(proto, "forward (block) failed: %v", err)
			status = 0x0508 // server-error-job-canceled
		}
	}

	resp := buildIPPResponse(op, status, reqID, r.Host)
	w.Header().Set("Content-Type", "application/ipp")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

// ippOpName maps an IPP operation code to its name for logging.
func ippOpName(op uint16) string {
	switch op {
	case opPrintJob:
		return "Print-Job"
	case opValidateJob:
		return "Validate-Job"
	case opCreateJob:
		return "Create-Job"
	case opSendDocument:
		return "Send-Document"
	case opCancelJob:
		return "Cancel-Job"
	case opGetJobs:
		return "Get-Jobs"
	case opGetPrinterAttributes:
		return "Get-Printer-Attributes"
	default:
		return fmt.Sprintf("op-0x%04x", op)
	}
}

func formatAllowed(f string) bool {
	for _, a := range cfg.Printer.DocumentFormats {
		if a == f {
			return true
		}
	}
	return false
}

// parseIPP walks the attribute groups, collecting attribute name→value pairs
// (first value only) and returning the trailing document bytes.
func parseIPP(b []byte) (map[string]string, []byte) {
	attrs := map[string]string{}
	i := 0
	lastName := ""
	for i < len(b) {
		tag := b[i]
		i++
		if tag <= 0x05 { // a delimiter / group tag
			if tag == tagEndOfAttrs {
				return attrs, b[i:] // rest of the buffer is the document
			}
			continue // begin a new attribute group
		}
		// Value attribute: name-length, name, value-length, value.
		if i+2 > len(b) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(b[i:]))
		i += 2
		if i+nameLen > len(b) {
			break
		}
		name := string(b[i : i+nameLen])
		i += nameLen
		if i+2 > len(b) {
			break
		}
		valLen := int(binary.BigEndian.Uint16(b[i:]))
		i += 2
		if i+valLen > len(b) {
			break
		}
		val := b[i : i+valLen]
		i += valLen

		if nameLen == 0 {
			name = lastName // additional value of a 1setOf — keep first only
		} else {
			lastName = name
			if _, seen := attrs[name]; !seen {
				attrs[name] = string(val)
			}
		}
	}
	return attrs, nil
}

// buildIPPResponse assembles a valid IPP response. Get-Printer-Attributes gets
// a fully populated printer group (driverless/IPP-Everywhere-style) so clients
// will proceed to print; job operations get a job group. All advertised
// capabilities come from cfg.Printer.
func buildIPPResponse(op, status uint16, reqID uint32, host string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x02, 0x00}) // version 2.0
	binary.Write(&buf, binary.BigEndian, status)
	binary.Write(&buf, binary.BigEndian, reqID)

	// Operation attributes group is mandatory in every response.
	buf.WriteByte(tagOperationAttrs)
	writeStr(&buf, tagCharset, "attributes-charset", "utf-8")
	writeStr(&buf, tagLanguage, "attributes-natural-language", "en-us")

	if host == "" {
		host = "printcap"
	}
	p := cfg.Printer
	// Advertise the configured resource paths (e.g. /ipp/print, /printers/...).
	primaryPath := cfg.IPPOpts.DefaultPath
	if primaryPath == "" {
		primaryPath = "/ipp/print"
	}
	uri := "ipp://" + host + primaryPath
	paths := cfg.IPPOpts.ResourcePaths
	if len(paths) == 0 {
		paths = []string{primaryPath}
	}

	// On a rejected job, return only the operation group with the error status.
	if status != 0 {
		buf.WriteByte(tagEndOfAttrs)
		return buf.Bytes()
	}

	switch op {
	case opGetPrinterAttributes:
		buf.WriteByte(tagPrinterAttrs)
		uris := make([]string, len(paths))
		for i, pth := range paths {
			uris[i] = "ipp://" + host + pth
		}
		writeStrSet(&buf, tagURI, "printer-uri-supported", uris...)
		writeStr(&buf, tagKeyword, "uri-authentication-supported", "none")
		writeStr(&buf, tagKeyword, "uri-security-supported", "none")
		writeStr(&buf, tagName, "printer-name", p.Name)
		writeStr(&buf, tagName, "printer-info", p.Info)
		writeStr(&buf, tagName, "printer-make-and-model", p.MakeAndModel)
		writeStr(&buf, tagText, "printer-location", p.Location)
		writeStr(&buf, tagURI, "printer-uuid", "urn:uuid:00000000-0000-1000-8000-000000000001")
		writeEnum(&buf, "printer-state", 3) // idle
		writeStr(&buf, tagKeyword, "printer-state-reasons", "none")
		writeBool(&buf, "printer-is-accepting-jobs", true)
		writeStrSet(&buf, tagKeyword, "ipp-versions-supported", "1.1", "2.0")
		writeStrSet(&buf, tagKeyword, "ipp-features-supported", "ipp-everywhere")
		writeEnumSet(&buf, "operations-supported",
			opPrintJob, opValidateJob, opCreateJob, opSendDocument,
			opCancelJob, opGetJobs, opGetPrinterAttributes)
		writeStr(&buf, tagCharset, "charset-configured", "utf-8")
		writeStr(&buf, tagCharset, "charset-supported", "utf-8")
		writeStr(&buf, tagLanguage, "natural-language-configured", "en-us")
		writeStr(&buf, tagLanguage, "generated-natural-language-supported", "en-us")
		writeStr(&buf, tagMime, "document-format-default", orElse(p.DefaultFormat, "application/octet-stream"))
		writeStrSet(&buf, tagMime, "document-format-supported", p.DocumentFormats...)
		writeInt(&buf, "queued-job-count", 0)
		writeStr(&buf, tagKeyword, "pdl-override-supported", "attempted")
		writeInt(&buf, "printer-up-time", 1)
		writeStr(&buf, tagKeyword, "compression-supported", "none")

		// IPP Everywhere / driverless capability attributes.
		writeStrSet(&buf, tagKeyword, "sides-supported", p.Sides...)
		writeStr(&buf, tagKeyword, "sides-default", firstOr(p.Sides, "one-sided"))
		colorModes := []string{"monochrome"}
		if p.Color {
			colorModes = []string{"auto", "color", "monochrome"}
		}
		writeStrSet(&buf, tagKeyword, "print-color-mode-supported", colorModes...)
		writeStr(&buf, tagKeyword, "print-color-mode-default", colorModes[0])
		writeStrSet(&buf, tagKeyword, "media-supported", p.Media...)
		writeStr(&buf, tagKeyword, "media-default", firstOr(p.Media, "iso_a4_210x297mm"))
		writeResolutions(&buf, "printer-resolution-supported", p.Resolutions)
		writeResolutions(&buf, "pwg-raster-document-resolution-supported", p.Resolutions)
		if len(p.Resolutions) > 0 {
			writeResolution(&buf, "printer-resolution-default", p.Resolutions[0])
		}
		writeStrSet(&buf, tagKeyword, "pwg-raster-document-type-supported", "srgb_8", "sgray_8")
		writeStrSet(&buf, tagKeyword, "urf-supported", urfSupported()...)

	case opPrintJob, opCreateJob, opSendDocument, opValidateJob:
		buf.WriteByte(tagJobAttrs)
		writeStr(&buf, tagURI, "job-uri", uri+"jobs/1")
		writeInt(&buf, "job-id", 1)
		writeEnum(&buf, "job-state", 9) // completed
		writeStr(&buf, tagKeyword, "job-state-reasons", "none")
	}

	buf.WriteByte(tagEndOfAttrs)
	return buf.Bytes()
}

func firstOr(s []string, alt string) string {
	if len(s) > 0 {
		return s[0]
	}
	return alt
}

// --- IPP attribute encoders -------------------------------------------------

func writeAttr(buf *bytes.Buffer, tag byte, name string, val []byte) {
	buf.WriteByte(tag)
	binary.Write(buf, binary.BigEndian, uint16(len(name)))
	buf.WriteString(name)
	binary.Write(buf, binary.BigEndian, uint16(len(val)))
	buf.Write(val)
}

func writeStr(buf *bytes.Buffer, tag byte, name, val string) {
	writeAttr(buf, tag, name, []byte(val))
}

func writeInt(buf *bytes.Buffer, name string, n int32) {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(n))
	writeAttr(buf, tagInteger, name, v)
}

func writeEnum(buf *bytes.Buffer, name string, n int32) {
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, uint32(n))
	writeAttr(buf, tagEnum, name, v)
}

func writeBool(buf *bytes.Buffer, name string, b bool) {
	v := byte(0)
	if b {
		v = 1
	}
	writeAttr(buf, tagBoolean, name, []byte{v})
}

// writeStrSet encodes a 1setOf of strings: first value carries the name, the
// rest carry an empty name (the IPP convention for additional values).
func writeStrSet(buf *bytes.Buffer, tag byte, name string, vals ...string) {
	for idx, v := range vals {
		n := name
		if idx > 0 {
			n = ""
		}
		writeStr(buf, tag, n, v)
	}
}

// writeResolution encodes one IPP resolution value: cross-feed and feed
// (4 bytes each) plus a 1-byte units field (3 = dots-per-inch).
func writeResolution(buf *bytes.Buffer, name string, dpi int) {
	v := make([]byte, 9)
	binary.BigEndian.PutUint32(v[0:], uint32(dpi))
	binary.BigEndian.PutUint32(v[4:], uint32(dpi))
	v[8] = 3
	writeAttr(buf, tagResolution, name, v)
}

func writeResolutions(buf *bytes.Buffer, name string, dpis []int) {
	for idx, d := range dpis {
		n := name
		if idx > 0 {
			n = ""
		}
		v := make([]byte, 9)
		binary.BigEndian.PutUint32(v[0:], uint32(d))
		binary.BigEndian.PutUint32(v[4:], uint32(d))
		v[8] = 3
		writeAttr(buf, tagResolution, n, v)
	}
}

func writeEnumSet(buf *bytes.Buffer, name string, vals ...int32) {
	for idx, n := range vals {
		nm := name
		if idx > 0 {
			nm = ""
		}
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, uint32(n))
		writeAttr(buf, tagEnum, nm, v)
	}
}
