package main

import (
	"bytes"
	"encoding/xml"
	"strings"
)

// soapEnvelope is the canonical in-memory representation of a SOAP 1.2 message
// with WS-Addressing 1.0 headers. BodyXML contains the raw inner XML of the
// SOAP Body element (already-valid XML, inserted verbatim).
type soapEnvelope struct {
	Action    string
	MessageID string
	To        string
	RelatesTo string
	BodyXML   []byte
}

const (
	nsSoap = "http://www.w3.org/2003/05/soap-envelope"
	nsAddr = "http://www.w3.org/2005/08/addressing"
)

// buildSOAP serialises env into a well-formed SOAP 1.2 / WS-Addressing 1.0
// envelope. BodyXML is inserted verbatim; addressing header values are
// XML-escaped via xml.EscapeText.
func buildSOAP(env soapEnvelope) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	buf.WriteString(`<s:Envelope xmlns:s="` + nsSoap + `" xmlns:a="` + nsAddr + `">`)
	buf.WriteString(`<s:Header>`)
	buf.WriteString(`<a:Action>`)
	_ = xml.EscapeText(&buf, []byte(env.Action))
	buf.WriteString(`</a:Action>`)
	buf.WriteString(`<a:MessageID>`)
	_ = xml.EscapeText(&buf, []byte(env.MessageID))
	buf.WriteString(`</a:MessageID>`)
	if env.To != "" {
		buf.WriteString(`<a:To>`)
		_ = xml.EscapeText(&buf, []byte(env.To))
		buf.WriteString(`</a:To>`)
	}
	if env.RelatesTo != "" {
		buf.WriteString(`<a:RelatesTo>`)
		_ = xml.EscapeText(&buf, []byte(env.RelatesTo))
		buf.WriteString(`</a:RelatesTo>`)
	}
	buf.WriteString(`</s:Header>`)
	buf.WriteString(`<s:Body>`)
	buf.Write(env.BodyXML)
	buf.WriteString(`</s:Body>`)
	buf.WriteString(`</s:Envelope>`)
	return buf.Bytes()
}

// xmlEnvelope is the unmarshal target for parseSOAP. encoding/xml matches
// element tags on local name only when no namespace is provided in the tag
// string, which gives us lenient namespace-prefix-independent parsing.
type xmlEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  struct {
		Action    string `xml:"Action"`
		MessageID string `xml:"MessageID"`
		To        string `xml:"To"`
		RelatesTo string `xml:"RelatesTo"`
	} `xml:"Header"`
	Body struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"Body"`
}

// parseSOAP decodes a raw SOAP 1.2 envelope and returns a soapEnvelope plus
// ok=true on success. Returns ok=false on any XML parse error or if the root
// element is not "Envelope". Never panics on malformed input.
func parseSOAP(raw []byte) (soapEnvelope, bool) {
	var x xmlEnvelope
	if err := xml.Unmarshal(raw, &x); err != nil {
		return soapEnvelope{}, false
	}
	if x.XMLName.Local != "Envelope" {
		return soapEnvelope{}, false
	}
	return soapEnvelope{
		Action:    strings.TrimSpace(x.Header.Action),
		MessageID: strings.TrimSpace(x.Header.MessageID),
		To:        strings.TrimSpace(x.Header.To),
		RelatesTo: strings.TrimSpace(x.Header.RelatesTo),
		BodyXML:   bytes.TrimSpace(x.Body.Inner),
	}, true
}
