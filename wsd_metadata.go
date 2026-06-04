package main

import "strings"

// WS-Transfer / WS-MetadataExchange / DPWS namespaces used by the metadata
// GetResponse. buildSOAP only declares s/a on the Envelope, so the mex:Metadata
// element declares the rest itself.
const (
	nsTransfer = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
	nsMex      = "http://schemas.xmlsoap.org/ws/2004/09/mex"

	actTransferGet     = nsTransfer + "/Get"
	actTransferGetResp = nsTransfer + "/GetResponse"
	actAddrFault       = nsAddr + "/fault"
	addrAnonymous      = nsAddr + "/anonymous"

	dialectThisModel    = nsDevProf + "/ThisModel"
	dialectThisDevice   = nsDevProf + "/ThisDevice"
	dialectRelationship = nsDevProf + "/Relationship"
	relTypeHost         = nsDevProf + "/host"
)

// metaNamespaces is the namespace declaration block placed on the mex:Metadata
// element (buildSOAP declares only s/a on the Envelope).
const metaNamespaces = ` xmlns:mex="` + nsMex + `"` +
	` xmlns:wsdp="` + nsDevProf + `"` +
	` xmlns:wprt="` + nsWdpPrint + `"` +
	` xmlns:wsa="` + nsAddr + `"`

// buildMetadata returns the BODY XML (the mex:Metadata element) for a
// WS-Transfer GetResponse, per the DPWS device profile. It carries three
// metadata sections: ThisModel, ThisDevice, and the host Relationship that
// advertises the hosted PrintService. Dynamic values are XML-escaped.
func buildMetadata() []byte {
	device := deviceUUID(wsdHost())

	model := cfg.Printer.MakeAndModel
	if strings.TrimSpace(model) == "" {
		model = "printcap Virtual MFP"
	}
	name := cfg.Printer.Name
	if strings.TrimSpace(name) == "" {
		name = "printcap"
	}
	serial := cfg.Printer.Serial
	if strings.TrimSpace(serial) == "" {
		serial = "printcap"
	}

	var b strings.Builder
	b.WriteString(`<mex:Metadata` + metaNamespaces + `>`)

	// ThisModel.
	b.WriteString(`<mex:MetadataSection Dialect="` + dialectThisModel + `">`)
	b.WriteString(`<wsdp:ThisModel>`)
	b.WriteString(`<wsdp:Manufacturer>printcap</wsdp:Manufacturer>`)
	b.WriteString(`<wsdp:ModelName>` + xmlEsc(model) + `</wsdp:ModelName>`)
	b.WriteString(`</wsdp:ThisModel>`)
	b.WriteString(`</mex:MetadataSection>`)

	// ThisDevice.
	b.WriteString(`<mex:MetadataSection Dialect="` + dialectThisDevice + `">`)
	b.WriteString(`<wsdp:ThisDevice>`)
	b.WriteString(`<wsdp:FriendlyName>` + xmlEsc(name) + `</wsdp:FriendlyName>`)
	b.WriteString(`<wsdp:FirmwareVersion>1.0</wsdp:FirmwareVersion>`)
	b.WriteString(`<wsdp:SerialNumber>` + xmlEsc(serial) + `</wsdp:SerialNumber>`)
	b.WriteString(`</wsdp:ThisDevice>`)
	b.WriteString(`</mex:MetadataSection>`)

	// Relationship: device hosts a PrintService.
	b.WriteString(`<mex:MetadataSection Dialect="` + dialectRelationship + `">`)
	b.WriteString(`<wsdp:Relationship Type="` + relTypeHost + `">`)
	b.WriteString(`<wsdp:Host>`)
	b.WriteString(`<wsa:EndpointReference><wsa:Address>` + xmlEsc(device) + `</wsa:Address></wsa:EndpointReference>`)
	b.WriteString(`<wsdp:Types>wsdp:Device</wsdp:Types>`)
	b.WriteString(`</wsdp:Host>`)
	b.WriteString(`<wsdp:Hosted>`)
	b.WriteString(`<wsa:EndpointReference><wsa:Address>` + xmlEsc(wsdEndpoint) + `</wsa:Address></wsa:EndpointReference>`)
	b.WriteString(`<wsdp:Types>wprt:PrintDeviceType</wsdp:Types>`)
	b.WriteString(`<wsdp:ServiceId>` + xmlEsc(device+"/print") + `</wsdp:ServiceId>`)
	b.WriteString(`</wsdp:Hosted>`)
	b.WriteString(`</wsdp:Relationship>`)
	b.WriteString(`</mex:MetadataSection>`)

	b.WriteString(`</mex:Metadata>`)
	return []byte(b.String())
}

// buildMetadataResponse wraps buildMetadata in a WS-Transfer GetResponse SOAP
// envelope, echoing the request MessageID as RelatesTo and addressing the reply
// to the anonymous endpoint.
func buildMetadataResponse(reqMessageID string) []byte {
	return buildSOAP(soapEnvelope{
		Action:    actTransferGetResp,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: reqMessageID,
		BodyXML:   buildMetadata(),
	})
}

// soapFault builds a SOAP 1.2 Fault envelope (WS-Addressing fault action),
// relating it to the request that triggered it. code is the s:Code Value
// (e.g. "Sender"), subcode the s:Subcode Value (e.g. "wsa:ActionNotSupported"),
// and reason the human-readable text.
func soapFault(reqMessageID, code, subcode, reason string) []byte {
	var b strings.Builder
	b.WriteString(`<s:Fault xmlns:wsa="` + nsAddr + `">`)
	b.WriteString(`<s:Code><s:Value>s:` + xmlEsc(code) + `</s:Value>`)
	b.WriteString(`<s:Subcode><s:Value>` + xmlEsc(subcode) + `</s:Value></s:Subcode>`)
	b.WriteString(`</s:Code>`)
	b.WriteString(`<s:Reason><s:Text xml:lang="en">` + xmlEsc(reason) + `</s:Text></s:Reason>`)
	b.WriteString(`</s:Fault>`)
	return buildSOAP(soapEnvelope{
		Action:    actAddrFault,
		MessageID: wsdMessageID(),
		To:        addrAnonymous,
		RelatesTo: reqMessageID,
		BodyXML:   []byte(b.String()),
	})
}
