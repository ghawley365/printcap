package main

// Minimal SPNEGO (RFC 4178) NegTokenResp encoder used to wrap the outbound NTLM
// tokens the server emits during SMB2 SESSION_SETUP. smbclient (and Windows)
// send their NTLMSSP messages wrapped in SPNEGO/GSS-API and require the server's
// reply token to be SPNEGO-wrapped as well; a raw "NTLMSSP\0" CHALLENGE is
// rejected with "Invalid SPNEGO request" / NT_STATUS_INVALID_PARAMETER.
//
// Inbound parsing stays signature-based (extractNTLM scans for "NTLMSSP\0"), so
// only the outbound direction needs this encoder.

// spnegoState is the NegTokenResp negState ENUMERATED value (RFC 4178 §4.2.2).
type spnegoState int

const (
	spnegoAcceptCompleted  spnegoState = 0
	spnegoAcceptIncomplete spnegoState = 1
)

// ntlmspMechOID is the DER encoding of the NTLMSSP mechanism OID
// 1.3.6.1.4.1.311.2.2.10 as an OBJECT IDENTIFIER TLV (tag 0x06).
var ntlmspMechOID = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

// derLen encodes a DER definite-form length: short form for len < 128, else long
// form (0x81 LL for <256, 0x82 HH LL for <65536). Tokens here never exceed a few
// hundred bytes, so two length octets suffice, but we handle up to 0xFFFF.
func derLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

// derTLV builds a DER tag-length-value triple with a correctly encoded length.
func derTLV(tag byte, value []byte) []byte {
	out := make([]byte, 0, 1+3+len(value))
	out = append(out, tag)
	out = append(out, derLen(len(value))...)
	out = append(out, value...)
	return out
}

// spnegoWrapResponse builds an SPNEGO NegTokenResp (RFC 4178 §4.2.2) carrying the
// given NTLM responseToken (nil to omit). negState is accept-incomplete for the
// CHALLENGE leg, accept-completed for final success. The supportedMech (NTLMSSP
// OID) is included only when a responseToken is present.
//
// Layout:
//
//	[1] negTokenResp {
//	  SEQUENCE {
//	    [0] negState     ENUMERATED  (always present)
//	    [1] supportedMech MechType   (only with a responseToken)
//	    [2] responseToken OCTET STRING (only when non-nil)
//	  }
//	}
func spnegoWrapResponse(state spnegoState, responseToken []byte) []byte {
	var inner []byte

	// [0] negState ENUMERATED { value }.
	negState := derTLV(0x0A, []byte{byte(state)}) // ENUMERATED tag = 0x0A
	inner = append(inner, derTLV(0xA0, negState)...)

	if len(responseToken) > 0 {
		// [1] supportedMech = NTLMSSP OID.
		inner = append(inner, derTLV(0xA1, ntlmspMechOID)...)
		// [2] responseToken OCTET STRING { token }.
		octet := derTLV(0x04, responseToken)
		inner = append(inner, derTLV(0xA2, octet)...)
	}

	// Wrap the fields in a SEQUENCE, then in the [1] negTokenResp choice tag.
	seq := derTLV(0x30, inner)
	return derTLV(0xA1, seq)
}
