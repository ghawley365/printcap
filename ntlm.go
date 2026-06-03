package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// NOTE: NTLMv2, MD4 and MD5-as-used-here are legacy primitives mandated by the
// [MS-NLMP] protocol for interop with Windows/SMB clients. They are NOT chosen
// for their security properties; we implement them only because the wire
// protocol requires them.

// utf16le encodes s as UTF-16 little-endian, the string form used throughout
// [MS-NLMP]. Each UTF-16 code unit is serialized low byte first.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

// ntowfv2 computes the NTLMv2 one-way function ([MS-NLMP] §3.3.2):
//
//	NTOWFv2 = HMAC_MD5( MD4(UTF16LE(password)), UTF16LE( UpperCase(user) + domain ) )
//
// Only the user is upper-cased; the domain case is preserved.
func ntowfv2(user, domain, password string) []byte {
	key := md4Sum(utf16le(password))
	mac := hmac.New(md5.New, key)
	mac.Write(utf16le(strings.ToUpper(user) + domain))
	return mac.Sum(nil)
}
