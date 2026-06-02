# mDNS/DNS-SD Advertisement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make printcap auto-discoverable as a driverless printer over mDNS/DNS-SD (Bonjour) on Windows, Linux/CUPS, macOS, and iOS/AirPrint, using a hand-rolled, pure-stdlib responder that adds zero new dependencies.

**Architecture:** Three new cross-platform files mirroring the existing one-concern-per-file layout: `dnsmsg.go` (hand-rolled DNS wire encode/decode, in the style of the BER code in `snmp.go`), `dnssd.go` (the service model — the only place that reads `cfg`), and `mdns.go` (the multicast responder). The Engine starts/stops the responder like it does the SNMP agent, advertising only listeners that actually bound. A pure `answersFor()` function makes query handling unit-testable without opening sockets.

**Tech Stack:** Go 1.26, standard library only (`net`, `encoding/binary`, `strings`, `testing`). No `golang.org/x/net`, no third-party DNS libs.

**Build order:** plan #4 of 6 (after Mainframe, before SMB/WSD). WSD reuses this plan's multicast-socket discipline, so build mDNS before WSD.

---

## Shared type & constant reference (defined in the tasks below; listed here for consistency)

These names are used across multiple tasks. Define them exactly as written.

```go
// dnsmsg.go
const (
    dnsTypeA    uint16 = 1
    dnsTypePTR  uint16 = 12
    dnsTypeTXT  uint16 = 16
    dnsTypeAAAA uint16 = 28
    dnsTypeSRV  uint16 = 33
    dnsTypeANY  uint16 = 255

    dnsClassIN   uint16 = 1
    dnsFlushBit  uint16 = 0x8000 // cache-flush bit (responses) / QU bit (questions)
    dnsClassMask uint16 = 0x7fff
)

type dnsQuestion struct {
    name    string
    qtype   uint16
    unicast bool // QU bit was set
}

type dnsRecord struct {
    name  string
    rtype uint16
    ttl   uint32
    data  []byte
    flush bool // set the cache-flush bit on this record
}
```

```go
// dnssd.go
type svcAddrs struct {
    host string   // e.g. "printcap.local"
    v4   []net.IP // 4-byte IPs to advertise
    v6   []net.IP // 16-byte IPs to advertise
}

type service struct {
    instance string   // e.g. "printcap"
    svcType  string   // e.g. "_ipp._tcp"
    port     uint16
    txt      []string // e.g. []string{"txtvers=1", "rp=ipp/print", ...}
    subtypes []string // e.g. []string{"_universal", "_cups"} (browse sub-types)
}

func (s service) instanceName() string { return s.instance + "." + s.svcType + ".local" }
func (s service) browseName() string   { return s.svcType + ".local" }
```

TTL constants (RFC 6762 §10 recommendations):

```go
// mdns.go
const (
    ttlDNSSD uint32 = 4500 // PTR/SRV/TXT
    ttlHost  uint32 = 120  // A/AAAA
)
```

---

## Task 1: DNS name encoding & decoding (`dnsmsg.go`)

**Files:**
- Create: `dnsmsg.go`
- Test: `dnsmsg_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestEncodeName(t *testing.T) {
    got := encodeName("_ipp._tcp.local")
    want := []byte{4, '_', 'i', 'p', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0}
    if string(got) != string(want) {
        t.Fatalf("encodeName mismatch\n got=%v\nwant=%v", got, want)
    }
}

func TestParseNameRoundTrip(t *testing.T) {
    enc := encodeName("printcap._ipp._tcp.local")
    name, next, ok := parseName(enc, 0)
    if !ok {
        t.Fatal("parseName returned ok=false")
    }
    if name != "printcap._ipp._tcp.local" {
        t.Fatalf("got %q", name)
    }
    if next != len(enc) {
        t.Fatalf("next=%d want=%d", next, len(enc))
    }
}

func TestParseNameCompressionPointer(t *testing.T) {
    // "local" at offset 0, then "_ipp" + pointer back to offset 0.
    buf := append([]byte{}, encodeName("local")...) // 0..6 (5 'local' 0)
    start := len(buf)
    buf = append(buf, 4, '_', 'i', 'p', 'p')      // label "_ipp"
    buf = append(buf, 0xC0, 0x00)                  // pointer to offset 0 ("local")
    name, next, ok := parseName(buf, start)
    if !ok {
        t.Fatal("ok=false")
    }
    if name != "_ipp.local" {
        t.Fatalf("got %q", name)
    }
    if next != len(buf) {
        t.Fatalf("next=%d want=%d", next, len(buf))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestEncodeName -v`
Expected: FAIL — `undefined: encodeName`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import "strings"

const (
    dnsTypeA    uint16 = 1
    dnsTypePTR  uint16 = 12
    dnsTypeTXT  uint16 = 16
    dnsTypeAAAA uint16 = 28
    dnsTypeSRV  uint16 = 33
    dnsTypeANY  uint16 = 255

    dnsClassIN   uint16 = 1
    dnsFlushBit  uint16 = 0x8000
    dnsClassMask uint16 = 0x7fff
)

// encodeName encodes a dotted DNS name as length-prefixed labels terminated by
// a zero byte. No compression (mDNS permits uncompressed responses).
func encodeName(name string) []byte {
    name = strings.TrimSuffix(name, ".")
    var out []byte
    if name == "" {
        return []byte{0}
    }
    for _, label := range strings.Split(name, ".") {
        if len(label) > 63 {
            label = label[:63]
        }
        out = append(out, byte(len(label)))
        out = append(out, label...)
    }
    return append(out, 0)
}

// parseName decodes a DNS name starting at off, following compression pointers.
// It returns the name, the offset of the byte after the name in the ORIGINAL
// (non-pointer) stream, and ok. next is only meaningful for the first pointer
// jump: it is the position right after the initial sequence.
func parseName(b []byte, off int) (name string, next int, ok bool) {
    var labels []string
    jumped := false
    next = -1
    safety := 0
    for {
        if off < 0 || off >= len(b) {
            return "", 0, false
        }
        safety++
        if safety > 128 {
            return "", 0, false // pointer loop guard
        }
        l := int(b[off])
        if l == 0 {
            off++
            if !jumped {
                next = off
            }
            return strings.Join(labels, "."), next, true
        }
        if l&0xC0 == 0xC0 { // compression pointer
            if off+1 >= len(b) {
                return "", 0, false
            }
            ptr := (l&0x3F)<<8 | int(b[off+1])
            if !jumped {
                next = off + 2
            }
            jumped = true
            off = ptr
            continue
        }
        if off+1+l > len(b) {
            return "", 0, false
        }
        labels = append(labels, string(b[off+1:off+1+l]))
        off += 1 + l
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestEncodeName|TestParseName' -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add dnsmsg.go dnsmsg_test.go
git commit -m "feat(mdns): DNS name encode/decode with compression-pointer support"
```

---

## Task 2: Resource-record data builders (`dnsmsg.go`)

**Files:**
- Modify: `dnsmsg.go`
- Test: `dnsmsg_test.go`

- [ ] **Step 1: Write the failing test**

```go
import "net"

func TestRdataSRV(t *testing.T) {
    got := rdataSRV(0, 0, 631, "printcap.local")
    want := append([]byte{0, 0, 0, 0, 0x02, 0x77}, encodeName("printcap.local")...) // port 631 = 0x0277
    if string(got) != string(want) {
        t.Fatalf("rdataSRV\n got=%v\nwant=%v", got, want)
    }
}

func TestRdataTXT(t *testing.T) {
    got := rdataTXT([]string{"txtvers=1", "rp=ipp/print"})
    want := []byte{9}
    want = append(want, "txtvers=1"...)
    want = append(want, 12)
    want = append(want, "rp=ipp/print"...)
    if string(got) != string(want) {
        t.Fatalf("rdataTXT\n got=%v\nwant=%v", got, want)
    }
}

func TestRdataA(t *testing.T) {
    got := rdataA(net.IPv4(192, 168, 1, 50))
    if len(got) != 4 || got[0] != 192 || got[3] != 50 {
        t.Fatalf("rdataA got=%v", got)
    }
}

func TestRdataAAAA(t *testing.T) {
    got := rdataAAAA(net.ParseIP("fe80::1"))
    if len(got) != 16 {
        t.Fatalf("rdataAAAA len=%d", len(got))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestRdata -v`
Expected: FAIL — `undefined: rdataSRV`

- [ ] **Step 3: Write minimal implementation**

```go
import (
    "encoding/binary"
    "net"
)

func rdataPTR(target string) []byte { return encodeName(target) }

func rdataSRV(priority, weight, port uint16, target string) []byte {
    out := make([]byte, 6)
    binary.BigEndian.PutUint16(out[0:], priority)
    binary.BigEndian.PutUint16(out[2:], weight)
    binary.BigEndian.PutUint16(out[4:], port)
    return append(out, encodeName(target)...)
}

// rdataTXT encodes each "key=value" string as a length-prefixed character-string
// (truncated to 255 bytes per DNS-SD). An empty set encodes as a single 0 byte.
func rdataTXT(pairs []string) []byte {
    if len(pairs) == 0 {
        return []byte{0}
    }
    var out []byte
    for _, p := range pairs {
        if len(p) > 255 {
            p = p[:255]
        }
        out = append(out, byte(len(p)))
        out = append(out, p...)
    }
    return out
}

func rdataA(ip net.IP) []byte    { return append([]byte{}, ip.To4()...) }
func rdataAAAA(ip net.IP) []byte { return append([]byte{}, ip.To16()...) }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestRdata -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add dnsmsg.go dnsmsg_test.go
git commit -m "feat(mdns): resource-record data builders (PTR/SRV/TXT/A/AAAA)"
```

---

## Task 3: Question parsing & response building (`dnsmsg.go`)

**Files:**
- Modify: `dnsmsg.go`
- Test: `dnsmsg_test.go`

- [ ] **Step 1: Write the failing test**

```go
func buildQuery(name string, qtype uint16, unicast bool) []byte {
    var b []byte
    hdr := make([]byte, 12)
    binary.BigEndian.PutUint16(hdr[4:], 1) // qdcount = 1
    b = append(b, hdr...)
    b = append(b, encodeName(name)...)
    qt := make([]byte, 4)
    binary.BigEndian.PutUint16(qt[0:], qtype)
    qclass := dnsClassIN
    if unicast {
        qclass |= dnsFlushBit
    }
    binary.BigEndian.PutUint16(qt[2:], qclass)
    return append(b, qt...)
}

func TestParseQuestions(t *testing.T) {
    q := buildQuery("_ipp._tcp.local", dnsTypePTR, true)
    qs, ok := parseQuestions(q)
    if !ok || len(qs) != 1 {
        t.Fatalf("ok=%v n=%d", ok, len(qs))
    }
    if qs[0].name != "_ipp._tcp.local" || qs[0].qtype != dnsTypePTR || !qs[0].unicast {
        t.Fatalf("got %+v", qs[0])
    }
}

func TestBuildResponseParsesBack(t *testing.T) {
    recs := []dnsRecord{
        {name: "_ipp._tcp.local", rtype: dnsTypePTR, ttl: ttlDNSSD, data: rdataPTR("printcap._ipp._tcp.local")},
    }
    resp := buildResponse(recs)
    // Header: QR=1 (0x8400 = response + authoritative), ancount=1.
    if binary.BigEndian.Uint16(resp[2:]) != 0x8400 {
        t.Fatalf("flags=0x%04x", binary.BigEndian.Uint16(resp[2:]))
    }
    if binary.BigEndian.Uint16(resp[6:]) != 1 {
        t.Fatalf("ancount=%d", binary.BigEndian.Uint16(resp[6:]))
    }
}
```

(`ttlDNSSD` is introduced in Task 5's file `mdns.go`; for this test to compile before Task 5, add it now in `dnsmsg.go` as shown in Step 3.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestParseQuestions|TestBuildResponse' -v`
Expected: FAIL — `undefined: parseQuestions`

- [ ] **Step 3: Write minimal implementation**

```go
// TTLs (RFC 6762 §10). Declared here so dnsmsg tests compile independently;
// mdns.go references the same identifiers.
const (
    ttlDNSSD uint32 = 4500 // PTR/SRV/TXT
    ttlHost  uint32 = 120  // A/AAAA
)

// parseQuestions parses the question section of a DNS message. The answer/
// authority/additional sections are ignored (known-answer suppression is
// handled best-effort elsewhere).
func parseQuestions(b []byte) ([]dnsQuestion, bool) {
    if len(b) < 12 {
        return nil, false
    }
    qd := int(binary.BigEndian.Uint16(b[4:]))
    off := 12
    var out []dnsQuestion
    for i := 0; i < qd; i++ {
        name, next, ok := parseName(b, off)
        if !ok {
            return nil, false
        }
        off = next
        if off+4 > len(b) {
            return nil, false
        }
        qtype := binary.BigEndian.Uint16(b[off:])
        qclass := binary.BigEndian.Uint16(b[off+2:])
        off += 4
        out = append(out, dnsQuestion{
            name:    name,
            qtype:   qtype,
            unicast: qclass&dnsFlushBit != 0,
        })
    }
    return out, true
}

// buildResponse assembles an mDNS response message carrying the given answer
// records. QR + Authoritative are set (0x8400); query ID is 0 per RFC 6762.
func buildResponse(answers []dnsRecord) []byte {
    hdr := make([]byte, 12)
    binary.BigEndian.PutUint16(hdr[2:], 0x8400)               // QR=1, AA=1
    binary.BigEndian.PutUint16(hdr[6:], uint16(len(answers))) // ancount
    out := hdr
    for _, r := range answers {
        out = append(out, encodeRR(r)...)
    }
    return out
}

func encodeRR(r dnsRecord) []byte {
    out := encodeName(r.name)
    tc := make([]byte, 8)
    binary.BigEndian.PutUint16(tc[0:], r.rtype)
    class := dnsClassIN
    if r.flush {
        class |= dnsFlushBit
    }
    binary.BigEndian.PutUint16(tc[2:], class)
    binary.BigEndian.PutUint32(tc[4:], r.ttl)
    out = append(out, tc...)
    rl := make([]byte, 2)
    binary.BigEndian.PutUint16(rl, uint16(len(r.data)))
    out = append(out, rl...)
    return append(out, r.data...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestParseQuestions|TestBuildResponse' -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add dnsmsg.go dnsmsg_test.go
git commit -m "feat(mdns): question parsing and response assembly"
```

---

## Task 4: Service model & TXT builders (`dnssd.go`)

**Files:**
- Create: `dnssd.go`
- Test: `dnssd_test.go`

This task introduces a `boundListeners` snapshot so the service model never reads
the Engine directly. It is built by the Engine in Task 7.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "strings"
    "testing"
)

func testCfg() *Config {
    c := defaultConfig()
    c.Printer.Name = "printcap"
    c.Printer.MakeAndModel = "printcap Virtual MFP"
    c.Printer.Location = "lab"
    c.Printer.Color = true
    return c
}

func TestBuildServicesMirrorsListeners(t *testing.T) {
    cfg = testCfg()
    bl := boundListeners{IPP: 631, Raw9100: 9100, LPR: 515} // IPPS and dashboard off
    svcs := buildServices(bl, true /* airprint */, "printcap")

    types := map[string]service{}
    for _, s := range svcs {
        types[s.svcType] = s
    }
    if _, ok := types["_ipp._tcp"]; !ok {
        t.Error("expected _ipp._tcp advertised")
    }
    if _, ok := types["_pdl-datastream._tcp"]; !ok {
        t.Error("expected _pdl-datastream._tcp advertised")
    }
    if _, ok := types["_printer._tcp"]; !ok {
        t.Error("expected _printer._tcp advertised")
    }
    if _, ok := types["_ipps._tcp"]; ok {
        t.Error("_ipps._tcp must NOT be advertised when IPPS is off")
    }
}

func TestIPPTxtHasURFButPrinterDoesNot(t *testing.T) {
    cfg = testCfg()
    svcs := buildServices(boundListeners{IPP: 631, LPR: 515}, true, "printcap")
    for _, s := range svcs {
        joined := strings.Join(s.txt, ",")
        switch s.svcType {
        case "_ipp._tcp":
            if !strings.Contains(joined, "URF=") {
                t.Errorf("_ipp TXT missing URF: %v", s.txt)
            }
            if !strings.Contains(joined, "rp=ipp/print") {
                t.Errorf("_ipp TXT missing rp=ipp/print: %v", s.txt)
            }
            if !hasPair(s.txt, "Color", "T") {
                t.Errorf("_ipp TXT missing Color=T: %v", s.txt)
            }
        case "_printer._tcp":
            if strings.Contains(joined, "URF=") {
                t.Errorf("_printer TXT must not contain URF: %v", s.txt)
            }
        }
    }
}

func TestIPPSubtypesIncludeAirPrint(t *testing.T) {
    cfg = testCfg()
    svcs := buildServices(boundListeners{IPP: 631}, true, "printcap")
    for _, s := range svcs {
        if s.svcType == "_ipp._tcp" {
            if !contains(s.subtypes, "_universal") {
                t.Errorf("expected _universal sub-type, got %v", s.subtypes)
            }
        }
    }
}

func hasPair(txt []string, k, v string) bool {
    for _, p := range txt {
        if p == k+"="+v {
            return true
        }
    }
    return false
}
```

Note: `contains([]string, string)` does not yet exist as a `[]string` helper.
`firstOr` exists in `ipp.go`. Add a small `containsStr` in `dnssd.go` instead of
reusing the byte-oriented `contains` from `pdl.go`, and use `containsStr` in the
test (rename the call in the test to `containsStr`).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestBuildServices|TestIPPTxt|TestIPPSubtypes' -v`
Expected: FAIL — `undefined: boundListeners` / `buildServices`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import "strings"

// boundListeners is the snapshot of which listeners actually bound, with their
// effective ports. 0 means "not advertised". The Engine fills this in.
type boundListeners struct {
    IPP     int
    IPPS    int
    Raw9100 int
    LPR     int
    Dash    int
}

func containsStr(xs []string, want string) bool {
    for _, x := range xs {
        if x == want {
            return true
        }
    }
    return false
}

func boolTF(b bool) string {
    if b {
        return "T"
    }
    return "F"
}

// urfSupported is the single source of truth for the printer's URF capability
// set. BOTH this file (the AirPrint URF TXT value) and ipp.go's urf-supported
// attribute derive from it, so the two transports never drift. Returns the
// ordered token list, e.g. []string{"V1.4", "W8", "SRGB24", "RS300-600"}.
//
// REQUIRED REFACTOR: change ipp.go:271 from the hardcoded
//   writeStrSet(&buf, tagKeyword, "urf-supported", "V1.4", "W8", "SRGB24", "RS300-600")
// to derive from this same function:
//   writeStrSet(&buf, tagKeyword, "urf-supported", urfSupported()...)
func urfSupported() []string {
    return []string{"V1.4", "W8", "SRGB24", "RS300-600"}
}

// urfTxt joins urfSupported() into the comma-separated AirPrint URF TXT value.
func urfTxt() string {
    return strings.Join(urfSupported(), ",")
}

// buildServices turns the live config plus the set of bound listeners into the
// DNS-SD services to advertise. instance is the (already collision-resolved)
// service instance name.
func buildServices(bl boundListeners, airprint bool, instance string) []service {
    p := cfg.Printer
    var svcs []service

    rp := strings.TrimPrefix(orElse(cfg.IPPOpts.DefaultPath, "/ipp/print"), "/")
    pdl := strings.Join(p.DocumentFormats, ",")
    duplex := boolTF(containsAnyTwoSided(p.Sides))
    uuid := "00000000-0000-1000-8000-000000000001"
    adminurl := ""
    if bl.Dash > 0 {
        // Use the resolved host, not instance+".local": the instance name and
        // the host label can differ after sanitization (e.g. instance
        // "Lobby MFP" vs host "Lobby-MFP.local").
        adminurl = "http://" + resolveHost() + ":" + itoa(bl.Dash) + "/"
    }

    ippTxt := func(tls bool) []string {
        txt := []string{
            "txtvers=1", "qtotal=1",
            "rp=" + rp,
            "ty=" + p.MakeAndModel,
            "product=(" + p.MakeAndModel + ")",
            "note=" + p.Location,
            "pdl=" + pdl,
            "UUID=" + uuid,
            "Color=" + boolTF(p.Color),
            "Duplex=" + duplex,
            "URF=" + urfTxt(),
            "kind=document",
        }
        if adminurl != "" {
            txt = append(txt, "adminurl="+adminurl)
        }
        if tls {
            txt = append(txt, "TLS=1.2")
        }
        return txt
    }

    subs := []string{}
    if airprint {
        subs = []string{"_universal", "_cups"}
    }

    if bl.IPP > 0 {
        svcs = append(svcs, service{instance, "_ipp._tcp", uint16(bl.IPP), ippTxt(false), subs})
    }
    if bl.IPPS > 0 {
        svcs = append(svcs, service{instance, "_ipps._tcp", uint16(bl.IPPS), ippTxt(true), subs})
    }
    if bl.Raw9100 > 0 {
        txt := []string{"txtvers=1", "qtotal=1", "ty=" + p.MakeAndModel,
            "product=(" + p.MakeAndModel + ")", "note=" + p.Location,
            "pdl=" + pdl, "Transparent=T", "Binary=T"}
        svcs = append(svcs, service{instance, "_pdl-datastream._tcp", uint16(bl.Raw9100), txt, nil})
    }
    if bl.LPR > 0 {
        txt := []string{"txtvers=1", "qtotal=1", "rp=auto", "ty=" + p.MakeAndModel, "note=" + p.Location}
        svcs = append(svcs, service{instance, "_printer._tcp", uint16(bl.LPR), txt, nil})
    }
    return svcs
}

func containsAnyTwoSided(sides []string) bool {
    for _, s := range sides {
        if strings.HasPrefix(s, "two-sided") {
            return true
        }
    }
    return false
}
```

Also update the test: change the `contains(s.subtypes, "_universal")` call to
`containsStr(s.subtypes, "_universal")`.

**URF single source of truth (spec §2/§4):** the `URF` TXT value must be *derived*
from the same set IPP advertises, not duplicated. This task adds `urfSupported()
[]string` in `dnssd.go` as the one place that defines the capability tokens;
`urfTxt()` joins them for the TXT record. As part of this task, refactor
`ipp.go:271` to call the shared function — replace the hardcoded
`writeStrSet(&buf, tagKeyword, "urf-supported", "V1.4", "W8", "SRGB24", "RS300-600")`
with `writeStrSet(&buf, tagKeyword, "urf-supported", urfSupported()...)` so both
transports read from `urfSupported()`. Add a test asserting `urfTxt()` equals
`strings.Join(urfSupported(), ",")` to lock the relationship.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestBuildServices|TestIPPTxt|TestIPPSubtypes' -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add dnssd.go dnssd_test.go
git commit -m "feat(mdns): DNS-SD service model and per-service TXT records"
```

---

## Task 5: Responder answer selection (`mdns.go`, pure logic first)

**Files:**
- Create: `mdns.go`
- Test: `mdns_test.go`

Build the pure, socket-free `answersFor()` first so query handling is fully unit-tested.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "net"
    "testing"
)

func sampleAddrs() svcAddrs {
    return svcAddrs{host: "printcap.local", v4: []net.IP{net.IPv4(192, 168, 1, 50)}}
}

func TestAnswersForBrowsePTR(t *testing.T) {
    svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631,
        txt: []string{"txtvers=1"}, subtypes: []string{"_universal"}}}
    recs := answersFor(dnsQuestion{name: "_ipp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
    if !hasRecord(recs, "_ipp._tcp.local", dnsTypePTR) {
        t.Fatalf("expected browse PTR, got %v", recNames(recs))
    }
    // SRV + TXT + A should be bundled as additionals/answers.
    if !hasRecord(recs, "printcap._ipp._tcp.local", dnsTypeSRV) {
        t.Error("expected SRV bundled")
    }
    if !hasRecord(recs, "printcap._ipp._tcp.local", dnsTypeTXT) {
        t.Error("expected TXT bundled")
    }
    if !hasRecord(recs, "printcap.local", dnsTypeA) {
        t.Error("expected A bundled")
    }
}

func TestAnswersForSubtypePTR(t *testing.T) {
    svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631,
        txt: []string{"txtvers=1"}, subtypes: []string{"_universal"}}}
    recs := answersFor(dnsQuestion{name: "_universal._sub._ipp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
    if !hasRecord(recs, "_universal._sub._ipp._tcp.local", dnsTypePTR) {
        t.Fatalf("expected sub-type PTR, got %v", recNames(recs))
    }
}

func TestAnswersForServiceEnumeration(t *testing.T) {
    svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631, txt: []string{"txtvers=1"}}}
    recs := answersFor(dnsQuestion{name: "_services._dns-sd._udp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
    if !hasRecord(recs, "_services._dns-sd._udp.local", dnsTypePTR) {
        t.Fatalf("expected meta-query PTR, got %v", recNames(recs))
    }
}

func TestAnswersForUnrelatedQuestionEmpty(t *testing.T) {
    svcs := []service{{instance: "printcap", svcType: "_ipp._tcp", port: 631, txt: []string{"txtvers=1"}}}
    recs := answersFor(dnsQuestion{name: "_afpovertcp._tcp.local", qtype: dnsTypePTR}, svcs, sampleAddrs())
    if len(recs) != 0 {
        t.Fatalf("expected no records, got %v", recNames(recs))
    }
}

func hasRecord(recs []dnsRecord, name string, rtype uint16) bool {
    for _, r := range recs {
        if r.name == name && r.rtype == rtype {
            return true
        }
    }
    return false
}

func recNames(recs []dnsRecord) []string {
    var out []string
    for _, r := range recs {
        out = append(out, r.name)
    }
    return out
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestAnswersFor -v`
Expected: FAIL — `undefined: answersFor`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import "net"

const (
    mdnsAddr4 = "224.0.0.251:5353"
    mdnsAddr6 = "[ff02::fb]:5353"
    metaQuery = "_services._dns-sd._udp.local"
)

// srvAndTxt returns the SRV, TXT, and host A/AAAA records for one service.
func srvAndTxt(s service, a svcAddrs) []dnsRecord {
    recs := []dnsRecord{
        {name: s.instanceName(), rtype: dnsTypeSRV, ttl: ttlDNSSD, flush: true,
            data: rdataSRV(0, 0, s.port, a.host)},
        {name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD, flush: true,
            data: rdataTXT(s.txt)},
    }
    recs = append(recs, hostRecords(a)...)
    return recs
}

func hostRecords(a svcAddrs) []dnsRecord {
    var recs []dnsRecord
    for _, ip := range a.v4 {
        recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeA, ttl: ttlHost, flush: true, data: rdataA(ip)})
    }
    for _, ip := range a.v6 {
        recs = append(recs, dnsRecord{name: a.host, rtype: dnsTypeAAAA, ttl: ttlHost, flush: true, data: rdataAAAA(ip)})
    }
    return recs
}

// answersFor returns the records that answer one question, or nil if the
// question targets nothing we advertise.
func answersFor(q dnsQuestion, svcs []service, a svcAddrs) []dnsRecord {
    var out []dnsRecord
    matchesType := func(want uint16) bool { return q.qtype == want || q.qtype == dnsTypeANY }

    // Meta-query: enumerate our service types.
    if q.name == metaQuery && matchesType(dnsTypePTR) {
        for _, s := range svcs {
            out = append(out, dnsRecord{name: metaQuery, rtype: dnsTypePTR, ttl: ttlDNSSD,
                data: rdataPTR(s.browseName())})
        }
        return out
    }

    for _, s := range svcs {
        switch {
        case q.name == s.browseName() && matchesType(dnsTypePTR):
            out = append(out, dnsRecord{name: s.browseName(), rtype: dnsTypePTR, ttl: ttlDNSSD,
                data: rdataPTR(s.instanceName())})
            out = append(out, srvAndTxt(s, a)...)
        case q.name == s.instanceName() && matchesType(dnsTypeSRV):
            out = append(out, srvAndTxt(s, a)...)
        case q.name == s.instanceName() && matchesType(dnsTypeTXT):
            out = append(out, dnsRecord{name: s.instanceName(), rtype: dnsTypeTXT, ttl: ttlDNSSD,
                flush: true, data: rdataTXT(s.txt)})
        case q.name == a.host && (matchesType(dnsTypeA) || matchesType(dnsTypeAAAA)):
            out = append(out, hostRecords(a)...)
        }
        // Sub-type browse PTRs (e.g. _universal._sub._ipp._tcp.local).
        for _, sub := range s.subtypes {
            subName := sub + "._sub." + s.svcType + ".local"
            if q.name == subName && matchesType(dnsTypePTR) {
                out = append(out, dnsRecord{name: subName, rtype: dnsTypePTR, ttl: ttlDNSSD,
                    data: rdataPTR(s.instanceName())})
            }
        }
    }
    return out
}

var _ = net.IPv4 // net used by helpers above
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestAnswersFor -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add mdns.go mdns_test.go
git commit -m "feat(mdns): pure answer-selection for DNS-SD queries"
```

---

## Task 5.5: Instance collision rename (`mdns.go`)

**Files:**
- Modify: `mdns.go`
- Test: `mdns_test.go`

Spec §4 ("Name-collision handling, RFC 6762 §9") and §5 ("on start, lightweight
**probe** for name collision") require renaming our instance if another responder
already owns the name. This is best-effort: a pure `uniqueInstance` for the rename
logic (unit-tested) plus a short probe wired into `startResponder`.

- [ ] **Step 1: Write the failing test**

```go
func TestUniqueInstance(t *testing.T) {
    if got := uniqueInstance("printcap", map[string]bool{}); got != "printcap" {
        t.Fatalf("free name should be unchanged, got %q", got)
    }
    taken := map[string]bool{"printcap": true}
    if got := uniqueInstance("printcap", taken); got != "printcap (2)" {
        t.Fatalf("got %q, want %q", got, "printcap (2)")
    }
    taken["printcap (2)"] = true
    taken["printcap (3)"] = true
    if got := uniqueInstance("printcap", taken); got != "printcap (4)" {
        t.Fatalf("got %q, want %q", got, "printcap (4)")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestUniqueInstance -v`
Expected: FAIL — `undefined: uniqueInstance`

- [ ] **Step 3: Write minimal implementation**

```go
import "strconv"

// uniqueInstance returns base if it is not in taken; otherwise it appends
// " (2)", " (3)", … until it finds a name not in taken (RFC 6762 §9 style).
func uniqueInstance(base string, taken map[string]bool) string {
    if !taken[base] {
        return base
    }
    for n := 2; ; n++ {
        cand := base + " (" + strconv.Itoa(n) + ")"
        if !taken[cand] {
            return cand
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./... -run TestUniqueInstance -v`
Expected: PASS.

- [ ] **Step 5: Wire probing into `startResponder` (best-effort)**

Before announcing (Task 6), probe for our own instance name and rename if it is
already answered. After the sockets are open and before `go r.announce()`:

1. Build the probe: a query for our IPP instance name
   (`<instance>._ipp._tcp.local`, type `ANY`) using the same `buildQuery` shape
   the tests use, and `writeMulticast` it on each open conn.
2. Collect answers for a short window (~250 ms): temporarily read incoming
   packets (or have `serve` feed a channel) and record every instance name that
   appears in the answer section of replies referencing our service types into a
   `taken map[string]bool`.
3. Compute `name := uniqueInstance(resolveInstance(), taken)`. If it differs from
   the configured instance, `logWarn("mDNS", "instance %q in use, advertising as
   %q", resolveInstance(), name)`, rebuild `r.svcs` with the new instance (each
   `service.instance = name`), and update `r.addrs`/records accordingly before
   announcing.

Keep it strictly best-effort: any probe read error is ignored and we proceed with
the original name. The probe must not block startup beyond its short window, and a
collision never prevents advertising.

- [ ] **Step 6: Commit**

```bash
git add mdns.go mdns_test.go
git commit -m "feat(mdns): instance-collision probe and rename (RFC 6762 §9)"
```

---

## Task 6: Responder runtime — sockets, announce, goodbye (`mdns.go`)

**Files:**
- Modify: `mdns.go`

This is the socket-driven shell around `answersFor()`. It is exercised by the
manual acceptance steps (multicast is not unit-tested in CI).

- [ ] **Step 1: Write the implementation**

```go
import (
    "encoding/binary"
    "strings"
    "sync"
    "time"
)

// mdnsResponder owns the multicast sockets and the advertised service set.
type mdnsResponder struct {
    conns []*net.UDPConn
    svcs  []service
    addrs svcAddrs
    grp4  *net.UDPAddr
    grp6  *net.UDPAddr
    mu    sync.Mutex
    done  chan struct{}
}

// startResponder opens whatever multicast sockets it can and begins answering.
// It returns nil (and logs) if no socket could be opened, so mDNS failure never
// stops other listeners.
func startResponder(svcs []service, addrs svcAddrs) *mdnsResponder {
    r := &mdnsResponder{svcs: svcs, addrs: addrs, done: make(chan struct{})}
    r.grp4, _ = net.ResolveUDPAddr("udp4", mdnsAddr4)
    r.grp6, _ = net.ResolveUDPAddr("udp6", mdnsAddr6)

    // Join the multicast group on each usable interface (spec §5: "Join the
    // group per usable interface; per-interface failures are logged at debug
    // and skipped"). Using nil for the interface binds only the default route,
    // which misses multi-homed hosts and many Windows configurations, so we
    // enumerate explicitly.
    ifaces, err := net.Interfaces()
    if err != nil {
        logWarn("mDNS", "cannot enumerate interfaces: %v", err)
    }
    for _, ifi := range ifaces {
        // Skip interfaces that cannot carry mDNS.
        if ifi.Flags&net.FlagUp == 0 ||
            ifi.Flags&net.FlagLoopback != 0 ||
            ifi.Flags&net.FlagMulticast == 0 {
            continue
        }
        if c, err := net.ListenMulticastUDP("udp4", &ifi, r.grp4); err == nil {
            r.conns = append(r.conns, c)
        } else {
            logDebug("mDNS", "IPv4 5353 join on %s failed: %v", ifi.Name, err)
        }
        if c, err := net.ListenMulticastUDP("udp6", &ifi, r.grp6); err == nil {
            r.conns = append(r.conns, c)
        } else {
            logDebug("mDNS", "IPv6 5353 join on %s failed: %v", ifi.Name, err)
        }
    }
    if len(r.conns) == 0 {
        logWarn("mDNS", "no multicast socket available; discovery advertisement disabled")
        return nil
    }

    for _, c := range r.conns {
        go r.serve(c)
    }
    go r.announce()
    names := make([]string, len(svcs))
    for i, s := range svcs {
        names[i] = s.svcType
    }
    logInfo("mDNS", "advertising %d service(s) as %q [%s]", len(svcs), addrs.host, strings.Join(names, ", "))
    return r
}

func (r *mdnsResponder) serve(c *net.UDPConn) {
    buf := make([]byte, 9000)
    for {
        n, src, err := c.ReadFromUDP(buf)
        if err != nil {
            return // socket closed
        }
        qs, ok := parseQuestions(buf[:n])
        if !ok {
            continue
        }
        // Known-answer suppression (RFC 6762 §7.1, spec §5): parse the query's
        // answer section and drop any record the querier already knows.
        known := knownAnswers(buf[:n])
        var answers []dnsRecord
        wantUnicast := false
        for _, q := range qs {
            recs := answersFor(q, r.svcs, r.addrs)
            for _, rec := range recs {
                if recordKnown(rec, known) {
                    continue // suppress: querier already has a live copy
                }
                answers = append(answers, rec)
                if q.unicast {
                    wantUnicast = true
                }
            }
            if len(recs) > 0 {
                logTrace("mDNS", "answered %s for %s from %s", dnsTypeName(q.qtype), q.name, src)
            }
        }
        if len(answers) == 0 {
            continue
        }
        msg := buildResponse(answers)
        if wantUnicast {
            _, _ = c.WriteToUDP(msg, src)
        } else {
            r.writeMulticast(c, msg)
        }
    }
}

func (r *mdnsResponder) writeMulticast(c *net.UDPConn, msg []byte) {
    grp := r.grp4
    if c.LocalAddr() != nil && strings.Contains(c.LocalAddr().String(), "::") {
        grp = r.grp6
    }
    _, _ = c.WriteToUDP(msg, grp)
}

// announce sends unsolicited responses for all records twice ~1s apart.
func (r *mdnsResponder) announce() {
    msg := buildResponse(r.allRecords())
    for i := 0; i < 2; i++ {
        for _, c := range r.conns {
            r.writeMulticast(c, msg)
        }
        select {
        case <-time.After(time.Second):
        case <-r.done:
            return
        }
    }
}

// allRecords returns the full record set used for announce/goodbye.
func (r *mdnsResponder) allRecords() []dnsRecord {
    var recs []dnsRecord
    for _, s := range r.svcs {
        recs = append(recs, dnsRecord{name: s.browseName(), rtype: dnsTypePTR, ttl: ttlDNSSD,
            data: rdataPTR(s.instanceName())})
        for _, sub := range s.subtypes {
            subName := sub + "._sub." + s.svcType + ".local"
            recs = append(recs, dnsRecord{name: subName, rtype: dnsTypePTR, ttl: ttlDNSSD,
                data: rdataPTR(s.instanceName())})
        }
        recs = append(recs, srvAndTxt(s, r.addrs)...)
    }
    return recs
}

// Close sends goodbye packets (TTL 0) and shuts the sockets.
func (r *mdnsResponder) Close() error {
    r.mu.Lock()
    defer r.mu.Unlock()
    close(r.done)
    goodbye := r.allRecords()
    for i := range goodbye {
        goodbye[i].ttl = 0
    }
    msg := buildResponse(goodbye)
    for _, c := range r.conns {
        r.writeMulticast(c, msg)
        _ = c.Close()
    }
    logInfo("mDNS", "withdrawn")
    return nil
}

func dnsTypeName(t uint16) string {
    switch t {
    case dnsTypeA:
        return "A"
    case dnsTypeAAAA:
        return "AAAA"
    case dnsTypePTR:
        return "PTR"
    case dnsTypeTXT:
        return "TXT"
    case dnsTypeSRV:
        return "SRV"
    case dnsTypeANY:
        return "ANY"
    default:
        return "?"
    }
}

// knownAnswers parses the answer section of an incoming query (RFC 6762 §7.1
// known-answer suppression). It walks ancount records after the question
// section and returns them as dnsRecords (name + rtype + ttl are sufficient for
// suppression; rdata is captured for exact matching). Best-effort: on any parse
// error it returns whatever it has decoded so far so suppression simply does
// less, never more.
func knownAnswers(b []byte) []dnsRecord {
    if len(b) < 12 {
        return nil
    }
    qd := int(binary.BigEndian.Uint16(b[4:]))
    an := int(binary.BigEndian.Uint16(b[6:]))
    off := 12
    // Skip the question section.
    for i := 0; i < qd; i++ {
        _, next, ok := parseName(b, off)
        if !ok || next+4 > len(b) {
            return nil
        }
        off = next + 4
    }
    var out []dnsRecord
    for i := 0; i < an; i++ {
        name, next, ok := parseName(b, off)
        if !ok || next+10 > len(b) {
            return out
        }
        rtype := binary.BigEndian.Uint16(b[next:])
        ttl := binary.BigEndian.Uint32(b[next+4:])
        rdlen := int(binary.BigEndian.Uint16(b[next+8:]))
        rdStart := next + 10
        if rdStart+rdlen > len(b) {
            return out
        }
        out = append(out, dnsRecord{
            name:  name,
            rtype: rtype,
            ttl:   ttl,
            data:  append([]byte{}, b[rdStart:rdStart+rdlen]...),
        })
        off = rdStart + rdlen
    }
    return out
}

// recordKnown reports whether the querier already knows rec: same name+type and
// a known-answer TTL of at least half ours (RFC 6762 §7.1 — suppress only if the
// remaining TTL is more than half the record's true TTL). We match name+rtype
// and require known.ttl >= rec.ttl/2.
func recordKnown(rec dnsRecord, known []dnsRecord) bool {
    for _, k := range known {
        if k.name == rec.name && k.rtype == rec.rtype && k.ttl >= rec.ttl/2 {
            return true
        }
    }
    return false
}
```

`knownAnswers`/`recordKnown` reference `binary`, already imported in `dnsmsg.go`;
`mdns.go` must add `"encoding/binary"` to its import block for these helpers.

Add a small unit test in `mdns_test.go` driving suppression: build a query for a
browse PTR whose answer section already carries that PTR (via the `buildResponse`
helper to lay out an answer record), confirm `knownAnswers` returns it and that
the serve-loop's `recordKnown` would drop the duplicate while still emitting the
bundled SRV/TXT/A records. Keep it pure (no socket): assert on the
`answersFor` → filter pipeline directly.

Remove the temporary `var _ = net.IPv4` line added in Task 5 (the package now uses `net` throughout).

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: builds with no errors.

- [ ] **Step 3: Run the full test suite (no regressions)**

Run: `go test ./...`
Expected: PASS (all prior mdns/dnssd/dnsmsg tests still green).

- [ ] **Step 4: Commit**

```bash
git add mdns.go
git commit -m "feat(mdns): multicast responder with announce and goodbye"
```

---

## Task 7: Config + flag + Engine wiring (`config.go`, `main.go`, `engine.go`)

**Files:**
- Modify: `config.go` (add `MDNSConf`, field on `Config`, default)
- Modify: `main.go` (`-mdns` flag + override)
- Modify: `engine.go` (collect bound listeners, start/stop responder; add `localAddrs` helper)
- Test: `dnssd_test.go` (instance-name + address-selection helpers)

- [ ] **Step 1: Write the failing test**

```go
func TestResolveInstanceDefaultsToPrinterName(t *testing.T) {
    cfg = testCfg()
    cfg.MDNS = MDNSConf{Enabled: true}
    if got := resolveInstance(); got != "printcap" {
        t.Fatalf("got %q", got)
    }
    cfg.MDNS.Instance = "Lobby MFP"
    if got := resolveInstance(); got != "Lobby MFP" {
        t.Fatalf("got %q", got)
    }
}

func TestResolveHostSanitizes(t *testing.T) {
    cfg = testCfg()
    cfg.MDNS = MDNSConf{}
    cfg.Printer.Name = "Lobby MFP #2"
    if got := resolveHost(); got != "Lobby-MFP-2.local" {
        t.Fatalf("got %q", got)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestResolveInstance|TestResolveHost' -v`
Expected: FAIL — `undefined: MDNSConf` / `resolveInstance`

- [ ] **Step 3a: Add config (`config.go`)**

Add the struct after `DashConf`:

```go
// MDNSConf drives the built-in mDNS/DNS-SD (Bonjour) responder that makes
// printcap auto-discoverable as a driverless printer.
type MDNSConf struct {
    Enabled  bool   `json:"enabled"`
    Instance string `json:"instance"` // blank = printer.name
    Hostname string `json:"hostname"` // blank = sanitized printer.name
    AirPrint bool   `json:"airprint"`
}
```

Add the field to `Config` (after `Dashboard DashConf`):

```go
    MDNS      MDNSConf `json:"mdns"`
```

Add to `defaultConfig()` (after the `Dashboard:` line):

```go
        MDNS: MDNSConf{
            Enabled:  true,
            Instance: "",
            Hostname: "",
            AirPrint: true,
        },
```

Add the resolver helpers (in `dnssd.go`):

```go
import "regexp"

var hostUnsafe = regexp.MustCompile(`[^A-Za-z0-9-]+`)

func resolveInstance() string {
    if cfg.MDNS.Instance != "" {
        return cfg.MDNS.Instance
    }
    return cfg.Printer.Name
}

// resolveHost returns the advertised "<host>.local" label, sanitized to the
// DNS host-label charset (letters, digits, hyphen).
func resolveHost() string {
    h := cfg.MDNS.Hostname
    if h != "" {
        return strings.TrimSuffix(h, ".local") + ".local"
    }
    base := hostUnsafe.ReplaceAllString(cfg.Printer.Name, "-")
    base = strings.Trim(base, "-")
    if base == "" {
        base = "printcap"
    }
    return base + ".local"
}
```

- [ ] **Step 3b: Add the flag (`main.go`)**

In `main()`, beside the other listener flags, add:

```go
    flag.Bool("mdns", true, "advertise the printer over mDNS/DNS-SD (Bonjour)")
```

In `applyFlagOverrides()`'s switch, add a case:

```go
        case "mdns":
            cfg.MDNS.Enabled = get() == "true"
```

- [ ] **Step 3c: Wire the Engine (`engine.go`)**

**Critical (spec §4 "Advertise a service only if its listener is up", spec §9
criterion 3):** `bl` must reflect the listeners that *actually bound*, NOT the
configured `cfg.Ports`/`ports` values. A configured port that fails to bind
(address in use, permission denied, TLS error) must never be advertised.
Therefore the Engine *fills in* a `boundListeners` value as each listener comes
up successfully, and `buildServices` is fed that struct — do not copy `ports`.

Declare the struct once near the top of `Start()` (e.g. just before the
`addTCP`/`addHTTP` closures):

```go
    var bl boundListeners
```

Then record the bound port at each SUCCESSFUL bind site — i.e. everywhere the
existing code does `e.active = append(...)`. Set the matching `bl` field there,
keyed by the listener identity, not by config:

- In the **`addTCP` success path** (after `e.active = append(...)`), the caller
  needs to know which field to set. Give `addTCP`/`addHTTP` a way to record the
  bound port — the simplest is to set the field at each call site right after the
  helper returns success, or pass a small post-bind callback. Concretely, after
  the existing listener wiring, set:
  - raw/9100 bind success → `bl.Raw9100 = ports.Raw9100`
  - LPR bind success → `bl.LPR = ports.LPR`
  - IPP (`addHTTP("IPP", ...)`) success → `bl.IPP = ports.IPP`
  - IPPS (`addHTTP("IPPS", ...)`) success → `bl.IPPS = ports.IPPS`
  - dashboard (`addHTTP("dashboard", ...)`) success → `bl.Dash = ports.Dashboard`

  Because `addTCP`/`addHTTP` swallow bind errors internally (they `return` after
  `e.logf`), make them report success. The cleanest change: have them return a
  `bool` (or the bound port, 0 on failure) so the call site can do
  `if addHTTP("IPP", ports.IPP, nil, ...) { bl.IPP = ports.IPP }`. Set each `bl`
  field ONLY on the success return. (If you prefer not to change the helper
  signatures, set the field on the line immediately after `e.active = append(...)`
  inside each helper by having the helper accept a `*int` out-param to fill.)

- In the **auto-TLS success block** (inside the `if ports.AutoTLS > 0 { ... }`
  branch, in the `else` where `e.active = append(e.active, "IPP/IPPS:"+...)`
  happens), record BOTH mappings since the one port serves IPP and IPPS by
  setting `bl.IPP, bl.IPPS = ports.AutoTLS, ports.AutoTLS`. Do this inside the
  success `else`, not before the bind attempt, so a failed auto-TLS bind
  advertises neither.

Add `localAddrs` and start/stop. After the dashboard block and before
`e.running = ...`, insert (note `bl` is now already populated from real binds):

```go
    if cfg.MDNS.Enabled {
        host := resolveHost()
        v4, v6 := localAddrs(cfg.Bind)
        svcs := buildServices(bl, cfg.MDNS.AirPrint, resolveInstance())
        if len(svcs) > 0 {
            if r := startResponder(svcs, svcAddrs{host: host, v4: v4, v6: v6}); r != nil {
                e.closers = append(e.closers, r)
            }
        }
    }
```

`buildServices` already skips any service whose `bl` field is 0, so listeners
that failed to bind are automatically absent from the advertisement.

Add the helper at the end of `engine.go`:

```go
// localAddrs returns the IPv4 and IPv6 addresses to advertise. A specific bind
// address is advertised as-is; 0.0.0.0/:: expands to all non-loopback
// interface addresses.
func localAddrs(bind string) (v4, v6 []net.IP) {
    if bind != "" && bind != "0.0.0.0" && bind != "::" {
        if ip := net.ParseIP(bind); ip != nil {
            if ip4 := ip.To4(); ip4 != nil {
                return []net.IP{ip4}, nil
            }
            return nil, []net.IP{ip}
        }
    }
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return nil, nil
    }
    for _, a := range addrs {
        ipNet, ok := a.(*net.IPNet)
        if !ok || ipNet.IP.IsLoopback() {
            continue
        }
        if ip4 := ipNet.IP.To4(); ip4 != nil {
            v4 = append(v4, ip4)
        } else if ipNet.IP.To16() != nil && !ipNet.IP.IsLinkLocalUnicast() {
            v6 = append(v6, ipNet.IP)
        }
    }
    return v4, v6
}
```

(`engine.go` already imports `net`.)

- [ ] **Step 4: Run tests + build**

Run: `go test ./... -run 'TestResolve' -v && go build ./... && go vet ./...`
Expected: tests PASS; build and vet clean.

- [ ] **Step 5: Confirm no new dependency crept in**

Run: `git diff -- go.mod go.sum`
Expected: empty (no changes — pure stdlib).

- [ ] **Step 6: Commit**

```bash
git add config.go main.go engine.go dnssd.go dnssd_test.go
git commit -m "feat(mdns): config, -mdns flag, and Engine start/stop wiring"
```

---

## Task 8: Documentation (`README.md`, `ADMIN_GUIDE.md`)

**Files:**
- Modify: `README.md` (new "Auto-discovery (Bonjour/mDNS)" subsection)
- Modify: `ADMIN_GUIDE.md` (config field notes + acceptance step)

- [ ] **Step 1: Add the README section**

Insert after the "SNMP discovery" section in `README.md`:

```markdown
## Auto-discovery (Bonjour / mDNS)

printcap advertises itself over **mDNS/DNS-SD** so CUPS, macOS, iOS (AirPrint),
and Windows discover it automatically — no manual IP/port entry. It announces a
service for each enabled listener: `_ipp._tcp` (IPP), `_ipps._tcp` (IPPS),
`_pdl-datastream._tcp` (raw/9100), and `_printer._tcp` (LPD), plus the
`_universal` AirPrint sub-type so iPhones list it in the Print sheet.

Control it in the `mdns` config block: `enabled` (or `-mdns`), `instance`
(service name; default the printer name), `hostname` (advertised `<host>.local`),
and `airprint` (advertise the AirPrint sub-type + URF key). If UDP 5353 is
already owned by another responder (e.g. Apple Bonjour, Avahi, or the Windows
resolver), printcap logs a warning and disables only its mDNS advertisement.

Verify:

    dns-sd -B _ipp._tcp           # macOS
    avahi-browse -rat             # Linux
    ippfind                       # resolves the printer URI
```

- [ ] **Step 2: Add the ADMIN_GUIDE config note + acceptance step**

In `ADMIN_GUIDE.md` §8 "Config file reference", add an `mdns` block to the JSON
sample and a field note:

```markdown
* **`mdns`** — Bonjour/DNS-SD advertisement: `enabled`, `instance` (service name;
  blank = `printer.name`), `hostname` (advertised `<host>.local`; blank =
  sanitized `printer.name`), `airprint` (advertise the `_universal` sub-type and
  `URF` key for iOS). Advertises only the listeners that actually bound. If UDP
  5353 is unavailable, mDNS disables itself and logs a warning; no other listener
  is affected.
```

Add an acceptance step to §19:

```markdown
8. **mDNS discovery** — on a macOS/Linux client on the same subnet:
   ```
   ippfind            # prints ipp://<host>.local:631/ipp/print
   avahi-browse -rat  # (Linux) lists printcap under _ipp._tcp
   ```
   The printer also appears in the macOS "Add Printer" Bonjour list and the iOS
   Print sheet.
```

- [ ] **Step 3: Commit**

```bash
git add README.md ADMIN_GUIDE.md
git commit -m "docs(mdns): document Bonjour/DNS-SD auto-discovery"
```

---

## Task 9: Manual acceptance (end-to-end discovery)

**Files:** none (verification only).

These require a real network and cannot run in CI. Run from the printcap host
plus one client on the same subnet.

- [ ] **Step 1: Start printcap with defaults**

Run (on the capture host): `go run . -console` (or the built exe).
Expected log line: `INFO [mDNS] advertising N service(s) as "printcap.local" [_ipp._tcp, ...]`.

- [ ] **Step 2: Browse from a client**

macOS: `dns-sd -B _ipp._tcp` → printcap appears.
Linux: `avahi-browse -rat | grep -i printcap` → entry under `_ipp._tcp`.

- [ ] **Step 3: Resolve and print via driverless CUPS**

```
ippfind
lpadmin -p printcap-mdns -E -v "$(ippfind | head -1)" -m everywhere
echo "hello" | lp -d printcap-mdns
```
Expected: a job appears in the printcap dashboard within ~2 s.

- [ ] **Step 4: AirPrint check**

On an iPhone on the same subnet: open any app → Share → Print → printcap is
listed. Print a page; it is captured.

- [ ] **Step 5: Coexistence / degrade check**

Start a second responder on 5353 first (e.g. ensure Avahi/Bonjour is running),
then start printcap. Expected: `WARN [mDNS] ...5353 unavailable...` and all other
listeners run normally (the process does not exit).

- [ ] **Step 6: Goodbye check**

Stop printcap (Ctrl+C). On the client, the browse list drops printcap promptly
(goodbye packets sent).

---

## Self-Review notes (completed by plan author)

- **Spec coverage:** §3 architecture → Tasks 1–7; §4 advertised content → Tasks 4–6
  (incl. URF single-source via `urfSupported()` shared with ipp.go in Task 4, and
  instance/host naming + collision rename in Task 5.5); §5 responder behavior →
  Tasks 5, 5.5, 6 — specifically: query/answer + QU bit (Task 6), **probe/announce/
  goodbye lifecycle** (Task 5.5 probe + Task 6 announce/goodbye), **known-answer
  suppression** (Task 6 `knownAnswers`/`recordKnown`), and **per-interface
  multicast joins** (Task 6 `net.Interfaces()` enumeration); §6 logging → Task 6
  (incl. per-interface debug + rename warn); §7 testing → Tasks 1–5.5 (unit, now
  incl. `TestUniqueInstance`, the URF-derivation test, and the known-answer
  suppression test) + Task 9 (manual); §8 affected files → all tasks (plus the
  ipp.go:271 refactor in Task 4); §9 acceptance criteria → Task 9. **Previously-open
  §5 gaps now closed:** instance probing/rename, known-answer suppression, and
  per-interface group joins are each covered by the tasks listed above.
- **Type consistency:** `boundListeners`, `service`, `svcAddrs`, `dnsRecord`, `dnsQuestion`,
  `answersFor`, `buildServices`, `srvAndTxt`, `startResponder`, `resolveInstance`, `resolveHost`,
  `localAddrs`, `urfSupported`/`urfTxt`, `uniqueInstance`, `knownAnswers`/`recordKnown` are used
  identically across tasks. `containsStr` (string slice) is distinct from
  the byte-oriented `contains` in `pdl.go`. `ttlDNSSD`/`ttlHost` are declared once in `dnsmsg.go`
  (Task 3) and reused by `mdns.go`.
- **Placeholder scan:** none — every code/step is concrete.
- **Dependency guard:** Task 7 Step 5 asserts `go.mod`/`go.sum` are unchanged.
```
