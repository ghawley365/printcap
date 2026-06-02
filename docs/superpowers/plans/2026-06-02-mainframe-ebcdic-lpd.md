# Mainframe EBCDIC + richer LPD Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture IBM mainframe / AS-400 print jobs readably — transcode EBCDIC→UTF-8 with operator-controlled code pages, convert ASA/machine carriage-control, and capture richer LPD metadata — while keeping the raw bytes and zero dependencies.

**Architecture:** Hand-rolled `[256]rune` code-page tables and a heuristic detector in `ebcdic.go`; carriage-control conversion in `carriage.go`; richer control-file parsing in `lpd.go`; central decode + `-decoded.txt` sidecar in `sink.save`, with effective settings resolved from per-queue defaults → global default → auto-detect.

**Tech Stack:** Go 1.26, standard library only. Code-page tables transcribed from the Unicode Consortium IBM mapping files (`https://www.unicode.org/Public/MAPPINGS/VENDORS/MICSFT/EBCDIC/`).

**Build order:** plan #3 of 6 (after Forwarding). It inserts an EBCDIC-decode block into `sink.save`; the Forwarding plan also edits `sink.save` (adds the tee + `error` return). Whichever lands second keeps both edits; the EBCDIC block goes before `store.add`.

---

## Shared types (defined across tasks)

```go
// config.go
type EBCDICConf struct {
    Enabled         bool   `json:"enabled"`
    DefaultCodePage string `json:"default_code_page"` // e.g. "CP037"
    AutoDetect      bool   `json:"auto_detect"`
    DecodedSidecar  bool   `json:"decoded_sidecar"`
    CarriageControl string `json:"carriage_control"`  // none|asa|machine|auto
}

type QueueDefault struct {
    CodePage        string `json:"code_page"`
    CarriageControl string `json:"carriage_control"`
    EBCDIC          bool   `json:"ebcdic"`
}
// LPDOpts gains: QueueDefaults map[string]QueueDefault `json:"queue_defaults"`
```

`job` (in `main.go`) gains: `Class`, `Title`, `CodePage`, `DecodedAs string` (all
`json:",omitempty"`).

---

## Task 1: EBCDIC code-page tables & decode (`ebcdic.go`)

**Files:**
- Create: `ebcdic.go`
- Test: `ebcdic_test.go`

- [ ] **Step 1: Write the failing test (anchor points + round trip)**

```go
package main

import "testing"

func TestDecodeEBCDIC_CP037Anchors(t *testing.T) {
    cases := []struct {
        b    byte
        want rune
    }{
        {0x40, ' '}, {0xC1, 'A'}, {0xC2, 'B'}, {0x81, 'a'}, {0xF0, '0'},
        {0x4B, '.'}, {0x5B, '$'}, {0x7D, '\''}, {0x6C, '%'}, {0x50, '&'},
    }
    for _, c := range cases {
        got := decodeEBCDIC([]byte{c.b}, "CP037")
        if got != string(c.want) {
            t.Errorf("CP037 0x%02x => %q want %q", c.b, got, string(c.want))
        }
    }
}

func TestDecodeEBCDIC_CP037Word(t *testing.T) {
    // "HELLO" in CP037: H=0xC8 E=0xC5 L=0xD3 L=0xD3 O=0xD6
    got := decodeEBCDIC([]byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6}, "CP037")
    if got != "HELLO" {
        t.Fatalf("got %q", got)
    }
}

func TestDecodeEBCDIC_CP500BracketDiffersFromCP037(t *testing.T) {
    // CP500 maps 0x4A to '[' while CP037 maps it to a cent sign — assert they differ.
    if decodeEBCDIC([]byte{0x4A}, "CP500") == decodeEBCDIC([]byte{0x4A}, "CP037") {
        t.Fatal("CP500 and CP037 should differ at 0x4A")
    }
}

func TestDecodeEBCDIC_UnknownPageReturnsEmpty(t *testing.T) {
    if got := decodeEBCDIC([]byte{0xC1}, "CP999"); got != "" {
        t.Fatalf("unknown page should return empty, got %q", got)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestDecodeEBCDIC -v`
Expected: FAIL — `undefined: decodeEBCDIC`

- [ ] **Step 3: Write the implementation**

Create `ebcdic.go` with a registry and one `[256]rune` table per page. Transcribe
each table from the Unicode IBM mapping file for that CCSID (CP037, CP500, CP1047,
CP273, CP285, CP297). Structure:

```go
package main

// ebcdicTables maps a code-page name to its 256-entry byte→rune table.
// Each table is transcribed from the Unicode Consortium IBM mapping files
// (MAPPINGS/VENDORS/MICSFT/EBCDIC/<page>.TXT). The anchor-point tests in
// ebcdic_test.go lock the critical positions.
var ebcdicTables = map[string]*[256]rune{
    "CP037":  &cp037,
    "CP500":  &cp500,
    "CP1047": &cp1047,
    "CP273":  &cp273,
    "CP285":  &cp285,
    "CP297":  &cp297,
}

// cp037 is the EBCDIC US/Canada table. Indices not shown map per the official
// CP037 mapping; the values below are the ASCII-relevant anchors the tests check.
// (Transcribe the full 256 entries from the Unicode mapping file.)
var cp037 = [256]rune{
    0x40: ' ', 0x4B: '.', 0x50: '&', 0x5B: '$', 0x6C: '%', 0x7D: '\'',
    0xC1: 'A', 0xC2: 'B', 0xC3: 'C', 0xC4: 'D', 0xC5: 'E', 0xC6: 'F',
    0xC7: 'G', 0xC8: 'H', 0xC9: 'I',
    0xD1: 'J', 0xD2: 'K', 0xD3: 'L', 0xD4: 'M', 0xD5: 'N', 0xD6: 'O',
    0xD7: 'P', 0xD8: 'Q', 0xD9: 'R',
    0xE2: 'S', 0xE3: 'T', 0xE4: 'U', 0xE5: 'V', 0xE6: 'W', 0xE7: 'X',
    0xE8: 'Y', 0xE9: 'Z',
    0x81: 'a', 0x82: 'b', 0x83: 'c', 0x84: 'd', 0x85: 'e', 0x86: 'f',
    0x87: 'g', 0x88: 'h', 0x89: 'i',
    0x91: 'j', 0x92: 'k', 0x93: 'l', 0x94: 'm', 0x95: 'n', 0x96: 'o',
    0x97: 'p', 0x98: 'q', 0x99: 'r',
    0xA2: 's', 0xA3: 't', 0xA4: 'u', 0xA5: 'v', 0xA6: 'w', 0xA7: 'x',
    0xA8: 'y', 0xA9: 'z',
    0xF0: '0', 0xF1: '1', 0xF2: '2', 0xF3: '3', 0xF4: '4', 0xF5: '5',
    0xF6: '6', 0xF7: '7', 0xF8: '8', 0xF9: '9',
    // ... transcribe remaining punctuation/accented entries from CP037.TXT ...
}
// cp500, cp1047, cp273, cp285, cp297 declared the same way, transcribed from
// their respective mapping files. cp500[0x4A] = '[' (differs from cp037).
var cp500, cp1047, cp273, cp285, cp297 [256]rune

// decodeEBCDIC maps EBCDIC bytes to a UTF-8 string using the named code page.
// Unknown pages return "" (caller logs + skips). Unmapped entries (rune 0) are
// emitted as the Unicode replacement char.
func decodeEBCDIC(data []byte, page string) string {
    tbl, ok := ebcdicTables[page]
    if !ok {
        return ""
    }
    out := make([]rune, len(data))
    for i, b := range data {
        r := tbl[b]
        if r == 0 {
            r = '�'
        }
        out[i] = r
    }
    return string(out)
}
```

> NOTE: The `cp500`…`cp297` package-level `[256]rune` vars must be populated with
> their full tables (an `init()` or composite literals), transcribed from the
> mapping files. Leaving them empty will fail the CP500 anchor test in Step 1,
> which is the point — the test drives completing the data.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestDecodeEBCDIC -v`
Expected: PASS (4 tests) once CP037 and CP500 tables are filled.

- [ ] **Step 5: Commit**

```bash
git add ebcdic.go ebcdic_test.go
git commit -m "feat(ebcdic): hand-rolled EBCDIC code-page tables and decode"
```

---

## Task 2: EBCDIC detection heuristic (`ebcdic.go`)

**Files:**
- Modify: `ebcdic.go`
- Test: `ebcdic_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestLooksEBCDIC(t *testing.T) {
    // EBCDIC "HELLO WORLD" (0x40 = space, dominant on padded records).
    ebc := []byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6, 0x40, 0xE6, 0xD6, 0xD9, 0xD3, 0xC4,
        0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40}
    if !looksEBCDIC(ebc) {
        t.Error("expected EBCDIC detection true")
    }
    if looksEBCDIC([]byte("Hello world, this is plain ASCII text.\n")) {
        t.Error("ASCII text should not be detected as EBCDIC")
    }
    if looksEBCDIC([]byte("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")) {
        t.Error("PDF binary should not be detected as EBCDIC")
    }
    if looksEBCDIC(nil) {
        t.Error("empty should be false")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestLooksEBCDIC -v`
Expected: FAIL — `undefined: looksEBCDIC`

- [ ] **Step 3: Write the implementation**

```go
// looksEBCDIC heuristically reports whether data is EBCDIC text. It samples the
// first 4 KiB and is deliberately conservative: it requires the EBCDIC space
// (0x40) to be the dominant byte and a high share of bytes in EBCDIC-printable
// ranges, while ASCII printables are sparse. Favors leaving data raw over
// corrupting ASCII.
func looksEBCDIC(data []byte) bool {
    n := len(data)
    if n == 0 {
        return false
    }
    if n > 4096 {
        n = 4096
    }
    var spaces, ebcPrintable, asciiPrintable int
    for _, b := range data[:n] {
        if b == 0x40 {
            spaces++
        }
        if isEBCDICPrintable(b) {
            ebcPrintable++
        }
        if b >= 0x20 && b <= 0x7e && b != 0x40 {
            // Exclude 0x40: it is the EBCDIC space and also ASCII '@'. Counting it
            // as ASCII-printable lands the letter+space samples exactly on the 50%
            // boundary (asciiPrintable*100/n == 50, which fails `< 50`) and breaks
            // detection. With it excluded, a 10-letter + 10-space EBCDIC sample
            // yields asciiPrintable=0 (EBCDIC letter bytes are all > 0x7e), so the
            // ASCII-printable share is 0% < 50% and looksEBCDIC returns true.
            asciiPrintable++
        }
    }
    // EBCDIC space must be the most common byte class, EBCDIC-printable share
    // high, and ASCII-printable share low.
    return spaces*100/n >= 8 &&
        ebcPrintable*100/n >= 80 &&
        asciiPrintable*100/n < 50
}

func isEBCDICPrintable(b byte) bool {
    switch {
    case b == 0x40: // space
        return true
    case b >= 0x4A && b <= 0x50, b >= 0x5A && b <= 0x61, b >= 0x6A && b <= 0x6F,
        b >= 0x7A && b <= 0x7F: // punctuation clusters
        return true
    case b >= 0x81 && b <= 0x89, b >= 0x91 && b <= 0x99, b >= 0xA2 && b <= 0xA9: // a-z
        return true
    case b >= 0xC1 && b <= 0xC9, b >= 0xD1 && b <= 0xD9, b >= 0xE2 && b <= 0xE9: // A-Z
        return true
    case b >= 0xF0 && b <= 0xF9: // 0-9
        return true
    }
    return false
}
```

**Why `b != 0x40` matters:** 0x40 is both the EBCDIC space and ASCII '@', so it
falls inside `0x20..0x7e`. The Task 2 sample is 10 EBCDIC letters + 10 EBCDIC
spaces (n=20). The letter bytes (0xC8, 0xC5, 0xD3, 0xD6, 0xE6, 0xD9, 0xC4) are all
> 0x7e, so they are never ASCII-printable. If 0x40 were counted, the 10 spaces
would give asciiPrintable=10 → `10*100/20 == 50`, which fails the `< 50` test and
returns false. Excluding 0x40 gives asciiPrintable=0 → `0 < 50` true, so the
sample is detected (true). The same exclusion makes the Task 6 auto-detect sample
(`{0xC8,0xC5,0xD3,0xD3,0xD6, 0x40,0x40,0x40,0x40,0x40}`, 5 letters + 5 spaces)
yield asciiPrintable=0 and resolve EBCDIC on. The `spaces >= 8%` and
`ebcPrintable >= 80%` thresholds are unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestLooksEBCDIC -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ebcdic.go ebcdic_test.go
git commit -m "feat(ebcdic): conservative EBCDIC detection heuristic"
```

---

## Task 3: Carriage-control conversion (`carriage.go`)

**Files:**
- Create: `carriage.go`
- Test: `carriage_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestASACarriageControl(t *testing.T) {
    // Each line's first char is the ASA control: ' ' single, '0' double, '1' formfeed.
    in := " LINE1\n0LINE2\n1LINE3\n"
    got := applyCarriageControl(in, "asa")
    want := "LINE1\n\nLINE2\n\fLINE3\n"
    if got != want {
        t.Fatalf("asa got %q want %q", got, want)
    }
}

func TestNoneIsPassthrough(t *testing.T) {
    in := " LINE1\n0LINE2\n"
    if got := applyCarriageControl(in, "none"); got != in {
        t.Fatalf("none should pass through, got %q", got)
    }
}

func TestAutoDetectsASA(t *testing.T) {
    in := " A\n0B\n"
    if applyCarriageControl(in, "auto") != applyCarriageControl(in, "asa") {
        t.Fatal("auto should detect ASA here")
    }
    // Non-ASA leading chars => treated as none.
    plain := "hello\nworld\n"
    if applyCarriageControl(plain, "auto") != plain {
        t.Fatal("auto should pass non-ASA text through")
    }
}

func TestMachineCarriageControlRaw(t *testing.T) {
    // Machine carriage-control runs on RAW EBCDIC bytes (before decode), splitting
    // on EBCDIC NEL (0x15) records. The first byte of each record is the machine
    // control code; it is stripped. 0x8B/0x89 (skip-to-channel) insert a form feed.
    // Record bytes shown are EBCDIC letters A/B (0xC1/0xC2); the FF is the ASCII
    // \f the function inserts, independent of code page.
    raw := []byte{0x09, 0xC1, 0x15, 0x8B, 0xC2, 0x15} // 0x09=print+space, 0x8B=skip-to-ch
    got := convertMachineRaw(raw)
    want := []byte{0xC1, 0x15, '\f', 0xC2, 0x15}
    if string(got) != string(want) {
        t.Fatalf("machine raw got %v want %v", got, want)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestASA|TestNone|TestAuto|TestMachine' -v`
Expected: FAIL — `undefined: applyCarriageControl` / `undefined: convertMachineRaw`

- [ ] **Step 3: Write the implementation**

```go
package main

import "strings"

// applyCarriageControl converts mainframe carriage-control to plain text. It
// handles ASA on already-decoded text. NOTE: "machine" carriage-control is NOT
// handled here — machine (FCFC) codes are raw EBCDIC control bytes that no longer
// exist after EBCDIC decode (they were mapped through the code page). Machine mode
// is handled by convertMachineRaw on the RAW bytes BEFORE decode (see sink
// integration, Task 6 Step 3b). Here:
//   asa:     first char of each record is the ASA control (' '=single, '0'=double,
//            '-'=triple, '1'=form feed, '+'=overprint); it is stripped.
//   none:    returned unchanged.   auto: detect asa, else none.
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

// convertMachineRaw applies machine (FCFC) carriage-control to the RAW EBCDIC
// byte stream, BEFORE EBCDIC decode. Machine control bytes are raw EBCDIC values
// (e.g. 0x8B/0x89 skip-to-channel) that would be destroyed by decoding through a
// code-page table, so this MUST run on the raw bytes. It splits the stream on
// EBCDIC line delimiters (NEL 0x15 and/or LF 0x25), strips the first (control)
// byte of each record, and inserts an ASCII form-feed (\f, 0x0C) where the control
// byte is a skip-to-channel code (0x8B/0x89). The delimiter byte is preserved so
// the subsequent decodeEBCDIC pass maps it to a newline. Returns the cleaned raw
// bytes for decode. Minimal but sufficient for capture readability.
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
            ctrl, body = rec[0], rec[1:] // strip the control byte
        }
        if ctrl == 0x8B || ctrl == 0x89 { // skip-to-channel => form feed
            out = append(out, '\f')
        }
        out = append(out, body...)
        if haveDelim {
            out = append(out, delim) // preserve EBCDIC delimiter for decode
        }
        rec = rec[:0]
    }
    for _, b := range raw {
        if b == 0x15 || b == 0x25 { // EBCDIC NEL or LF: end of record
            flush(b, true)
            continue
        }
        rec = append(rec, b)
    }
    flush(0, false) // trailing record without a delimiter
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestASA|TestNone|TestAuto|TestMachine' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add carriage.go carriage_test.go
git commit -m "feat(ebcdic): ASA/machine carriage-control conversion"
```

---

## Task 4: Config + job fields (`config.go`, `main.go`)

**Files:**
- Modify: `config.go` (add `EBCDICConf`, `QueueDefault`, `LPDOpts.QueueDefaults`, defaults, `Config` field)
- Modify: `main.go` (`job` fields)
- Test: `config_ebcdic_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestEBCDICDefaults(t *testing.T) {
    c := defaultConfig()
    if !c.EBCDIC.Enabled || c.EBCDIC.DefaultCodePage != "CP037" {
        t.Fatalf("unexpected EBCDIC defaults: %+v", c.EBCDIC)
    }
    if c.LPD.QueueDefaults == nil {
        t.Fatal("QueueDefaults map should be initialized")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestEBCDICDefaults -v`
Expected: FAIL — `c.EBCDIC undefined`

- [ ] **Step 3: Implement**

In `config.go`: add `EBCDICConf` and `QueueDefault` (from "Shared types"); add to
`LPDOpts`:

```go
    QueueDefaults map[string]QueueDefault `json:"queue_defaults"`
```

Add to `Config`:

```go
    EBCDIC    EBCDICConf `json:"ebcdic"`
```

In `defaultConfig()`, set the LPD field `QueueDefaults: map[string]QueueDefault{}`
and add:

```go
        EBCDIC: EBCDICConf{
            Enabled:         true,
            DefaultCodePage: "CP037",
            AutoDetect:      true,
            DecodedSidecar:  true,
            CarriageControl: "auto",
        },
```

In `main.go`, add to the `job` struct:

```go
    Class    string `json:"class,omitempty"`
    Title    string `json:"title,omitempty"`
    CodePage string `json:"code_page,omitempty"`
    DecodedAs string `json:"decoded_as,omitempty"`
```

- [ ] **Step 4: Run tests + build**

Run: `go test ./... -run TestEBCDICDefaults -v && go build ./...`
Expected: PASS; build clean.

- [ ] **Step 5: Commit**

```bash
git add config.go main.go config_ebcdic_test.go
git commit -m "feat(ebcdic): config (EBCDICConf, queue defaults) and job fields"
```

---

## Task 5: Richer LPD control-file parsing + queue defaults (`lpd.go`)

**Files:**
- Modify: `lpd.go`
- Test: `lpd_control_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestParseControlFileRicherFields(t *testing.T) {
    ctrl := []byte("Hmainframe\nProot\nJPayroll\nCblue\nTReport Title\nNdfA001host\nrdfA001host\n")
    j := &job{}
    parseControlFile(ctrl, j)
    if j.Host != "mainframe" || j.User != "root" || j.JobName != "Payroll" {
        t.Fatalf("base fields: %+v", j)
    }
    if j.Class != "blue" || j.Title != "Report Title" {
        t.Fatalf("rich fields: class=%q title=%q", j.Class, j.Title)
    }
}

func TestControlFormatLetterHintsASA(t *testing.T) {
    // 'r' (FORTRAN carriage) should hint ASA carriage control.
    if controlCarriageHint([]byte("Hh\nrdfA001\n")) != "asa" {
        t.Fatal("expected 'r' to hint asa")
    }
    if controlCarriageHint([]byte("Hh\nfdfA001\n")) != "" {
        t.Fatal("expected no hint for 'f'")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestParseControlFileRicher|TestControlFormat' -v`
Expected: FAIL — `j.Class undefined` / `undefined: controlCarriageHint`

- [ ] **Step 3: Implement**

Extend `parseControlFile` in `lpd.go`:

```go
func parseControlFile(ctrl []byte, j *job) {
    for _, line := range strings.Split(string(ctrl), "\n") {
        if line == "" {
            continue
        }
        key, val := line[0], strings.TrimRight(line[1:], "\r")
        switch key {
        case 'H':
            j.Host = val
        case 'P':
            j.User = val
        case 'J':
            j.JobName = val
        case 'C':
            j.Class = val
        case 'T':
            j.Title = val
        }
    }
}

// controlCarriageHint returns "asa" when the control file uses the FORTRAN
// carriage-control print letter ('r'), else "".
func controlCarriageHint(ctrl []byte) string {
    for _, line := range strings.Split(string(ctrl), "\n") {
        if len(line) > 0 && line[0] == 'r' {
            return "asa"
        }
    }
    return ""
}
```

Attach the carriage hint where the control file is parsed in `handleLPD` (store on
the job for `sink.save` to consult — add an unexported `carriageHint string` field
to `job` in `main.go` and set `j.carriageHint = controlCarriageHint(ctrl)` right
after `parseControlFile(ctrl, j)`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestParseControlFileRicher|TestControlFormat' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lpd.go main.go lpd_control_test.go
git commit -m "feat(ebcdic): richer LPD control-file fields + carriage hint"
```

---

## Task 6: Central decode + sidecar in `sink.save` (`sink.go`)

**Files:**
- Modify: `sink.go`
- Create: `ebcdic_resolve.go` (settings resolution, isolated + testable)
- Test: `sink_ebcdic_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestResolveEBCDICByQueue(t *testing.T) {
    cfg = defaultConfig()
    cfg.LPD.QueueDefaults = map[string]QueueDefault{
        "mvs*": {CodePage: "CP037", CarriageControl: "asa", EBCDIC: true},
    }
    j := &job{Queue: "mvs1"}
    page, cc, on := resolveEBCDIC(j, []byte{0x40})
    if !on || page != "CP037" || cc != "asa" {
        t.Fatalf("queue resolve: on=%v page=%q cc=%q", on, page, cc)
    }
}

func TestResolveEBCDICAutoDetect(t *testing.T) {
    cfg = defaultConfig() // EBCDIC.AutoDetect true, default CP037
    ebc := []byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6, 0x40, 0x40, 0x40, 0x40, 0x40}
    page, _, on := resolveEBCDIC(&job{Queue: "unmapped"}, ebc)
    if !on || page != "CP037" {
        t.Fatalf("auto resolve: on=%v page=%q", on, page)
    }
    // ASCII must not trigger.
    if _, _, on := resolveEBCDIC(&job{}, []byte("plain ascii text here ok")); on {
        t.Fatal("ASCII should not resolve to EBCDIC")
    }
}

func TestSinkWritesDecodedSidecar(t *testing.T) {
    cfg = defaultConfig()
    cfg.OutDir = t.TempDir()
    cfg.LPD.QueueDefaults = map[string]QueueDefault{"mvs*": {CodePage: "CP037", CarriageControl: "none", EBCDIC: true}}
    sink = &captureSink{dir: cfg.OutDir}
    store = newJobStore(10)

    j := &job{Protocol: "LPR", Queue: "mvs1"}
    j.data = []byte{0xC8, 0xC5, 0xD3, 0xD3, 0xD6} // HELLO
    j.Bytes = len(j.data)
    _ = sink.save(j)

    if j.CodePage != "CP037" || j.DecodedAs == "" {
        t.Fatalf("metadata: codepage=%q decodedAs=%q", j.CodePage, j.DecodedAs)
    }
    b, err := os.ReadFile(filepath.Join(cfg.OutDir, j.DecodedAs))
    if err != nil {
        t.Fatal(err)
    }
    if !strings.Contains(string(b), "HELLO") {
        t.Fatalf("decoded sidecar content %q", b)
    }
}
```

(`sink.save` returns `error` here if the forward-proxy plan landed first;
otherwise it returns nothing — adjust the call to `_ = sink.save(j)` or
`sink.save(j)` accordingly. Both plans modify `sink.save`; whichever lands second
keeps the EBCDIC block.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestResolveEBCDIC|TestSinkWritesDecoded' -v`
Expected: FAIL — `undefined: resolveEBCDIC`

- [ ] **Step 3a: Implement resolution (`ebcdic_resolve.go`)**

```go
package main

import "path/filepath"

// resolveEBCDIC determines whether to decode this job and with which code page /
// carriage-control mode. Order: queue defaults (glob) -> auto-detect + global
// default -> off.
func resolveEBCDIC(j *job, raw []byte) (page, carriage string, on bool) {
    if !cfg.EBCDIC.Enabled {
        return "", "", false
    }
    for pattern, qd := range cfg.LPD.QueueDefaults {
        if ok, _ := filepath.Match(pattern, j.Queue); ok {
            if qd.EBCDIC || qd.CodePage != "" {
                page = orElse(qd.CodePage, cfg.EBCDIC.DefaultCodePage)
                carriage = orElse(qd.CarriageControl, cfg.EBCDIC.CarriageControl)
                return page, resolveCarriage(carriage, j), true
            }
        }
    }
    if cfg.EBCDIC.AutoDetect && looksEBCDIC(raw) {
        return cfg.EBCDIC.DefaultCodePage, resolveCarriage(cfg.EBCDIC.CarriageControl, j), true
    }
    return "", "", false
}

// resolveCarriage lets the LPD control-file hint upgrade "auto"/"" to "asa".
func resolveCarriage(mode string, j *job) string {
    if (mode == "" || mode == "auto") && j.carriageHint != "" {
        return j.carriageHint
    }
    if mode == "" {
        return "auto"
    }
    return mode
}
```

- [ ] **Step 3b: Wire into `sink.save` (`sink.go`)**

After the raw spool file is written (and after `extForFormat`), before `store.add`,
insert:

```go
    if page, carriage, on := resolveEBCDIC(j, j.data); on {
        // Ordering matters. Machine (FCFC) carriage-control is raw EBCDIC control
        // bytes that decodeEBCDIC would map away through the code-page table, so it
        // MUST be applied to the raw bytes BEFORE decode. ASA/none/auto operate on
        // the decoded text and are applied AFTER decode.
        raw := j.data
        if carriage == "machine" {
            raw = convertMachineRaw(raw)
        }
        if decoded := decodeEBCDIC(raw, page); decoded != "" {
            if carriage != "machine" {
                decoded = applyCarriageControl(decoded, carriage)
            }
            j.CodePage = page
            if cfg.EBCDIC.DecodedSidecar && cfg.mode() != saveMeta {
                name := base + "-decoded.txt"
                if err := os.WriteFile(filepath.Join(s.dir, name), []byte(decoded), 0o600); err != nil {
                    logErr(j.Protocol, "failed to write decoded sidecar: %v", err)
                } else {
                    j.DecodedAs = name
                    logInfo(j.Protocol, "decoded %d bytes as %s (%s) -> %s", j.Bytes, page, carriage, name)
                }
            }
        } else {
            logWarn(j.Protocol, "EBCDIC decode skipped: unknown code page %q", page)
        }
    }
```

Note: `resolveEBCDIC`/`resolveCarriage` are unchanged — they still return the mode
string (`asa`/`machine`/`none`/`auto`); the ordering decision lives in `sink.save`.
For machine mode, carriage-control is consumed on the raw bytes before decode and
must NOT also be re-applied to the decoded text (`applyCarriageControl` treats
"machine" as a passthrough anyway, but the explicit guard documents intent).

- [ ] **Step 4: Run the full suite + build + vet**

Run: `go test ./... && go build ./... && go vet ./...`
Expected: PASS; clean.

- [ ] **Step 5: Confirm no new dependency**

Run: `git diff -- go.mod go.sum`
Expected: empty.

- [ ] **Step 6: Commit**

```bash
git add sink.go ebcdic_resolve.go sink_ebcdic_test.go
git commit -m "feat(ebcdic): central decode + decoded.txt sidecar in sink.save"
```

---

## Task 7: Documentation (`README.md`, `ADMIN_GUIDE.md`)

**Files:**
- Modify: `README.md`, `ADMIN_GUIDE.md`

- [ ] **Step 1: README — add a "Mainframe & EBCDIC" subsection** under capture/output:

```markdown
## Mainframe & EBCDIC (z/OS, IBM i / AS-400)

Mainframe and midrange hosts print over LPR/LPD and often send **EBCDIC** data
with ASA or machine carriage-control. printcap can transcode these to readable
UTF-8 while keeping the raw bytes: it writes a `<base>-decoded.txt` alongside the
raw spool.

Configure under `ebcdic` (`enabled`, `default_code_page`, `auto_detect`,
`decoded_sidecar`, `carriage_control`) and map specific LPD queues under
`lpd.queue_defaults` (e.g. `"mvs*": {"code_page":"CP037","carriage_control":"asa","ebcdic":true}`).
Built-in code pages: CP037, CP500, CP1047, CP273, CP285, CP297. The richer LPD
control file also captures Class (`C`) and Title (`T`).
```

- [ ] **Step 2: ADMIN_GUIDE — add the `ebcdic` config block + `lpd.queue_defaults`
   to §8, field notes, the code-page list, and an acceptance step in §19:**

```markdown
10. **EBCDIC capture** — map a test queue to CP037 in `lpd.queue_defaults`, send an
    EBCDIC job via LPR; confirm `<base>-decoded.txt` is readable and the job `.json`
    shows `code_page` and `decoded_as`.
```

- [ ] **Step 3: Commit**

```bash
git add README.md ADMIN_GUIDE.md
git commit -m "docs(ebcdic): document mainframe EBCDIC capture and queue defaults"
```

---

## Task 8: Manual acceptance

**Files:** none.

- [ ] **Step 1:** Map `lpd.queue_defaults` `"mvs*" -> CP037/asa`, send an EBCDIC
  spool via `lpr -S host -P mvs1` (or a crafted socket); confirm raw + readable
  `-decoded.txt`, correct ASA line breaks, and `code_page`/`decoded_as` metadata.
- [ ] **Step 2:** Send an ASCII job to a non-mapped queue; confirm it is captured
  byte-identical to before (no sidecar).
- [ ] **Step 3:** Send an EBCDIC job to an unmapped queue with `auto_detect:true`;
  confirm it is detected and decoded with the default page.
- [ ] **Step 4:** Verify `C`/`T` control-file fields surface in the dashboard/JSON.

---

## Self-Review notes (completed by plan author)

- **Spec coverage:** §3 architecture → Tasks 1–6; §4 config/resolution → Tasks 4,6;
  §5 decode → Tasks 1–2; §6 carriage → Task 3; §7 LPD fields → Task 5; §8 output →
  Task 6; §9 logging → Task 6; §10 testing → Tasks 1–6; §11 acceptance → Task 8. No gaps.
- **Type consistency:** `decodeEBCDIC`, `looksEBCDIC`, `applyCarriageControl`,
  `convertMachineRaw`, `resolveEBCDIC`, `resolveCarriage`, `controlCarriageHint`,
  `EBCDICConf`, `QueueDefault`, `LPDOpts.QueueDefaults`, and job fields
  `Class`/`Title`/`CodePage`/`DecodedAs`/`carriageHint` are used identically across
  tasks. Note `applyCarriageControl` handles only asa/none/auto on decoded text;
  machine mode uses `convertMachineRaw([]byte) []byte` on raw bytes.
- **looksEBCDIC fix (Task 2):** the ASCII-printable tally excludes 0x40
  (`b != 0x40`). 0x40 is both the EBCDIC space and ASCII '@', so counting it put
  the letter+space test samples exactly on the `asciiPrintable*100/n < 50` boundary
  (==50, fails `<`) and returned false against tests that assert true. With it
  excluded, the Task 2 sample (10 letters + 10 spaces) and the Task 6 auto-detect
  sample both yield asciiPrintable=0 → detected true. The `spaces >= 8%` /
  `ebcPrintable >= 80%` thresholds are unchanged.
- **Machine carriage-control reordering (Tasks 3 & 6):** machine (FCFC) control
  bytes are raw EBCDIC values destroyed by decode, so machine mode is applied to
  the RAW bytes via `convertMachineRaw` BEFORE `decodeEBCDIC` (splitting on EBCDIC
  delimiters 0x15/0x25, stripping the per-record control byte, inserting `\f` for
  0x8B/0x89). ASA/none stay after decode. `sink.save` branches on
  `carriage == "machine"` to pick the order; `resolveEBCDIC`/`resolveCarriage` are
  unchanged.
- **Placeholder note:** the only "fill-in" is bulk *data* — the six `[256]rune`
  tables — sourced from the named Unicode mapping files and locked by anchor tests.
  This is data transcription, not logic left unspecified.
- **Cross-plan note:** both this plan and the forward-proxy plan modify `sink.save`.
  Whichever lands second keeps its inserted block; if forward landed first,
  `sink.save` already returns `error` and the EBCDIC block sits before `store.add`.
- **Dependency guard:** Task 6 Step 5 asserts `go.mod`/`go.sum` unchanged.
```
