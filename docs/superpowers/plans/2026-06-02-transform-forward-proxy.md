# Transform & Forward Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional tee/transform/forward proxy so every captured job is also passed through an ordered transform pipeline (find/replace + PCL/command injection) and forwarded to one or more real downstream printers over raw/9100, LPR, or IPP/IPPS — while still capturing the original.

**Architecture:** A `forwarder` built at engine start hooks into `sink.save` (the single capture chokepoint). It evaluates per-target routing conditions, runs each matching target's transform pipeline over a copy of the original bytes, captures the transformed output, and delivers via a pluggable `transport` (raw/LPR/IPP). Failure handling is per target (best-effort/spool-retry/block); `block` propagates an error back through `sink.save` to the inbound handler.

**Tech Stack:** Go 1.26, standard library only (`net`, `net/http`, `crypto/tls`, `regexp`, `encoding/hex`, `bytes`, `testing`). Reuses the IPP attribute encoders already in `ipp.go`.

---

## Shared types & helpers (defined across the tasks; listed here for consistency)

```go
// config.go
type ForwardConf struct {
    Enabled bool              `json:"enabled"`
    Capture string            `json:"capture"` // both | sent | orig
    Macros  map[string]string `json:"macros"`
    Targets []ForwardTarget   `json:"targets"`
}

type ForwardTarget struct {
    Name                 string           `json:"name"`
    Transport            string           `json:"transport"` // raw | lpr | ipp | ipps
    Address              string           `json:"address"`
    TimeoutMS            int              `json:"timeout_ms"`
    Queue                string           `json:"queue"`                    // lpr
    PrivilegedSourcePort bool             `json:"privileged_source_port"`   // lpr
    TLSSkipVerify        bool             `json:"tls_skip_verify"`          // ipps
    DocumentFormat       string           `json:"document_format"`          // ipp
    When                 ForwardCond      `json:"when"`
    Failure              string           `json:"failure"` // best_effort | spool_retry | block
    Retry                ForwardRetry     `json:"retry"`
    Transforms           []TransformStep  `json:"transforms"`
}

type ForwardRetry struct {
    MaxAttempts int `json:"max_attempts"`
    BackoffMS   int `json:"backoff_ms"`
    TTLMin      int `json:"ttl_min"`
}

type ForwardCond struct {
    Protocols   []string `json:"protocols"`
    SourceCIDRs []string `json:"source_cidrs"`
    Users       []string `json:"users"`
    Hosts       []string `json:"hosts"`
    JobName     string   `json:"job_name"`
    Queues      []string `json:"queues"`
    DocFormats  []string `json:"doc_formats"`
    PDLs        []string `json:"pdls"`
    Contains    string   `json:"contains"`
    MinBytes    int      `json:"min_bytes"`
    MaxBytes    int      `json:"max_bytes"`
}

type TransformStep struct {
    Type  string      `json:"type"`  // replace | inject_prefix | inject_suffix
    Mode  string      `json:"mode"`  // replace: literal | regex | hex
    Match string      `json:"match"`
    With  string      `json:"with"`
    All   bool        `json:"all"`
    Data  string      `json:"data"`  // inject_*: \xNN-escaped, supports macro:NAME
    When  ForwardCond `json:"when"`
}
```

```go
// forward.go — runtime model derived from config (compiled regexes/CIDRs, resolved macros)
type forwardResult struct {
    Target    string `json:"target"`
    Transport string `json:"transport"`
    Address   string `json:"address"`
    Status    string `json:"status"` // ok | failed | queued
    Bytes     int    `json:"bytes"`
    Error     string `json:"error,omitempty"`
}

type transport interface {
    send(t *target, data []byte, j *job) error
}

// target is the compiled form of ForwardTarget.
type target struct {
    name       string
    transport  string
    address    string
    timeout    time.Duration
    queue      string
    privPort   bool
    tlsSkip    bool
    docFormat  string
    when       *compiledCond
    failure    string
    retry      ForwardRetry
    steps      []compiledStep
    send       transport
}
```

The `job` struct (in `main.go`) gains: `Forwards []forwardResult \`json:"forwards,omitempty"\``.

---

## Task 1: Byte-literal decoding (`transform.go`)

Decodes `\xNN` escapes and `macro:NAME` references used by inject data, macros, and replacements.

**Files:**
- Create: `transform.go`
- Test: `transform_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestDecodeBytesHexEscapes(t *testing.T) {
    got := decodeBytes(`\x1bE hello\x0a`, nil)
    want := append([]byte{0x1b, 'E', ' ', 'h', 'e', 'l', 'l', 'o', 0x0a})
    if string(got) != string(want) {
        t.Fatalf("got %v want %v", got, want)
    }
}

func TestDecodeBytesMacroExpansion(t *testing.T) {
    macros := map[string][]byte{"reset": {0x1b, 'E'}}
    got := decodeBytes("macro:reset", macros)
    if string(got) != "\x1bE" {
        t.Fatalf("got %v", got)
    }
}

func TestDecodeBytesUnknownMacroIsEmpty(t *testing.T) {
    if got := decodeBytes("macro:nope", map[string][]byte{}); len(got) != 0 {
        t.Fatalf("got %v", got)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestDecodeBytes -v`
Expected: FAIL — `undefined: decodeBytes`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import "strings"

// decodeBytes resolves a configured byte string. A leading "macro:NAME" expands
// to that macro's already-decoded bytes (empty if unknown). Otherwise it decodes
// \xNN hex escapes; all other characters are literal.
func decodeBytes(s string, macros map[string][]byte) []byte {
    if strings.HasPrefix(s, "macro:") {
        return append([]byte{}, macros[strings.TrimPrefix(s, "macro:")]...)
    }
    var out []byte
    for i := 0; i < len(s); {
        if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
            if b, ok := hexByte(s[i+2], s[i+3]); ok {
                out = append(out, b)
                i += 4
                continue
            }
        }
        out = append(out, s[i])
        i++
    }
    return out
}

func hexByte(hi, lo byte) (byte, bool) {
    h, ok1 := hexNibble(hi)
    l, ok2 := hexNibble(lo)
    if !ok1 || !ok2 {
        return 0, false
    }
    return h<<4 | l, true
}

func hexNibble(c byte) (byte, bool) {
    switch {
    case c >= '0' && c <= '9':
        return c - '0', true
    case c >= 'a' && c <= 'f':
        return c - 'a' + 10, true
    case c >= 'A' && c <= 'F':
        return c - 'A' + 10, true
    }
    return 0, false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestDecodeBytes -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add transform.go transform_test.go
git commit -m "feat(forward): byte-literal decoding with hex escapes and macros"
```

---

## Task 2: Compiled transform steps & the pipeline (`transform.go`)

**Files:**
- Modify: `transform.go`
- Test: `transform_test.go`

This task defines `compiledStep` and `applyTransforms`. The step's optional
condition is represented by `*compiledCond` (built in Task 3); to keep this task
independent, `compiledStep.when` is typed as `condMatcher`, an interface Task 3's
`*compiledCond` satisfies. Tests here pass `nil` (always-apply).

- [ ] **Step 1: Write the failing test**

```go
func TestApplyInjectPrefixSuffix(t *testing.T) {
    steps := []compiledStep{
        {kind: "inject_prefix", data: []byte("<<")},
        {kind: "inject_suffix", data: []byte(">>")},
    }
    got := applyTransforms(steps, []byte("BODY"), &job{})
    if string(got) != "<<BODY>>" {
        t.Fatalf("got %q", got)
    }
}

func TestApplyReplaceLiteralAllVsFirst(t *testing.T) {
    all := []compiledStep{{kind: "replace", mode: "literal", match: []byte("a"), with: []byte("X"), all: true}}
    if got := applyTransforms(all, []byte("banana"), &job{}); string(got) != "bXnXnX" {
        t.Fatalf("all got %q", got)
    }
    first := []compiledStep{{kind: "replace", mode: "literal", match: []byte("a"), with: []byte("X"), all: false}}
    if got := applyTransforms(first, []byte("banana"), &job{}); string(got) != "bXnana" {
        t.Fatalf("first got %q", got)
    }
}

func TestApplyReplaceRegexWithBackref(t *testing.T) {
    steps := []compiledStep{{kind: "replace", mode: "regex",
        re: mustCompileRE(t, `Draft (\d+)`), with: []byte("FINAL-$1")}}
    got := applyTransforms(steps, []byte("Draft 7 copy"), &job{})
    if string(got) != "FINAL-7 copy" {
        t.Fatalf("got %q", got)
    }
}

func TestApplyReplaceHex(t *testing.T) {
    steps := []compiledStep{{kind: "replace", mode: "hex",
        match: []byte{0x1b, 0x45}, with: []byte{0x1b, 0x46}, all: true}}
    got := applyTransforms(steps, []byte{0x1b, 0x45, 0x01}, &job{})
    if string(got) != string([]byte{0x1b, 0x46, 0x01}) {
        t.Fatalf("got %v", got)
    }
}

func mustCompileRE(t *testing.T, p string) *regexp.Regexp {
    re, err := regexp.Compile(p)
    if err != nil {
        t.Fatal(err)
    }
    return re
}
```

Add imports `regexp` to the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestApply -v`
Expected: FAIL — `undefined: compiledStep`

- [ ] **Step 3: Write minimal implementation**

```go
import (
    "bytes"
    "regexp"
)

// condMatcher is satisfied by *compiledCond (Task 3). A nil matcher always
// applies.
type condMatcher interface {
    matches(j *job, data []byte) bool
}

type compiledStep struct {
    kind  string         // inject_prefix | inject_suffix | replace
    mode  string         // replace: literal | regex | hex
    match []byte         // literal/hex match bytes
    re    *regexp.Regexp // regex mode
    with  []byte         // replacement (literal/hex) — regex uses withStr
    withS string         // regex replacement template (supports $1)
    all   bool
    data  []byte         // inject_* bytes (already decoded)
    when  condMatcher    // nil = always
}

// applyTransforms runs steps in order over a copy of data.
func applyTransforms(steps []compiledStep, data []byte, j *job) []byte {
    out := append([]byte{}, data...)
    for _, s := range steps {
        if s.when != nil && !s.when.matches(j, out) {
            logDebug("fwd", "skip transform %s (condition not met)", s.kind)
            continue
        }
        before := len(out)
        switch s.kind {
        case "inject_prefix":
            out = append(append([]byte{}, s.data...), out...)
        case "inject_suffix":
            out = append(out, s.data...)
        case "replace":
            out = applyReplace(s, out)
        }
        logDebug("fwd", "transform %s: %d -> %d bytes", s.kind, before, len(out))
    }
    return out
}

func applyReplace(s compiledStep, data []byte) []byte {
    switch s.mode {
    case "regex":
        if s.re == nil {
            return data
        }
        return s.re.ReplaceAll(data, []byte(s.withS))
    default: // literal or hex — both already-decoded byte slices
        if len(s.match) == 0 {
            return data
        }
        if s.all {
            return bytes.ReplaceAll(data, s.match, s.with)
        }
        return bytes.Replace(data, s.match, s.with, 1)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestApply -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add transform.go transform_test.go
git commit -m "feat(forward): ordered transform pipeline (replace + inject)"
```

---

## Task 3: Condition matching (`match.go`)

**Files:**
- Create: `match.go`
- Test: `match_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func mkCond(t *testing.T, c ForwardCond) *compiledCond {
    cc, err := compileCond(c)
    if err != nil {
        t.Fatal(err)
    }
    return cc
}

func TestCondEmptyMatchesAlways(t *testing.T) {
    if !mkCond(t, ForwardCond{}).matches(&job{}, nil) {
        t.Fatal("empty condition should always match")
    }
}

func TestCondProtocolAndSource(t *testing.T) {
    c := mkCond(t, ForwardCond{Protocols: []string{"IPP"}, SourceCIDRs: []string{"10.0.0.0/24"}})
    j := &job{Protocol: "IPP", Source: "10.0.0.5:5000"}
    if !c.matches(j, nil) {
        t.Fatal("should match IPP from 10.0.0.5")
    }
    j2 := &job{Protocol: "IPP", Source: "192.168.1.5:5000"}
    if c.matches(j2, nil) {
        t.Fatal("should not match wrong subnet")
    }
}

func TestCondJobNameGlobAndRegex(t *testing.T) {
    g := mkCond(t, ForwardCond{JobName: "*invoice*"})
    if !g.matches(&job{JobName: "april-invoice.pdf"}, nil) {
        t.Fatal("glob should match")
    }
    r := mkCond(t, ForwardCond{JobName: `/^INV\d+/`})
    if !r.matches(&job{JobName: "INV42"}, nil) {
        t.Fatal("regex should match")
    }
}

func TestCondContainsModes(t *testing.T) {
    lit := mkCond(t, ForwardCond{Contains: "@PJL"})
    if !lit.matches(&job{}, []byte("\x1b%-12345X@PJL SET")) {
        t.Fatal("literal contains should match")
    }
    hx := mkCond(t, ForwardCond{Contains: "hex:1b45"})
    if !hx.matches(&job{}, []byte{0x00, 0x1b, 0x45}) {
        t.Fatal("hex contains should match")
    }
    re := mkCond(t, ForwardCond{Contains: `/PJL\s+SET/`})
    if !re.matches(&job{}, []byte("@PJL  SET")) {
        t.Fatal("regex contains should match")
    }
}

func TestCondSizeBounds(t *testing.T) {
    c := mkCond(t, ForwardCond{MinBytes: 2, MaxBytes: 4})
    if c.matches(&job{}, []byte("x")) {
        t.Fatal("under min should not match")
    }
    if !c.matches(&job{}, []byte("xxx")) {
        t.Fatal("in range should match")
    }
    if c.matches(&job{}, []byte("xxxxx")) {
        t.Fatal("over max should not match")
    }
}

func TestCondPDLAndDocFormat(t *testing.T) {
    c := mkCond(t, ForwardCond{PDLs: []string{"PCL"}, DocFormats: []string{"application/pdf"}})
    if !c.matches(&job{PDL: "PCL", DocFormat: "application/pdf"}, nil) {
        t.Fatal("should match PDL+docformat")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestCond -v`
Expected: FAIL — `undefined: compileCond`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
    "encoding/hex"
    "fmt"
    "net"
    "path/filepath"
    "regexp"
    "strings"
)

type compiledCond struct {
    protocols  []string
    cidrs      []*net.IPNet
    users      []string
    hosts      []string
    jobName    *textMatcher
    queues     []string
    docFormats []string
    pdls       []string
    contains   *bytesMatcher
    minBytes   int
    maxBytes   int
    empty      bool
}

// textMatcher matches a string by glob (default) or /regex/.
type textMatcher struct {
    glob string
    re   *regexp.Regexp
}

func (m *textMatcher) match(s string) bool {
    if m.re != nil {
        return m.re.MatchString(s)
    }
    ok, _ := filepath.Match(m.glob, s)
    return ok
}

// bytesMatcher matches bytes by literal substring, /regex/, or hex:....
type bytesMatcher struct {
    lit []byte
    re  *regexp.Regexp
}

func (m *bytesMatcher) match(b []byte) bool {
    if m.re != nil {
        return m.re.Match(b)
    }
    return bytesContains(b, m.lit)
}

func bytesContains(haystack, needle []byte) bool {
    if len(needle) == 0 {
        return true
    }
    return strings.Contains(string(haystack), string(needle))
}

func compileTextMatcher(s string) (*textMatcher, error) {
    if s == "" {
        return nil, nil
    }
    if strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/") && len(s) >= 2 {
        re, err := regexp.Compile(s[1 : len(s)-1])
        if err != nil {
            return nil, err
        }
        return &textMatcher{re: re}, nil
    }
    return &textMatcher{glob: s}, nil
}

func compileBytesMatcher(s string) (*bytesMatcher, error) {
    if s == "" {
        return nil, nil
    }
    switch {
    case strings.HasPrefix(s, "hex:"):
        b, err := hex.DecodeString(strings.TrimPrefix(s, "hex:"))
        if err != nil {
            return nil, err
        }
        return &bytesMatcher{lit: b}, nil
    case strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/") && len(s) >= 2:
        re, err := regexp.Compile(s[1 : len(s)-1])
        if err != nil {
            return nil, err
        }
        return &bytesMatcher{re: re}, nil
    default:
        return &bytesMatcher{lit: []byte(s)}, nil
    }
}

func compileCond(c ForwardCond) (*compiledCond, error) {
    cc := &compiledCond{
        protocols: c.Protocols, users: c.Users, hosts: c.Hosts,
        queues: c.Queues, docFormats: c.DocFormats, pdls: c.PDLs,
        minBytes: c.MinBytes, maxBytes: c.MaxBytes,
    }
    for _, s := range c.SourceCIDRs {
        _, n, err := net.ParseCIDR(s)
        if err != nil {
            return nil, fmt.Errorf("bad source_cidr %q: %w", s, err)
        }
        cc.cidrs = append(cc.cidrs, n)
    }
    var err error
    if cc.jobName, err = compileTextMatcher(c.JobName); err != nil {
        return nil, fmt.Errorf("bad job_name: %w", err)
    }
    if cc.contains, err = compileBytesMatcher(c.Contains); err != nil {
        return nil, fmt.Errorf("bad contains: %w", err)
    }
    cc.empty = len(c.Protocols) == 0 && len(c.SourceCIDRs) == 0 && len(c.Users) == 0 &&
        len(c.Hosts) == 0 && c.JobName == "" && len(c.Queues) == 0 && len(c.DocFormats) == 0 &&
        len(c.PDLs) == 0 && c.Contains == "" && c.MinBytes == 0 && c.MaxBytes == 0
    return cc, nil
}

func (c *compiledCond) matches(j *job, data []byte) bool {
    if c == nil || c.empty {
        return true
    }
    if len(c.protocols) > 0 && !containsFold(c.protocols, j.Protocol) {
        return false
    }
    if len(c.cidrs) > 0 && !cidrMatch(c.cidrs, j.Source) {
        return false
    }
    if len(c.users) > 0 && !containsFold(c.users, j.User) {
        return false
    }
    if len(c.hosts) > 0 && !containsFold(c.hosts, j.Host) {
        return false
    }
    if c.jobName != nil && !c.jobName.match(j.JobName) {
        return false
    }
    if len(c.queues) > 0 && !containsFold(c.queues, j.Queue) {
        return false
    }
    if len(c.docFormats) > 0 && !containsFold(c.docFormats, j.DocFormat) {
        return false
    }
    if len(c.pdls) > 0 && !containsFold(c.pdls, j.PDL) {
        return false
    }
    if c.contains != nil && !c.contains.match(data) {
        return false
    }
    if c.minBytes > 0 && len(data) < c.minBytes {
        return false
    }
    if c.maxBytes > 0 && len(data) > c.maxBytes {
        return false
    }
    return true
}

func containsFold(xs []string, v string) bool {
    for _, x := range xs {
        if strings.EqualFold(x, v) {
            return true
        }
    }
    return false
}

func cidrMatch(nets []*net.IPNet, source string) bool {
    host := source
    if h, _, err := net.SplitHostPort(source); err == nil {
        host = h
    }
    ip := net.ParseIP(host)
    if ip == nil {
        return false
    }
    for _, n := range nets {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestCond -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add match.go match_test.go
git commit -m "feat(forward): condition matching for routing and step gating"
```

---

## Task 4: Raw/9100 transport (`fwd_raw.go`)

**Files:**
- Create: `fwd_raw.go`
- Test: `fwd_raw_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "net"
    "testing"
    "time"
)

func TestRawTransportDelivers(t *testing.T) {
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    got := make(chan []byte, 1)
    go func() {
        c, err := ln.Accept()
        if err != nil {
            return
        }
        defer c.Close()
        buf := make([]byte, 64)
        n, _ := c.Read(buf)
        got <- buf[:n]
    }()

    tr := rawTransport{}
    tg := &target{address: ln.Addr().String(), timeout: 2 * time.Second}
    if err := tr.send(tg, []byte("HELLO"), &job{}); err != nil {
        t.Fatalf("send: %v", err)
    }
    select {
    case b := <-got:
        if string(b) != "HELLO" {
            t.Fatalf("got %q", b)
        }
    case <-time.After(2 * time.Second):
        t.Fatal("timeout waiting for bytes")
    }
}

func TestRawTransportDeadAddressErrors(t *testing.T) {
    tr := rawTransport{}
    tg := &target{address: "127.0.0.1:1", timeout: 500 * time.Millisecond}
    if err := tr.send(tg, []byte("X"), &job{}); err == nil {
        t.Fatal("expected error dialing dead address")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestRawTransport -v`
Expected: FAIL — `undefined: rawTransport`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
    "net"
    "time"
)

type rawTransport struct{}

func (rawTransport) send(t *target, data []byte, j *job) error {
    to := t.timeout
    if to <= 0 {
        to = 30 * time.Second
    }
    conn, err := net.DialTimeout("tcp", t.address, to)
    if err != nil {
        return err
    }
    defer conn.Close()
    _ = conn.SetWriteDeadline(time.Now().Add(to))
    _, err = conn.Write(data)
    return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestRawTransport -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add fwd_raw.go fwd_raw_test.go
git commit -m "feat(forward): raw/9100 forward transport"
```

---

## Task 5: LPR/LPD client transport (`fwd_lpr.go`)

**Files:**
- Create: `fwd_lpr.go`
- Test: `fwd_lpr_test.go`

The integration test points the forwarder at **printcap's own LPD server** on a
random port and asserts the job is captured there.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "net"
    "testing"
    "time"
)

func TestLPRTransportToOwnServer(t *testing.T) {
    // Spin up printcap's LPD server on a random port.
    cfg = defaultConfig()
    cfg.OutDir = t.TempDir()
    sink = &captureSink{dir: cfg.OutDir}
    store = newJobStore(10)

    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    go serveLPD(ln)

    tr := lprTransport{}
    tg := &target{address: ln.Addr().String(), timeout: 2 * time.Second, queue: "lp"}
    j := &job{Host: "client1", User: "alice", JobName: "report"}
    if err := tr.send(tg, []byte("PCL-DATA"), j); err != nil {
        t.Fatalf("send: %v", err)
    }

    // Allow the server goroutine to persist the job.
    deadline := time.Now().Add(2 * time.Second)
    for time.Now().Before(deadline) {
        if len(store.recent(10)) > 0 {
            break
        }
        time.Sleep(20 * time.Millisecond)
    }
    jobs := store.recent(10)
    if len(jobs) == 0 {
        t.Fatal("LPD server captured no job from the LPR client")
    }
    if jobs[0].User != "alice" || jobs[0].Host != "client1" {
        t.Fatalf("control-file metadata not delivered: %+v", jobs[0])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestLPRTransport -v`
Expected: FAIL — `undefined: lprTransport`

- [ ] **Step 3: Write minimal implementation**

```go
package main

import (
    "bufio"
    "fmt"
    "net"
    "time"
)

type lprTransport struct{}

// send implements the RFC 1179 client side: receive-job, then control file then
// data file, reading the single-byte ACK after each step.
func (lprTransport) send(t *target, data []byte, j *job) error {
    to := t.timeout
    if to <= 0 {
        to = 30 * time.Second
    }
    queue := t.queue
    if queue == "" || queue == "auto" {
        queue = orElse(j.Queue, "lp")
    }

    conn, err := dialMaybePrivileged(t.address, t.privPort, to)
    if err != nil {
        return err
    }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(to))
    r := bufio.NewReader(conn)

    // 0x02 <queue>\n  — receive a printer job.
    if _, err := fmt.Fprintf(conn, "\x02%s\n", queue); err != nil {
        return err
    }
    if err := expectAck(r); err != nil {
        return fmt.Errorf("receive-job rejected: %w", err)
    }

    host := orElse(j.Host, "printcap")
    user := orElse(j.User, "printcap")
    name := orElse(j.JobName, "job")
    dfName := "dfA001" + host
    cfName := "cfA001" + host
    ctrl := fmt.Sprintf("H%s\nP%s\nJ%s\nf%s\n", host, user, name, dfName)

    // 0x02 <len> <cfname>\n  (control file sub-command)
    if err := sendLPRFile(conn, r, 0x02, cfName, []byte(ctrl)); err != nil {
        return fmt.Errorf("control file: %w", err)
    }
    // 0x03 <len> <dfname>\n  (data file sub-command)
    if err := sendLPRFile(conn, r, 0x03, dfName, data); err != nil {
        return fmt.Errorf("data file: %w", err)
    }
    return nil
}

func sendLPRFile(conn net.Conn, r *bufio.Reader, sub byte, name string, body []byte) error {
    if _, err := fmt.Fprintf(conn, "%c%d %s\n", sub, len(body), name); err != nil {
        return err
    }
    if err := expectAck(r); err != nil {
        return err
    }
    if _, err := conn.Write(body); err != nil {
        return err
    }
    if _, err := conn.Write([]byte{0x00}); err != nil { // terminator
        return err
    }
    return expectAck(r)
}

func expectAck(r *bufio.Reader) error {
    b, err := r.ReadByte()
    if err != nil {
        return err
    }
    if b != 0x00 {
        return fmt.Errorf("negative acknowledgement 0x%02x", b)
    }
    return nil
}

// dialMaybePrivileged optionally binds a privileged local source port (721-731)
// for strict downstream daemons; falls back to an ephemeral port.
func dialMaybePrivileged(addr string, priv bool, to time.Duration) (net.Conn, error) {
    if !priv {
        return net.DialTimeout("tcp", addr, to)
    }
    d := net.Dialer{Timeout: to}
    for p := 721; p <= 731; p++ {
        d.LocalAddr = &net.TCPAddr{Port: p}
        if c, err := d.Dial("tcp", addr); err == nil {
            return c, nil
        }
    }
    // Could not get a privileged port — try ephemeral as a last resort.
    return net.DialTimeout("tcp", addr, to)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestLPRTransport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fwd_lpr.go fwd_lpr_test.go
git commit -m "feat(forward): RFC 1179 LPR client transport"
```

---

## Task 6: IPP/IPPS client transport (`fwd_ipp.go`)

**Files:**
- Create: `fwd_ipp.go`
- Test: `fwd_ipp_test.go`

Reuses `writeStr`/`writeAttr` and the `tag*` constants from `ipp.go`. The
integration test points the forwarder at **printcap's own IPP handler**.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "net"
    "net/http"
    "testing"
    "time"
)

func TestIPPTransportToOwnHandler(t *testing.T) {
    cfg = defaultConfig()
    cfg.OutDir = t.TempDir()
    sink = &captureSink{dir: cfg.OutDir}
    store = newJobStore(10)

    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    srv := &http.Server{Handler: http.HandlerFunc(ippHandler)}
    go srv.Serve(ln)
    defer srv.Close()

    tr := ippTransport{}
    tg := &target{
        transport: "ipp",
        address:   "ipp://" + ln.Addr().String() + "/ipp/print",
        timeout:   2 * time.Second,
        docFormat: "application/pdf",
    }
    j := &job{User: "bob", JobName: "memo"}
    if err := tr.send(tg, []byte("%PDF-1.4 hi"), j); err != nil {
        t.Fatalf("send: %v", err)
    }

    deadline := time.Now().Add(2 * time.Second)
    for time.Now().Before(deadline) {
        if len(store.recent(10)) > 0 {
            break
        }
        time.Sleep(20 * time.Millisecond)
    }
    jobs := store.recent(10)
    if len(jobs) == 0 {
        t.Fatal("IPP handler captured no job from the IPP client")
    }
    if jobs[0].User != "bob" || jobs[0].DocFormat != "application/pdf" {
        t.Fatalf("IPP attributes not delivered: %+v", jobs[0])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestIPPTransport -v`
Expected: FAIL — `undefined: ippTransport`

- [ ] **Step 3: Write minimal implementation**

```go
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
    buf.Write([]byte{0x02, 0x00}) // version 2.0
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run TestIPPTransport -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add fwd_ipp.go fwd_ipp_test.go
git commit -m "feat(forward): IPP/IPPS client transport (Print-Job)"
```

---

## Task 7: Config types, compilation & the forwarder (`config.go`, `forward.go`)

**Files:**
- Modify: `config.go` (add `ForwardConf` and nested structs, default, `Config` field)
- Create: `forward.go` (compile config → targets, `newForwarder`, `forward`)
- Modify: `main.go` (`job.Forwards` field, `-forward` flag + override)
- Test: `forward_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "strings"
    "testing"
    "time"
)

// fakeTransport records sends and can be made to fail.
type fakeTransport struct {
    sent   [][]byte
    failErr error
}

func (f *fakeTransport) send(t *target, data []byte, j *job) error {
    if f.failErr != nil {
        return f.failErr
    }
    f.sent = append(f.sent, append([]byte{}, data...))
    return nil
}

func TestForwarderRoutesAndTransforms(t *testing.T) {
    cfg = defaultConfig()
    fw, err := newForwarder(ForwardConf{
        Enabled: true,
        Macros:  map[string]string{"reset": `\x1bE`},
        Targets: []ForwardTarget{{
            Name: "t1", Transport: "raw", Address: "x", Failure: "block",
            When:       ForwardCond{Protocols: []string{"IPP"}},
            Transforms: []TransformStep{
                {Type: "inject_prefix", Data: "macro:reset"},
                {Type: "replace", Mode: "literal", Match: "A", With: "B", All: true},
            },
        }},
    })
    if err != nil {
        t.Fatal(err)
    }
    ft := &fakeTransport{}
    fw.targets[0].send = ft

    // Matching job (IPP) is transformed and forwarded.
    j := &job{Protocol: "IPP"}
    if err := fw.forward(j, []byte("AAA")); err != nil {
        t.Fatalf("forward: %v", err)
    }
    if len(ft.sent) != 1 || string(ft.sent[0]) != "\x1bEBBB" {
        t.Fatalf("sent=%v", ft.sent)
    }
    if len(j.Forwards) != 1 || j.Forwards[0].Status != "ok" {
        t.Fatalf("forwards=%+v", j.Forwards)
    }

    // Non-matching job (9100) is not forwarded.
    j2 := &job{Protocol: "9100"}
    _ = fw.forward(j2, []byte("AAA"))
    if len(ft.sent) != 1 {
        t.Fatalf("non-matching job should not forward; sent=%v", ft.sent)
    }
}

func TestForwarderBlockPolicyReturnsError(t *testing.T) {
    cfg = defaultConfig()
    fw, err := newForwarder(ForwardConf{
        Enabled: true,
        Targets: []ForwardTarget{{Name: "t1", Transport: "raw", Address: "x", Failure: "block"}},
    })
    if err != nil {
        t.Fatal(err)
    }
    fw.targets[0].send = &fakeTransport{failErr: errForward}
    j := &job{Protocol: "IPP"}
    if err := fw.forward(j, []byte("X")); err == nil {
        t.Fatal("block policy must return the delivery error")
    }
    if len(j.Forwards) != 1 || j.Forwards[0].Status != "failed" {
        t.Fatalf("forwards=%+v", j.Forwards)
    }
}

func TestForwarderBestEffortSwallowsError(t *testing.T) {
    cfg = defaultConfig()
    fw, _ := newForwarder(ForwardConf{
        Enabled: true,
        Targets: []ForwardTarget{{Name: "t1", Transport: "raw", Address: "x", Failure: "best_effort"}},
    })
    fw.targets[0].send = &fakeTransport{failErr: errForward}
    j := &job{Protocol: "IPP"}
    if err := fw.forward(j, []byte("X")); err != nil {
        t.Fatalf("best_effort must not return an error, got %v", err)
    }
    // best_effort delivers on a goroutine; allow it to record the result.
    time.Sleep(50 * time.Millisecond)
}

var errForward = func() error { return errString("boom") }()

type errString string
func (e errString) Error() string { return string(e) }

func TestUnknownTransportDisablesTarget(t *testing.T) {
    cfg = defaultConfig()
    fw, err := newForwarder(ForwardConf{
        Enabled: true,
        Targets: []ForwardTarget{{Name: "bad", Transport: "smb", Address: "x"}},
    })
    if err != nil {
        t.Fatal(err)
    }
    if len(fw.targets) != 0 {
        t.Fatalf("unknown transport should be disabled; targets=%d", len(fw.targets))
    }
    _ = strings.TrimSpace
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run 'TestForwarder|TestUnknownTransport' -v`
Expected: FAIL — `undefined: newForwarder`

- [ ] **Step 3a: Add config types (`config.go`)**

Add the structs from the "Shared types" section (`ForwardConf`, `ForwardTarget`,
`ForwardRetry`, `ForwardCond`, `TransformStep`). Add to `Config` after `MDNS`
(or after `Log` if the mDNS spec isn't merged):

```go
    Forward   ForwardConf `json:"forward"`
```

Add to `defaultConfig()`:

```go
        Forward: ForwardConf{
            Enabled: false,
            Capture: "both",
            Macros:  map[string]string{},
            Targets: []ForwardTarget{},
        },
```

- [ ] **Step 3b: Add `job.Forwards` + `-forward` flag (`main.go`)**

In the `job` struct, add:

```go
    Forwards  []forwardResult `json:"forwards,omitempty"`
```

In `main()`, add the flag:

```go
    flag.Bool("forward", false, "enable the transform & forward proxy")
```

In `applyFlagOverrides()` switch, add:

```go
        case "forward":
            cfg.Forward.Enabled = get() == "true"
```

- [ ] **Step 3c: Implement the forwarder (`forward.go`)**

```go
package main

import (
    "encoding/hex"
    "fmt"
    "sync"
    "time"
)

type forwarder struct {
    capture string
    macros  map[string][]byte
    targets []*target
    wg      sync.WaitGroup
}

// knownTransports maps a transport name to its implementation. lpr/ipp/ipps are
// all first-class in phase 1.
func transportFor(name string) (transport, bool) {
    switch name {
    case "raw":
        return rawTransport{}, true
    case "lpr":
        return lprTransport{}, true
    case "ipp", "ipps":
        return ippTransport{}, true
    }
    return nil, false
}

// newForwarder compiles config into runtime targets. Bad targets/rules are
// logged and skipped, never fatal.
func newForwarder(c ForwardConf) (*forwarder, error) {
    f := &forwarder{capture: orElse(c.Capture, "both"), macros: map[string][]byte{}}
    for name, raw := range c.Macros {
        f.macros[name] = decodeBytes(raw, nil)
    }
    for _, tc := range c.Targets {
        send, ok := transportFor(tc.Transport)
        if !ok {
            logWarn("fwd", "target %q: unknown transport %q, disabled", tc.Name, tc.Transport)
            continue
        }
        cond, err := compileCond(tc.When)
        if err != nil {
            logWarn("fwd", "target %q: %v, disabled", tc.Name, err)
            continue
        }
        steps, err := f.compileSteps(tc.Transforms)
        if err != nil {
            logWarn("fwd", "target %q: %v, disabled", tc.Name, err)
            continue
        }
        f.targets = append(f.targets, &target{
            name: tc.Name, transport: tc.Transport, address: tc.Address,
            timeout:  time.Duration(tc.TimeoutMS) * time.Millisecond,
            queue:    tc.Queue, privPort: tc.PrivilegedSourcePort,
            tlsSkip:  tc.TLSSkipVerify, docFormat: tc.DocumentFormat,
            when:     cond, failure: orElse(tc.Failure, "best_effort"),
            retry:    tc.Retry, steps: steps, send: send,
        })
    }
    return f, nil
}

func (f *forwarder) compileSteps(in []TransformStep) ([]compiledStep, error) {
    var out []compiledStep
    for _, s := range in {
        cs := compiledStep{kind: s.Type, mode: s.Mode, all: s.All}
        if s.When != (ForwardCond{}) {
            cond, err := compileCond(s.When)
            if err != nil {
                return nil, fmt.Errorf("transform when: %w", err)
            }
            cs.when = cond
        }
        switch s.Type {
        case "inject_prefix", "inject_suffix":
            cs.data = decodeBytes(s.Data, f.macros)
        case "replace":
            switch s.Mode {
            case "regex":
                re, err := compileRegex(s.Match)
                if err != nil {
                    return nil, err
                }
                cs.re = re
                cs.withS = decodeRegexReplacement(s.With)
            case "hex":
                m, err := hex.DecodeString(s.Match)
                if err != nil {
                    return nil, fmt.Errorf("bad hex match: %w", err)
                }
                w, err := hex.DecodeString(s.With)
                if err != nil {
                    return nil, fmt.Errorf("bad hex with: %w", err)
                }
                cs.match, cs.with = m, w
            default: // literal
                cs.match = decodeBytes(s.Match, f.macros)
                cs.with = decodeBytes(s.With, f.macros)
            }
        default:
            return nil, fmt.Errorf("unknown transform type %q", s.Type)
        }
        out = append(out, cs)
    }
    return out, nil
}

// forward tees the job to every matching target. Returns the first error from a
// target whose failure policy is "block".
func (f *forwarder) forward(j *job, original []byte) error {
    var blockErr error
    for _, t := range f.targets {
        if t.when != nil && !t.when.matches(j, original) {
            logDebug("fwd", "target %q: condition not met, skipping", t.name)
            continue
        }
        out := applyTransforms(t.steps, original, j)
        captureTransformed(f.capture, j, t.name, out)
        if err := f.deliver(t, out, j); err != nil && t.failure == "block" && blockErr == nil {
            blockErr = err
        }
    }
    return blockErr
}

// deliver applies the target's failure policy. best_effort/spool_retry never
// return an error; block delivers synchronously and returns it.
func (f *forwarder) deliver(t *target, data []byte, j *job) error {
    record := func(status string, err error) {
        res := forwardResult{Target: t.name, Transport: t.transport, Address: t.address,
            Status: status, Bytes: len(data)}
        if err != nil {
            res.Error = err.Error()
        }
        j.Forwards = append(j.Forwards, res)
    }
    switch t.failure {
    case "block":
        if err := t.send.send(t, data, j); err != nil {
            logWarn("fwd", "target %q: forward failed (block): %v", t.name, err)
            record("failed", err)
            return err
        }
        logInfo("fwd", "forwarded %d bytes to %q", len(data), t.name)
        record("ok", nil)
        return nil
    case "spool_retry":
        record("queued", nil)
        f.wg.Add(1)
        go func() { defer f.wg.Done(); f.retryLoop(t, data) }()
        return nil
    default: // best_effort
        f.wg.Add(1)
        go func() {
            defer f.wg.Done()
            if err := t.send.send(t, data, j); err != nil {
                logWarn("fwd", "target %q: forward failed (best_effort): %v", t.name, err)
            } else {
                logInfo("fwd", "forwarded %d bytes to %q", len(data), t.name)
            }
        }()
        record("ok", nil) // recorded as dispatched; async outcome only logged
        return nil
    }
}

// retryLoop attempts delivery with backoff up to the configured limits.
func (f *forwarder) retryLoop(t *target, data []byte) {
    max := t.retry.MaxAttempts
    if max <= 0 {
        max = 3
    }
    backoff := time.Duration(t.retry.BackoffMS) * time.Millisecond
    if backoff <= 0 {
        backoff = 2 * time.Second
    }
    for attempt := 1; attempt <= max; attempt++ {
        if err := t.send.send(t, data, &job{}); err == nil {
            logInfo("fwd", "target %q: spooled job delivered on attempt %d", t.name, attempt)
            return
        } else {
            logWarn("fwd", "target %q: attempt %d/%d failed: %v", t.name, attempt, max, err)
        }
        time.Sleep(backoff)
    }
    logErr("fwd", "target %q: giving up after %d attempts", t.name, max)
}

// Close waits for in-flight async/retry deliveries to finish.
func (f *forwarder) Close() error {
    f.wg.Wait()
    return nil
}
```

Add the small helpers used above (in `forward.go`):

```go
import "regexp"

func compileRegex(p string) (*regexp.Regexp, error) {
    re, err := regexp.Compile(p)
    if err != nil {
        return nil, fmt.Errorf("bad regex %q: %w", p, err)
    }
    return re, nil
}

// decodeRegexReplacement turns \xNN escapes in a regex replacement template into
// literal bytes while leaving $1-style backreferences intact.
func decodeRegexReplacement(s string) string {
    return string(decodeBytes(s, nil))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -run 'TestForwarder|TestUnknownTransport' -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add config.go forward.go main.go forward_test.go
git commit -m "feat(forward): forwarder, config compilation, and failure policies"
```

---

## Task 8: Capture-transformed + sink integration (`sink.go`, handlers, `engine.go`)

**Files:**
- Modify: `sink.go` (`save` returns error; capture transformed; call forwarder)
- Modify: `forward.go` (add `captureTransformed`)
- Modify: `raw9100.go`, `lpd.go`, `ipp.go` (propagate the error)
- Modify: `engine.go` (build forwarder at Start, Close at Stop)
- Test: `sink_forward_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"
)

func TestSinkSaveTeesAndCapturesBoth(t *testing.T) {
    cfg = defaultConfig()
    cfg.OutDir = t.TempDir()
    sink = &captureSink{dir: cfg.OutDir}
    store = newJobStore(10)

    // Downstream raw listener that accepts the forwarded bytes.
    ln, _ := net.Listen("tcp", "127.0.0.1:0")
    defer ln.Close()
    go func() {
        c, err := ln.Accept()
        if err == nil {
            c.Close()
        }
    }()

    fwd, err := newForwarder(ForwardConf{
        Enabled: true, Capture: "both",
        Targets: []ForwardTarget{{
            Name: "lab", Transport: "raw", Address: ln.Addr().String(), Failure: "block",
            Transforms: []TransformStep{{Type: "replace", Mode: "literal", Match: "FOO", With: "BAR", All: true}},
        }},
    })
    if err != nil {
        t.Fatal(err)
    }
    forward = fwd

    j := &job{Protocol: "9100", Source: "127.0.0.1:1234"}
    j.data = []byte("FOO baz")
    j.Bytes = len(j.data)
    if err := sink.save(j); err != nil {
        t.Fatalf("save: %v", err)
    }

    // Original + sent files both present.
    entries, _ := os.ReadDir(cfg.OutDir)
    var sawOrig, sawSent bool
    for _, e := range entries {
        n := e.Name()
        if strings.Contains(n, "-sent-lab") {
            sawSent = true
            b, _ := os.ReadFile(filepath.Join(cfg.OutDir, n))
            if string(b) != "BAR baz" {
                t.Fatalf("sent file content %q", b)
            }
        } else if strings.HasSuffix(n, ".prn") || strings.HasSuffix(n, ".txt") {
            sawOrig = true
        }
    }
    if !sawOrig || !sawSent {
        t.Fatalf("orig=%v sent=%v entries=%v", sawOrig, sawSent, names(entries))
    }
    if len(j.Forwards) != 1 || j.Forwards[0].Status != "ok" {
        t.Fatalf("forwards=%+v", j.Forwards)
    }
    _ = time.Second
}

func names(es []os.DirEntry) []string {
    var out []string
    for _, e := range es {
        out = append(out, e.Name())
    }
    return out
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./... -run TestSinkSaveTees -v`
Expected: FAIL — `forward` global undefined / `save` returns no error

- [ ] **Step 3a: Add the `forward` global and `captureTransformed` (`forward.go`)**

```go
// forward is the process-wide forwarder, built by the Engine at Start (nil when
// forwarding is disabled).
var forward *forwarder

// captureTransformed writes the post-transform bytes when capture mode includes
// the sent copy. Filename mirrors the original's base with a -sent-<target> tag.
func captureTransformed(mode string, j *job, targetName string, data []byte) {
    if mode == "orig" {
        return
    }
    base := j.captureBase
    if base == "" {
        return
    }
    name := fmt.Sprintf("%s-sent-%s%s", base, unsafeName.ReplaceAllString(targetName, "_"), j.captureExt)
    if err := os.WriteFile(filepath.Join(sink.dir, name), data, 0o600); err != nil {
        logErr("fwd", "failed to write transformed capture: %v", err)
    }
}
```

Add imports `os`, `path/filepath` to `forward.go`.

- [ ] **Step 3b: Record the capture base/ext on the job and call the forwarder (`sink.go`)**

The `job` struct (in `main.go`) gains two unexported fields used to name the
`-sent` files consistently with the original:

```go
    captureBase string // set by sink.save: "<stamp>-<id>-<proto>[-<jobname>]"
    captureExt  string // set by sink.save: the chosen extension
```

In `sink.go`, change the signature and wire the forwarder. Replace the current
`func (s *captureSink) save(j *job)` with one returning `error`:

```go
func (s *captureSink) save(j *job) error {
    if cfg.MaxJobMB > 0 {
        if cap := cfg.MaxJobMB * 1024 * 1024; len(j.data) > cap {
            j.data = j.data[:cap]
            j.Bytes = cap
        }
    }
    j.ID = nextSeq()
    if j.Received == "" {
        j.Received = time.Now().Format(time.RFC3339)
    }
    ext := extForFormat(j)

    stamp := time.Now().Format("20060102-150405")
    base := fmt.Sprintf("%s-%04d-%s", stamp, j.ID, j.Protocol)
    if j.JobName != "" {
        base += "-" + unsafeName.ReplaceAllString(j.JobName, "_")
    }
    if len(base) > 120 {
        base = base[:120]
    }
    j.captureBase, j.captureExt = base, ext // for -sent naming

    mode := cfg.mode()
    if mode != saveMeta && len(j.data) > 0 {
        name := base + ext
        if err := os.WriteFile(filepath.Join(s.dir, name), j.data, 0o600); err != nil {
            logErr(j.Protocol, "failed to write spool data: %v", err)
        } else {
            j.SavedAs = name
            logDebug(j.Protocol, "wrote spool file %s (%d bytes)", name, j.Bytes)
        }
    }

    // Tee to the forwarder BEFORE writing metadata, so the .json captures the
    // forward results. Keep the original bytes intact for downstream delivery.
    var fwdErr error
    if forward != nil {
        original := append([]byte{}, j.data...)
        fwdErr = forward.forward(j, original)
    }

    if mode != saveRaw {
        b, _ := json.MarshalIndent(j, "", "  ")
        if err := os.WriteFile(filepath.Join(s.dir, base+".json"), b, 0o600); err != nil {
            logErr(j.Protocol, "failed to write metadata: %v", err)
        }
    }

    store.add(j)
    logInfo(j.Protocol, "captured %d bytes from %s user=%s job=%q queue=%s pdl=%s -> %s",
        j.Bytes, j.Source, orQ(j.User), j.JobName, orQ(j.Queue), orQ(j.PDL), orElse(j.SavedAs, "(meta only)"))
    return fwdErr
}
```

(Note: file mode tightened to `0o600`, addressing the audit's M1 finding.)

- [ ] **Step 3c: Propagate the error in handlers**

`raw9100.go` — `saveRawStream` ignores the return for best_effort but closes on
block failure. Change the `sink.save(j)` calls to:

```go
        if err := sink.save(j); err != nil {
            logWarn(proto, "forward (block) failed, dropping connection: %v", err)
            return
        }
```

`lpd.go` — both `sink.save(j)` call sites become:

```go
        if err := sink.save(j); err != nil {
            logWarn("LPR", "forward (block) failed: %v", err)
            return // withhold the final ACK; client sees the job as not completed
        }
```

`ipp.go` — in `ippHandler`, replace `sink.save(j)` with:

```go
        if err := sink.save(j); err != nil {
            logWarn(proto, "forward (block) failed: %v", err)
            status = 0x0508 // server-error-job-canceled
        }
```

(Place this where `status` is still mutable, before `buildIPPResponse`.)

- [ ] **Step 3d: Build/stop the forwarder in the Engine (`engine.go`)**

In `Start()`, after `store = newJobStore(200)`:

```go
    if cfg.Forward.Enabled {
        if fw, err := newForwarder(cfg.Forward); err != nil {
            e.logf("forward: %v", err)
        } else {
            forward = fw
            e.closers = append(e.closers, fw)
            logInfo("engine", "forwarding enabled: %d target(s)", len(fw.targets))
        }
    } else {
        forward = nil
    }
```

(`*forwarder` satisfies `io.Closer` via `Close()`.)

- [ ] **Step 4: Run the full suite + build + vet**

Run: `go test ./... && go build ./... && go vet ./...`
Expected: all PASS; build & vet clean.

- [ ] **Step 5: Confirm no new dependency**

Run: `git diff -- go.mod go.sum`
Expected: empty.

- [ ] **Step 6: Commit**

```bash
git add sink.go forward.go main.go raw9100.go lpd.go ipp.go engine.go sink_forward_test.go
git commit -m "feat(forward): tee in sink.save, capture transformed, propagate block errors"
```

---

## Task 9: Documentation (`README.md`, `ADMIN_GUIDE.md`)

**Files:**
- Modify: `README.md` (new "Forwarding & transform (proxy)" section)
- Modify: `ADMIN_GUIDE.md` (config block + field notes + a length-safety warning + acceptance step)

- [ ] **Step 1: Add the README section**

Insert after the "Output" section in `README.md`:

```markdown
## Forwarding & transform (proxy)

printcap can also **forward** each captured job to one or more real printers
after running it through a **transform pipeline** — find/replace and PCL/command
injection — while still capturing the original (a tee). Enable with
`forward.enabled` (or `-forward`).

Each entry in `forward.targets` defines a downstream printer: a `transport`
(`raw`/9100, `lpr`, or `ipp`/`ipps`), an `address`, a routing `when` condition,
an ordered list of `transforms`, and a `failure` policy
(`best_effort` | `spool_retry` | `block`). A job is sent to every target whose
condition matches. Transforms are `replace` (literal/regex/hex) and
`inject_prefix`/`inject_suffix` (raw bytes with `\xNN` escapes and reusable
`macro:` references). `capture` controls what lands on disk: `both` (default),
`sent`, or `orig`.

> **Length safety:** `replace` is intended for text/PCL/PostScript. Replacements
> that change byte length can corrupt length-indexed formats (PDF cross-reference
> tables, PCL transparent-data/raster blocks). Gate such rules with
> `when.pdls` to restrict them to safe formats.

See `ADMIN_GUIDE.md` for the full config block and examples.
```

- [ ] **Step 2: Add the ADMIN_GUIDE config + acceptance**

In `ADMIN_GUIDE.md` §8, add the `forward` block (copy the JSONC from the design
spec §3) and a field-notes bullet list summarizing `transport`, `address`
formats per transport, `when`, `transforms`, `failure`/`retry`, and `capture`.
Add the length-safety warning verbatim from Step 1. Add to §19:

```markdown
9. **Forwarding** — set `forward.enabled:true` with a `raw` target pointing at a
   test printer (or `nc -l 9100`). Print a job; confirm it appears at the target,
   and that both `<base>...` and `<base>-sent-<target>...` files exist in the
   capture folder with the transform applied.
```

- [ ] **Step 3: Commit**

```bash
git add README.md ADMIN_GUIDE.md
git commit -m "docs(forward): document the transform & forward proxy"
```

---

## Task 10: Manual acceptance (real printer)

**Files:** none (verification only).

- [ ] **Step 1: raw forward end-to-end**

Config a `raw` target at a real printer's `host:9100` with a literal `replace`
rule. Print a job. Confirm: the printer prints the modified output; the dashboard
job shows `forwards: [{... status: ok}]`; the capture folder has `-orig` and
`-sent-<target>` files differing exactly by the replacement.

- [ ] **Step 2: LPR + IPP forward**

Repeat with an `lpr` target (`host:515`, a real queue) and an `ipp` target
(`ipp://host:631/ipp/print`). Confirm delivery and capture for each.

- [ ] **Step 3: Injection + macro**

Add `inject_prefix: "macro:pcl_reset"` and a suffix; confirm the `-sent` bytes are
wrapped and the printer honors the commands.

- [ ] **Step 4: Failure policies**

Point a target at an unreachable address. With `block`, the sending client sees a
failure (raw connection dropped / IPP error / LPD no final ACK); with
`best_effort`, the job is still captured and a `WARN [fwd]` is logged; with
`spool_retry`, retries are logged then it gives up per limits.

- [ ] **Step 5: Routing**

Two targets with different `when` (e.g. one `pdls:["PCL"]`, one
`job_name:"*invoice*"`); confirm each job goes only to matching targets.

---

## Self-Review notes (completed by plan author)

- **Spec coverage:** §2 architecture → Tasks 7–8; §3 config/notation → Tasks 1,3,7;
  §4 transforms → Tasks 1–2; §5 conditions → Task 3; §6 transports → Tasks 4–6;
  §7 failure policies → Task 7; §8 capture → Task 8; §9 logging → Tasks 2,7,8;
  §10 testing → Tasks 1–8; §11 acceptance → Task 10. No gaps.
- **Type consistency:** `forwarder`, `target`, `transport.send(t *target, data []byte, j *job)`,
  `compiledStep`, `compiledCond`/`compileCond`, `condMatcher`, `applyTransforms`,
  `decodeBytes`, `forwardResult`, `captureTransformed`, `job.Forwards`/`captureBase`/`captureExt`
  are used identically across tasks. `rawTransport`/`lprTransport`/`ippTransport` all satisfy
  `transport`. `sink.save` returns `error` consistently in Task 8 and all three handlers.
- **Placeholder scan:** none — all steps carry concrete code.
- **Dependency guard:** Task 8 Step 5 asserts `go.mod`/`go.sum` unchanged (stdlib only).
- **Known follow-ups (not blockers):** the `-sent` files reuse the original's chosen
  extension even though a transform could change the detected PDL — acceptable for phase 1
  and noted in docs. best_effort records `status:"ok"` at dispatch time (async outcome only
  logged), consistent with the spec's "never blocks" intent.
```
