# SMB2/3 Print-Share Capture Implementation Plan (staged)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.
>
> **Staging note (read first):** A full SMB2/3 server + NTLMv2 + DCERPC/spoolss is a large, protocol-dense subsystem. This plan is organized into **stages**, each independently shippable and testable. Foundational stages (framing, NTLMv2) carry complete code TDD-anchored on published vectors. Deeper protocol stages (SMB2 commands, DCERPC, spoolss) specify the exact wire structures, the `[MS-SMB2]`/`[MS-RPCE]`/`[MS-RPRN]` sections, and the locking test for each task — the implementer fills the message bodies from those normative references. This staging is a deliberate, communicated decision (the subsystem is too large for a single fully-inlined codebase), **not** hidden placeholders.

**Build order:** plan #5 of 6 — build AFTER SNMPv3 (which creates `redactedConfig()`) and after Mainframe/Forwarding. Default-off, experimental.

**Goal:** Receive and capture a print job delivered over SMB to a printer share, modeling SMB2/3 + NTLMv2 + spoolss, on a configurable non-445 port, default-off/experimental.

**Architecture:** Per-connection state machine over Direct-TCP framing; NEGOTIATE → SESSION_SETUP (NTLMv2) → TREE_CONNECT(IPC$) → CREATE/WRITE/READ on `\spoolss` → DCERPC bind → MS-RPRN job sequence → `sink.save`.

**Tech Stack:** Go 1.26 stdlib only — `net`, `encoding/binary`, `crypto/md5`, `crypto/hmac`, `crypto/rc4`, `crypto/des`, `crypto/aes`, `crypto/cipher`, `crypto/rand`, `encoding/hex`.

**References:** `[MS-SMB2]` (SMB2), `[MS-NLMP]` (NTLM, §4.2 test vectors), `[MS-RPCE]` (DCERPC), `[MS-RPRN]` (Print System Remote Protocol).

---

## Stage 0 — Config & listener skeleton

### Task 0.1: SMBConf + flag + listener stub

**Files:** Modify `config.go`, `main.go`, `engine.go`, `dashboard.go`; Create `smb.go`; Test `smb_config_test.go`.

- [ ] **Step 1: Failing test**

```go
package main

import (
    "encoding/json"
    "strings"
    "testing"
)

func TestSMBDefaultsAndRedaction(t *testing.T) {
    cfg = defaultConfig()
    if cfg.SMB.Enabled || cfg.SMB.Port != 4445 {
        t.Fatalf("unexpected SMB defaults: %+v", cfg.SMB)
    }
    cfg.SMB.Users = []SMBUser{{User: "print", Password: "secret", Domain: "WORKGROUP"}}
    b, _ := json.Marshal(redactedConfig())
    if strings.Contains(string(b), "secret") {
        t.Fatal("SMB password leaked in redacted config")
    }
}
```

- [ ] **Step 2:** Run `go test ./... -run TestSMBDefaults -v` → FAIL (`cfg.SMB` undefined).
- [ ] **Step 3:** Implement:
  - `config.go`: add `SMBConf` + `SMBUser`, `Config.SMB`, and defaults
    (`Enabled:false, Port:4445, Sign:true, Encrypt:true, Users:[]SMBUser{}`).
    ```go
    type SMBUser struct {
        User     string `json:"user"`
        Password string `json:"password"`
        Domain   string `json:"domain"`
    }
    type SMBConf struct {
        Enabled     bool      `json:"enabled"`
        Port        int       `json:"port"`
        ShareName   string    `json:"share_name"`
        RequireAuth bool      `json:"require_auth"`
        Sign        bool      `json:"sign"`
        Encrypt     bool      `json:"encrypt"`
        Users       []SMBUser `json:"users"`
    }
    ```
  - `dashboard.go`: ensure a `redactedConfig()` helper exists, then extend it to
    blank `SMB.Users[i].Password`.
    - **If the SNMPv3 plan (build #1) already created `redactedConfig()`, just
      extend it; otherwise create it here.** On `main` today there is NO
      `redactedConfig()` — redaction is inline in `apiConfig` (dashboard.go ~108–118).
      If absent, CREATE it by extracting that inline body into
      `func redactedConfig() *Config` (copy `cfg`, redact `SNMP.Community` to `"***"`,
      blank `TLS.CertFile`/`TLS.KeyFile`) and change `apiConfig` to
      `writeJSON(w, redactedConfig())`.
    - THEN extend `redactedConfig()` to also blank `SMB.Users[i].Password` for each
      configured user.
  - `main.go`: add `flag.Bool("smb", false, "enable the experimental SMB print share")`.
    The existing override switch (`applyFlagOverrides`) keys port flags through
    `atoiDefault` (Int values); `-smb` is a **bool**, so add a distinct arm:
    `case "smb": cfg.SMB.Enabled = true`.
  - `engine.go`: in `Start()`, `if cfg.SMB.Enabled { addTCP("SMB", cfg.SMB.Port, serveSMB) }`.
  - `smb.go`: stub `func serveSMB(ln net.Listener) { for { c, err := ln.Accept(); if err != nil { return }; go handleSMBConn(c) } }` and `func handleSMBConn(c net.Conn) { defer c.Close() }` (filled in later stages).
- [ ] **Step 4:** `go test ./... -run TestSMBDefaults -v && go build ./...` → PASS/clean.
- [ ] **Step 5:** Commit `feat(smb): config, -smb flag, listener skeleton`.

---

## Stage 1 — NTLMv2 (foundational, fully coded)

### Task 1.1: NTOWFv2 + NTLMv2 response (MS-NLMP §4.2.4 vectors)

**Files:** Create `ntlm.go`, `ntlm_test.go`.

- [ ] **Step 1: Failing test (canonical [MS-NLMP] §4.2.4 vector)**

```go
package main

import (
    "encoding/hex"
    "testing"
)

// [MS-NLMP] §4.2.4.1.1: User="User", Domain="Domain", Password="Password".
// NTOWFv2 = MD4(NTOWFv1) keyed-HMAC-MD5 over UPPER(User)||Domain.
func TestNTOWFv2_Vector(t *testing.T) {
    got := ntowfv2("User", "Domain", "Password")
    want := "0c868a403bfd7a93a3001ef22ef02e3f"
    if hex.EncodeToString(got) != want {
        t.Fatalf("NTOWFv2\n got=%s\nwant=%s", hex.EncodeToString(got), want)
    }
}
```

- [ ] **Step 2:** Run `go test ./... -run TestNTOWFv2 -v` → FAIL.
- [ ] **Step 3:** Implement (stdlib MD4 is not in std; implement MD4 per RFC 1320 in `md4.go`, or compute NTOWFv1 via the documented algorithm). Provide:
  ```go
  // ntowfv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user)+domain))
  func ntowfv2(user, domain, password string) []byte { /* per [MS-NLMP] §3.3.2 */ }
  ```
  Include `md4.go` (RFC 1320) since Go removed `golang.org/x/crypto/md4` from stdlib;
  it is ~120 lines of pure Go and keeps zero external deps. Lock it with the RFC
  1320 MD4 test vectors (`MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0`) in
  `md4_test.go`.
- [ ] **Step 4:** `go test ./... -run 'TestNTOWFv2|TestMD4' -v` → PASS.
- [ ] **Step 5:** Commit `feat(smb): NTLMv2 NTOWFv2 + MD4 (verified vs MS-NLMP/RFC1320)`.

### Task 1.2: NTLM message parse/build + AUTHENTICATE verification

**Files:** Modify `ntlm.go`, `ntlm_test.go`.

- [ ] **Step 1: Failing test** — build a CHALLENGE with a fixed server challenge,
  construct an AUTHENTICATE using `ntowfv2` for a known user/password, then assert
  `verifyNTLMv2(...)` accepts it and rejects a wrong password. (Uses the functions
  from 1.1; deterministic with a fixed challenge + client nonce.)
- [ ] **Step 2:** Run → FAIL (`undefined: verifyNTLMv2`).
- [ ] **Step 3:** Implement NEGOTIATE/CHALLENGE/AUTHENTICATE structs (`[MS-NLMP]`
  §2.2.1), `buildChallenge(serverChallenge, targetInfo)`, and
  `verifyNTLMv2(user, password, domain, serverChallenge, authMsg)` computing the
  NTLMv2 response + session base key. Guest path returns a flagged anonymous
  identity when `require_auth:false`.
- [ ] **Step 4:** `go test ./... -run TestNTLM -v` → PASS.
- [ ] **Step 5:** Commit `feat(smb): NTLM message flow and NTLMv2 verification`.

---

## Stage 2 — SMB2 transport & negotiate

### Task 2.1: Direct-TCP framing + SMB2 header (`smb_frame.go`)

**Files:** Create `smb_frame.go`, `smb_frame_test.go`.

- [ ] **Step 1: Failing test** — round-trip an SMB2 header
  (`[MS-SMB2]` §2.2.1.2: ProtocolId `0xFE 'S' 'M' 'B'`, StructureSize 64,
  Command, MessageId, SessionId, etc.) and the 4-byte Direct-TCP length prefix.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `readTCPFrame(r)`/`writeTCPFrame(w, payload)` (4-byte
  big-endian length, top byte zero) and `parseSMB2Header`/`buildSMB2Header` with
  the exact field offsets from `[MS-SMB2]` §2.2.1.2.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(smb): Direct-TCP framing and SMB2 header codec`.

### Task 2.2: NEGOTIATE (`smb_negotiate.go`)

**Files:** Create `smb_negotiate.go`, `smb_negotiate_test.go`.

- [ ] **Step 1: Failing test** — feed a captured/constructed SMB2 NEGOTIATE request
  fixture advertising dialects 2.0.2–3.1.1 (with the 3.1.1 negotiate contexts:
  preauth-integrity SHA-512, encryption ciphers); assert `handleNegotiate` selects
  3.1.1 and emits a response with our GUID, the chosen dialect, and matching
  contexts (`[MS-SMB2]` §2.2.3/§2.2.4).
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement dialect selection + response build per `[MS-SMB2]`
  §2.2.4, including the 3.1.1 negotiate-context echo (preauth hash algo, cipher).
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(smb): SMB2 NEGOTIATE with 3.1.1 contexts`.

---

## Stage 3 — Session, signing, encryption

### Task 3.1: SESSION_SETUP wrapping NTLM (`smb_session.go`)

**Files:** Create `smb_session.go`, `smb_session_test.go`.

- [ ] **Step 1: Failing test** — a two-leg SESSION_SETUP (NEGOTIATE→CHALLENGE,
  AUTHENTICATE→success) using the NTLM functions; assert the session is established
  and the session key derived. Verify guest vs NTLMv2 per `require_auth`.
- [ ] **Step 2–5:** Implement SESSION_SETUP (`[MS-SMB2]` §2.2.5/§2.2.6) embedding the
  GSS/NTLM tokens; derive the signing key and (for 3.x) encryption keys via the
  SP800-108 KDF (`[MS-SMB2]` §3.1.4.2). Tests assert key derivation against a fixed
  preauth hash + session base key. Commit `feat(smb): SESSION_SETUP + key derivation`.

### Task 3.2: SMB2 signing + SMB3 encryption (`smb_session.go`)

- [ ] **Step 1: Failing test** — sign a message with AES-CMAC (3.x) / HMAC-SHA256
  (2.x) and verify; encrypt/decrypt a transform-header-wrapped message
  (AES-128-CCM/GCM) round-trip (`[MS-SMB2]` §3.1.4.3, §2.2.41).
- [ ] **Step 2–5:** Implement using `crypto/aes` + `crypto/cipher` (GCM/CCM) and an
  AES-CMAC helper (stdlib has no CMAC — add `cmac.go`, ~60 lines, locked by the
  NIST SP 800-38B AES-CMAC test vectors). Commit `feat(smb): SMB2 signing + SMB3 encryption`.

---

## Stage 4 — Tree connect, pipe, DCERPC, spoolss (capture)

### Task 4.1: TREE_CONNECT + named-pipe CREATE/WRITE/READ (`smb_tree.go`)

- [ ] **Step 1: Failing test** — TREE_CONNECT to `IPC$` succeeds; CREATE on
  `\spoolss` returns a handle; CREATE on any other path returns
  `STATUS_ACCESS_DENIED`; WRITE/READ shuttle bytes to a pluggable pipe backend.
- [ ] **Step 2–5:** Implement `[MS-SMB2]` §2.2.9/§2.2.13/§2.2.19/§2.2.21 for the
  IPC$ tree and the `\spoolss` pipe; route pipe payloads to the DCERPC layer.
  Commit `feat(smb): IPC$ tree + spoolss named pipe`.

### Task 4.2: DCERPC bind + fragments (`dcerpc.go`)

- [ ] **Step 1: Failing test** — a DCERPC BIND for the MS-RPRN interface UUID
  yields a BIND_ACK; a REQUEST PDU is parsed to (opnum, stub) and a RESPONSE PDU is
  built (`[MS-RPCE]` §2.2.2). Fragment reassembly round-trips.
- [ ] **Step 2–5:** Implement the connection-oriented DCERPC PDUs needed (BIND,
  BIND_ACK, REQUEST, RESPONSE) and fragment handling. Commit `feat(smb): DCERPC bind + request/response`.

### Task 4.3: MS-RPRN job sequence → capture (`spoolss.go`)

- [ ] **Step 1: Failing test** — drive a scripted opnum sequence over an in-memory
  pipe: `RpcOpenPrinterEx`→`RpcStartDocPrinter`(pDocName="Report")→
  `RpcWritePrinter`("PCL"×N)→`RpcEndDocPrinter`→`RpcClosePrinter`; assert a `job`
  is produced with `Protocol:"SMB"`, `JobName:"Report"`, concatenated bytes, and
  passed to a stubbed sink.
- [ ] **Step 2–5:** Implement the NDR-decoded opnums from `[MS-RPRN]`. Canonical
  opnum numbers: `RpcOpenPrinter=1`, `RpcStartDocPrinter=17`, `RpcWritePrinter=19`,
  `RpcEndDocPrinter=23`, `RpcClosePrinter=29`, `RpcOpenPrinterEx=69` (per `[MS-RPRN]`
  — verify against §3.1.4 during implementation; the integration test backstops a
  wrong number). Accumulate WritePrinter buffers; on EndDocPrinter build the `job`
  and call `sink.save`. Commit `feat(smb): MS-RPRN job capture into sink`.

### Task 4.4: Wire the connection state machine (`smb.go`)

- [ ] **Step 1: Failing integration test** — `handleSMBConn` over a loopback
  `net.Pipe()` fed a scripted client byte stream (NEGOTIATE→SESSION_SETUP guest→
  TREE_CONNECT IPC$→CREATE \spoolss→WRITE the DCERPC job sequence) captures an SMB
  job end to end.
- [ ] **Step 2–5:** Implement the per-connection dispatch tying Stages 2–4 together,
  honoring signing/encryption state. Then `go test ./... && go build ./... && go vet ./...`;
  `git diff -- go.mod go.sum` empty. Commit `feat(smb): connection state machine + integration`.

---

## Stage 5 — Docs & manual acceptance

### Task 5.1: Docs

- [ ] Add a README "SMB print share (experimental)" section: non-445 port,
  guest/NTLMv2, `\\host:4445\PRINTER` / `smbclient -p 4445`, and the limitation
  notes. Add the `smb` config block + field notes + security note to ADMIN_GUIDE
  §8 and an acceptance step to §19. Commit `docs(smb): document experimental SMB share`.

### Task 5.2: Manual acceptance

- [ ] Linux `smbclient //HOST/PRINTER -p 4445 -N` (guest) then with `-U user%pass`
  (NTLMv2); print a file; confirm an `SMB` job is captured with user + document
  name, flows through PDL detection + forwarding, and `/api/config` redacts the
  password. Repeat against a Windows client able to address the alternate port.

---

## Self-Review notes (plan author)

- **Spec coverage:** §3 architecture → Stages 0–4; §4 config → Stage 0; §5 capture
  mapping → Task 4.3; §6 security → Stages 1,3 + redaction in 0.1; §7 logging →
  woven through (add `[SMB]` logs as each stage lands); §8 testing → each task's
  Step 1; §9 acceptance → Stage 5.
- **Verifiable anchors:** MD4 (RFC 1320), NTOWFv2 (MS-NLMP §4.2.4), AES-CMAC (NIST
  SP 800-38B), SMB2 header/NEGOTIATE round-trips, and the spoolss-sequence
  integration test lock correctness at each layer.
- **Staging honesty:** deeper SMB2/DCERPC/spoolss message bodies are specified by
  exact `[MS-*]` section + a locking test rather than fully inlined — a deliberate,
  communicated decision for a subsystem of this size, not silent placeholders. Each
  task is independently shippable behind the default-off `-smb` flag.
- **Dependency guard:** Task 4.4 asserts `go.mod`/`go.sum` unchanged (stdlib only;
  MD4 and CMAC added as small local files, not modules).
```
