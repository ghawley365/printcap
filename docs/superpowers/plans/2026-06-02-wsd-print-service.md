# WSD Print Service Implementation Plan (staged)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.
>
> **Staging note (read first):** Full WSD print is a large SOAP stack (WS-Addressing, WS-Discovery, WS-Transfer, WSPrint, MTOM). This plan is **staged**; each stage is independently shippable behind the default-off `-wsd` flag. Foundational stages (SOAP/WS-Addressing codec, WS-Discovery, MTOM) are fully coded and unit-tested; the WSPrint operation bodies are specified against the WSD Print Service schema + a locking test per task. Staging is a deliberate, communicated decision for a subsystem of this size — not hidden placeholders.
>
> **Build order: plan #6 of 6 — build LAST, AFTER the mDNS plan** (Task 2.2 reuses `mdns.go`'s multicast-socket discipline: dual-stack bind, graceful degrade on `EADDRINUSE`, goodbye-on-close). If building WSD before mDNS, port that socket discipline inline first.

**Goal:** Make printcap a discoverable, installable WSD printer and receive print jobs over WSPrint, capturing them through the existing sink.

**Architecture:** A WS-Discovery UDP multicast responder + a SOAP HTTP server (default port 3911) dispatching by `wsa:Action` to WS-Transfer `Get` (metadata) and the WSPrint operations; `SendDocument` carries the document as an MTOM/XOP attachment.

**Tech Stack:** Go 1.26 stdlib only — `encoding/xml`, `net/http`, `net` (UDP multicast), `mime`, `mime/multipart`, `crypto/sha1` (SHA-1-derived stable device UUID; `crypto/rand` is not needed since the UUID is deterministic).

**References:** WS-Discovery 1.1, WS-Addressing 1.0, WS-Transfer, DPWS 1.1, the WSD/PWG **Print Service** schema, SOAP MTOM/XOP.

---

## Stage 0 — Config, UUID, listener skeleton

### Task 0.1: WSDConf + flag + skeleton

**Files:** Modify `config.go`, `main.go`, `engine.go`; Create `wsd.go`, `wsd_test.go`.

- [ ] **Step 1: Failing test**

```go
package main

import "testing"

func TestWSDDefaults(t *testing.T) {
    cfg = defaultConfig()
    if cfg.WSD.Enabled || cfg.WSD.Port != 3911 || !cfg.WSD.Discovery {
        t.Fatalf("unexpected WSD defaults: %+v", cfg.WSD)
    }
}

func TestDeviceUUIDStable(t *testing.T) {
    a := deviceUUID("printhost")
    b := deviceUUID("printhost")
    if a != b || len(a) != len("urn:uuid:00000000-0000-0000-0000-000000000000") {
        t.Fatalf("uuid unstable/malformed: %q vs %q", a, b)
    }
}
```

- [ ] **Step 2:** `go test ./... -run 'TestWSDDefaults|TestDeviceUUID' -v` → FAIL.
- [ ] **Step 3:** Implement:
  - `config.go`: `WSDConf{Enabled bool; Port int; Discovery bool}`, `Config.WSD`,
    defaults `{Enabled:false, Port:3911, Discovery:true}`.
  - `main.go`: `flag.Bool("wsd", false, "enable the WSD print service")`, and add a
    `case "wsd": cfg.WSD.Enabled = true` arm in the `flag.Visit` switch inside
    `applyFlagOverrides()`.
  - `wsd.go`: `deviceUUID(host)` = `"urn:uuid:" + uuidV5FromHost(host)` (derive a
    stable UUID from a SHA-1 of host, formatted 8-4-4-4-12); engine start/stop stubs
    `startWSD()`/`(*wsdServer).Close()`.
    > Note: ideally set the RFC-4122 version (5) and variant bits on the SHA-1
    > digest; "stable + well-formed" is acceptable for a device EPR if you skip them.
  - `engine.go`: `if cfg.WSD.Enabled { if w := startWSD(); w != nil { e.closers = append(e.closers, w) } }`.
- [ ] **Step 4:** PASS; `go build ./...` clean.
- [ ] **Step 5:** Commit `feat(wsd): config, -wsd flag, stable device UUID`.

---

## Stage 1 — SOAP / WS-Addressing codec (foundational, fully coded)

### Task 1.1: Envelope + Addressing headers (`wsd_soap.go`)

**Files:** Create `wsd_soap.go`, `wsd_soap_test.go`.

- [ ] **Step 1: Failing test**

```go
package main

import "testing"

func TestSOAPRoundTrip(t *testing.T) {
    env := soapEnvelope{
        Action:    "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get",
        MessageID: "urn:uuid:1111",
        To:        "urn:uuid:dev",
        RelatesTo: "",
        BodyXML:   []byte("<wprt:GetPrinterElements/>"),
    }
    raw := buildSOAP(env)
    got, ok := parseSOAP(raw)
    if !ok {
        t.Fatal("parseSOAP ok=false")
    }
    if got.Action != env.Action || got.MessageID != env.MessageID {
        t.Fatalf("addressing headers lost: %+v", got)
    }
}
```

- [ ] **Step 2:** Run → FAIL (`undefined: soapEnvelope`).
- [ ] **Step 3:** Implement `soapEnvelope` + `buildSOAP`/`parseSOAP` using
  `encoding/xml` with the SOAP 1.2 + WS-Addressing 1.0 namespaces; extract
  `wsa:Action`/`MessageID`/`To`/`RelatesTo` from the header and return the raw Body
  inner XML.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(wsd): SOAP 1.2 + WS-Addressing envelope codec`.

---

## Stage 2 — WS-Discovery (fully coded)

### Task 2.1: Discovery responder (`wsd_discovery.go`)

**Files:** Create `wsd_discovery.go`, `wsd_discovery_test.go`.

- [ ] **Step 1: Failing test** — feed a WS-Discovery **Probe** SOAP body targeting
  `Types = wprt:PrintDeviceType` to `handleProbe([]byte(...))` (single `[]byte`
  argument); assert it returns a **ProbeMatches** containing our EPR (`deviceUUID`)
  and an `XAddrs` pointing at the SOAP endpoint URL. A Probe for an unrelated type
  returns no match.

```go
import "bytes"

func TestProbeMatchesPrinter(t *testing.T) {
    cfg = defaultConfig()
    wsdEndpoint = "http://192.0.2.10:3911/wsd"
    resp, matched := handleProbe([]byte(`<d:Probe xmlns:d="..."><d:Types>wprt:PrintDeviceType</d:Types></d:Probe>`))
    if !matched {
        t.Fatal("printer probe should match")
    }
    if !bytes.Contains(resp, []byte("ProbeMatches")) || !bytes.Contains(resp, []byte(wsdEndpoint)) {
        t.Fatalf("missing ProbeMatches/XAddrs: %s", resp)
    }
}
```

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `handleProbe`/`handleResolve` building ProbeMatches/
  ResolveMatches per WS-Discovery 1.1 (Types `wsdp:Device wprt:PrintDeviceType`,
  the EPR, `MetadataVersion`, `XAddrs`), plus `helloMessage()`/`byeMessage()`.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(wsd): WS-Discovery Probe/Resolve/Hello/Bye`.

### Task 2.2: Discovery UDP responder runtime (`wsd_discovery.go`)

- [ ] **Step 1:** Implement the multicast socket (`239.255.255.250:3702` v4 /
  `ff02::c:3702` v6 via `net.ListenMulticastUDP`, same discipline/graceful-degrade
  as `mdns.go`): on start send Hello, answer Probe/Resolve, on Close send Bye.
  See the mDNS plan's multicast responder for the exact socket pattern (dual-stack
  bind, graceful degrade on `EADDRINUSE`, goodbye-on-close) — reuse it here.
- [ ] **Step 2:** `go build ./...` clean; the unit logic is covered by 2.1 (multicast
  I/O is exercised in manual acceptance).
- [ ] **Step 3:** Commit `feat(wsd): WS-Discovery multicast responder`.

---

## Stage 3 — Metadata & SOAP HTTP server

### Task 3.1: Device/print metadata (`wsd_metadata.go`)

- [ ] **Step 1: Failing test** — `buildMetadata()` returns a WS-Transfer `Get`
  response (Metadata sections: ThisDevice, ThisModel, Relationship→hosted
  PrintService) embedding `cfg.Printer.Name`/`MakeAndModel`; assert those values
  and the PrintService EPR are present.
- [ ] **Step 2–5:** Implement per DPWS metadata schema. Commit `feat(wsd): device + print-service metadata`.

### Task 3.2: SOAP HTTP server + Action dispatch (`wsd.go`)

- [ ] **Step 1: Failing test** — POST a WS-Transfer `Get` SOAP request to the
  handler; assert a 200 with the metadata envelope. An unknown Action returns a
  SOAP `wsa:ActionNotSupported` fault.
- [ ] **Step 2–5:** Implement an `http.Handler` at `/wsd` dispatching by
  `wsa:Action` to metadata (Stage 3.1) and WSPrint (Stage 4); start it on
  `cfg.WSD.Port` from `startWSD()`. Commit `feat(wsd): SOAP HTTP endpoint + dispatch`.

---

## Stage 4 — MTOM + WSPrint capture

### Task 4.1: MTOM/XOP attachment reader (`mtom.go`)

**Files:** Create `mtom.go`, `mtom_test.go`.

- [ ] **Step 1: Failing test** — given a `multipart/related` body (root SOAP part
  referencing an attachment via `<xop:Include href="cid:doc"/>` and a second part
  with `Content-ID: <doc>` carrying bytes), `extractMTOM(contentType, body)`
  returns the root XML and the exact attachment bytes keyed by CID.

```go
import "bytes"

func TestExtractMTOM(t *testing.T) {
    ct := `multipart/related; boundary=BND; type="application/xop+xml"; start="<root>"`
    body := "--BND\r\nContent-ID: <root>\r\n\r\n<env><xop:Include href=\"cid:doc\"/></env>\r\n" +
        "--BND\r\nContent-ID: <doc>\r\n\r\nDOCBYTES\r\n--BND--\r\n"
    root, parts, err := extractMTOM(ct, []byte(body))
    if err != nil {
        t.Fatal(err)
    }
    if string(parts["doc"]) != "DOCBYTES" || !bytes.Contains(root, []byte("Include")) {
        t.Fatalf("root=%s parts=%v", root, parts)
    }
}
```

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `extractMTOM` using `mime.ParseMediaType` +
  `multipart.NewReader`, mapping `Content-ID` (stripping `<>`) → bytes and returning
  the `start` root part.
- [ ] **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(wsd): MTOM/XOP attachment extraction`.

### Task 4.2: WSPrint operations → capture (`wsprint.go`)

- [ ] **Step 1: Failing test** — POST a `CreatePrintJob` then a `SendDocument`
  (MTOM) to the handler; assert a `job{Protocol:"WSD", JobName, User, DocFormat,
  data}` is captured (stubbed sink) with the attachment bytes, and the SOAP
  responses carry a JobId / success.
- [ ] **Dispatch keys (deterministic):** the WSD Print Service namespace is
  `http://schemas.microsoft.com/windows/2006/08/wdp/print` (prefix `wprt`). The
  canonical `wsa:Action` URIs are `<wprt-namespace>/<OperationName>`, i.e.:
  - `http://schemas.microsoft.com/windows/2006/08/wdp/print/CreatePrintJobRequest`
  - `http://schemas.microsoft.com/windows/2006/08/wdp/print/SendDocumentRequest`
  - `http://schemas.microsoft.com/windows/2006/08/wdp/print/GetPrinterElementsRequest`
  - `http://schemas.microsoft.com/windows/2006/08/wdp/print/GetJobElementsRequest`

  Use these as the `wsa:Action` dispatch keys. Confirm the exact strings against the
  WSD Print Service schema before finalizing.
- [ ] **Step 2–5:** Implement `GetPrinterElements`, `CreatePrintJob` (allocate a
  JobId, read `JobDescription`), `SendDocument` (extract the MTOM doc, build the
  job, `sink.save`), `GetJobElements` (report completed), per the WSD Print Service
  schema. Then `go test ./... && go build ./... && go vet ./...`; `git diff --
  go.mod go.sum` empty. Commit `feat(wsd): WSPrint CreatePrintJob/SendDocument capture`.

---

## Stage 5 — Docs & manual acceptance

### Task 5.1: Docs

- [ ] README "WSD (Windows network discovery & print)" section: enable `-wsd`,
  default port 3911, that Windows **Add a device** discovers/installs it, and jobs
  capture as `WSD`. ADMIN_GUIDE §8 `wsd` block + §19 acceptance step. Commit
  `docs(wsd): document WSD discovery and print`.

### Task 5.2: Manual acceptance

- [ ] On Windows: **Settings → Add a device** discovers printcap; install it; print
  a test page; confirm a `WSD` job is captured with user/job-name/format and exact
  bytes, flowing through PDL detection + forwarding. Stop printcap → the device
  disappears (Bye). With UDP 3702 already owned, confirm discovery degrades
  gracefully while a direct XAddr still serves metadata/print.

---

## Self-Review notes (plan author)

- **Spec coverage:** §3 architecture → Stages 0–4; §4 config → Stage 0; §5 capture
  mapping → Task 4.2; §6 logging → woven in (`[WSD]`); §7 testing → each task's
  Step 1; §8 acceptance → Stage 5.
- **Verifiable anchors:** SOAP/Addressing round-trip, Probe→ProbeMatches, MTOM
  extraction, and the WSPrint capture integration test lock each layer.
- **Staging honesty:** WSPrint operation bodies are specified against the WSD Print
  Service schema + a locking test rather than fully inlined — a deliberate,
  communicated staging decision, not silent placeholders. Each stage ships behind
  the default-off `-wsd` flag.
- **Reuse:** the discovery multicast socket mirrors `mdns.go`; the SOAP endpoint can
  share the engine's HTTP hardening (`hardenedServer`).
- **Dependency guard:** Task 4.2 asserts `go.mod`/`go.sum` unchanged (stdlib only).
```
