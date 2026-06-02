# Design — WSD print service (full)

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Track:** Legacy/ERP/Linux protocol expansion — **spec #5 of 5**
  (split from the original SMB/WSD item)
- **Approach:** Hand-rolled DPWS/WSD stack — WS-Discovery (SOAP-over-UDP) +
  WS-Transfer metadata + WSPrint SOAP PrintService with MTOM — pure stdlib
  (`encoding/xml`, `net/http`, UDP multicast).

> **Scale warning.** A full WSD print service is a large SOAP stack
> (WS-Addressing, WS-Discovery, WS-Transfer, WSPrint, MTOM/XOP). Staged and
> default-off. Zero new dependencies (stdlib XML/HTTP/UDP).

## 1. Problem & goal

Windows discovers and installs network printers natively via **WSD** ("Add a
device"). printcap is invisible to that path.

**Goal:** make printcap a discoverable, installable WSD printer and **receive
print jobs over the WSPrint SOAP service**, capturing them through the existing
sink. Full WSD: discovery + metadata so Windows installs it, and the print
operations so jobs flow over WSD itself (per the brainstorming choice).

## 2. Decisions (from brainstorming)

- **Full WSD print service**: WS-Discovery advertisement/response **and** the
  WSPrint `CreatePrintJob`/`SendDocument` operations (document delivered as an
  MTOM/XOP binary attachment).
- Discovery and the SOAP endpoint run on all platforms (UDP multicast + an HTTP
  listener); jobs captured as Protocol `"WSD"`.

## 3. Architecture

Two cooperating listeners started by the engine:
1. **WS-Discovery responder** — UDP multicast `239.255.255.250:3702` (IPv4) and
   `ff02::c:3702` (IPv6); same socket discipline as the mDNS responder (stdlib
   `net.ListenMulticastUDP`, graceful degrade if the port is taken).
2. **WSD SOAP HTTP server** — a dedicated port (default `3911`) serving
   WS-Transfer `Get` (device/model/relationship/hosted-service metadata) and the
   WSPrint operations, dispatched by the `wsa:Action` SOAP header.

### New files (staged; see plan)

- **`wsd.go`** — orchestration: a stable device `urn:uuid:`, endpoint references,
  start/stop of the discovery responder and SOAP server.
- **`wsd_soap.go`** — SOAP envelope + WS-Addressing header parse/build (shared by
  discovery and the HTTP service); `encoding/xml` structs.
- **`wsd_discovery.go`** — Hello/Bye (announce on start/stop), Probe→ProbeMatches,
  Resolve→ResolveMatches; advertises Types `wsdp:Device wprt:PrintDeviceType` and
  XAddrs (the SOAP endpoint URL).
- **`wsd_metadata.go`** — ThisDevice/ThisModel + Relationship listing the hosted
  **PrintService**, built from `cfg.Printer`.
- **`wsprint.go`** — WSPrint operations: `GetPrinterElements`, `CreatePrintJob`,
  `SendDocument` (parse the MTOM/XOP attachment to recover the document bytes),
  `GetJobElements`; hands the captured bytes to `sink.save`.
- **`mtom.go`** — minimal MIME multipart/related (MTOM/XOP) reader using
  `mime/multipart`, resolving the `xop:Include` href to its binary part.

### Modified files

- **`config.go`** — `WSDConf` (`enabled`, `port`, `discovery`).
- **`engine.go`** — start discovery + SOAP server when enabled.
- **`main.go`** — `-wsd` flag.

## 4. Configuration

```jsonc
"wsd": {
  "enabled": false,
  "port": 3911,        // SOAP HTTP endpoint
  "discovery": true    // run the WS-Discovery multicast responder
}
```

No secrets → no redaction needed.

## 5. Capture mapping

A `SendDocument` with its MTOM attachment yields `job{Protocol:"WSD",
Source:<remote>, JobName:<JobDescription/JobName>, User:<JobOriginatingUserName>,
DocFormat:<Format>, data:<attachment bytes>}` → `sink.save`, so PDL detection,
save modes, dashboard, and forwarding all apply.

## 6. Logging

Component `[WSD]`: `info` discovered/probed by <peer>, job captured; `warn`
malformed SOAP, unsupported Action, MTOM parse failure; `debug` each Action;
`trace` envelope sizes. Graceful degrade if UDP 3702 is unavailable (log + disable
discovery, keep the SOAP server).

## 7. Testing

- **SOAP/WS-Addressing:** envelope + header build/parse round-trip; Action
  dispatch table.
- **WS-Discovery:** a Probe for `wprt:PrintDeviceType` yields a ProbeMatches with
  our EPR + XAddrs; Resolve yields ResolveMatches.
- **Metadata:** `Get` returns ThisDevice/ThisModel and a Relationship that lists
  the PrintService with the configured make/model.
- **MTOM:** a crafted multipart/related body with an `xop:Include` resolves to the
  exact attachment bytes.
- **WSPrint integration:** scripted `CreatePrintJob`→`SendDocument` POSTs to the
  handler produce a captured `WSD` job with the right metadata and document bytes.

## 8. Acceptance criteria

1. On a Windows client, **Add a device** discovers printcap (WS-Discovery +
   metadata) and installs it as a WSD printer.
2. Printing to that queue delivers the document over WSPrint; it is captured as a
   `WSD` job with user/job-name/format and the exact bytes.
3. Captured WSD jobs flow through PDL detection, save modes, dashboard, and
   forwarding.
4. Hello on start and Bye on stop are observed by a WS-Discovery listener
   (`wsd-discovery` tools / Windows function discovery).
5. If UDP 3702 is unavailable, discovery disables gracefully; the SOAP service
   still serves metadata/print to clients given the direct XAddr.
6. No new module dependency (stdlib XML/HTTP/MIME/UDP); default-off.

## 9. Out of scope (YAGNI)

WS-Eventing/status subscriptions, WS-Security, scan/fax services, bidirectional
status beyond a static "idle/ready", and IPv6-only discovery edge cases beyond
basic dual-stack.
```
