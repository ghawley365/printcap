# Design — SMB2/3 print-share capture (full)

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Track:** Legacy/ERP/Linux protocol expansion — **spec #4 of 5**
  (split from the original SMB/WSD item; WSD is now spec #5)
- **Approach:** Hand-rolled SMB2/3 server + NTLMv2 + DCERPC + MS-RPRN spoolss,
  pure stdlib, **experimental**, on a configurable non-445 port.

> **Scale warning.** This is the largest feature in the roadmap — a real SMB2/3
> server with authentication and the Windows print RPC. It is staged (see the
> plan) and shipped behind a default-off, clearly-experimental flag. The zero
> dependency promise is preserved (all crypto is Go stdlib), but the surface is
> large; treat each stage as independently shippable.

## 1. Problem & goal

Many legacy Windows/ERP environments print to a **Windows print share**
(`\\host\printer`) rather than to 9100/LPD/IPP. printcap has no SMB path.

**Goal:** accept and capture a print job delivered over SMB to a shared printer
name, modeling enough of SMB2/3 + NTLMv2 + the Print System Remote Protocol
(spoolss over the `\spoolss` named pipe) to receive the spool bytes with metadata
(submitting user, document name), feeding them into the existing capture sink.

## 2. Hard constraints & decisions

- **Port:** **always a configurable non-standard port** (default `4445`); printcap
  never attempts 445 (the OS owns it on Windows). Clients reach it via
  `\\host:4445\...` where supported, or via Linux `smbclient` with a port option.
  This limitation is documented prominently.
- **Auth:** **guest + NTLMv2**. Anonymous/guest is accepted; NTLMv2
  challenge-response is implemented for authenticated clients (per [MS-NLMP]).
- **Depth:** **full SMB2/3 print server** — SMB2 dialects 2.0.2–3.1.1 negotiate,
  session setup (NTLMv2), tree connect to `IPC$`, create/write/read on the
  `\spoolss` named pipe, DCERPC bind, and the MS-RPRN print sequence
  (`RpcOpenPrinterEx`/`RpcStartDocPrinter`/`RpcWritePrinter`/`RpcEndDocPrinter`/
  `RpcClosePrinter`). SMB3 encryption (AES-CCM/GCM) and SMB2 signing
  (AES-CMAC/HMAC-SHA256) are supported so 3.x clients that require them work.
- **Read-only sharing:** printcap exposes exactly one printer share (named from
  `printer.name`) and `IPC$`; it is **not** a general file server.

## 3. Architecture

A new listener like the others (`engine.go` adds an `addTCP("SMB", port, serveSMB)`
when enabled). All SMB code is platform-neutral (pure stdlib), so it builds and
runs on Windows (alternate port), Linux, and macOS.

### New files (staged; see plan)

- **`smb_frame.go`** — NetBIOS/Direct-TCP framing (4-byte length prefix) and the
  SMB2 header (MS-SMB2 §2.2.1) parse/build; per-connection state.
- **`smb_negotiate.go`** — SMB2 NEGOTIATE (dialect selection, capabilities,
  negotiate contexts for 3.1.1 preauth-integrity + ciphers).
- **`ntlm.go`** — NTLMv2 (MS-NLMP): NEGOTIATE/CHALLENGE/AUTHENTICATE messages,
  NTOWFv2, the NTLMv2 response + session base key, and guest fallback.
- **`smb_session.go`** — SESSION_SETUP (wraps NTLM), signing key derivation, and
  optional SMB3 encryption keys (SP800-108 KDF).
- **`smb_tree.go`** — TREE_CONNECT to `IPC$` and the printer share; CREATE/READ/
  WRITE/CLOSE routed to the named pipe.
- **`dcerpc.go`** — DCERPC bind + request/response fragmenting over the pipe.
- **`spoolss.go`** — the MS-RPRN opnums needed to receive a job; assembles the
  document bytes and hands a `job` to `sink.save` (Protocol `"SMB"`, `User` from
  the authenticated identity, `JobName` from `RpcStartDocPrinter`'s `pDocInfo`).
- **`smb.go`** — `serveSMB(ln)` accept loop + per-connection dispatch tying the
  above together; connection state machine.

### Modified files

- **`config.go`** — `SMBConf` (`enabled`, `port`, `share_name`, `require_auth`,
  `users` for NTLMv2, `sign`, `encrypt`).
- **`engine.go`** — start the SMB listener when enabled.
- **`main.go`** — `-smb` flag.

## 4. Configuration

```jsonc
"smb": {
  "enabled": false,
  "port": 4445,                 // never 445
  "share_name": "",             // blank = printer.name
  "require_auth": false,        // false = allow guest; true = NTLMv2 required
  "sign": true,                 // honor/enforce SMB2 signing when client asks
  "encrypt": true,              // allow SMB3 encryption
  "users": [                    // NTLMv2 credentials accepted
    { "user": "print", "password": "secret", "domain": "WORKGROUP" }
  ]
}
```

User passwords are **secrets** → redacted in `/api/config` (extend
`redactedConfig`).

## 5. Capture mapping

A completed spoolss job produces a `job{Protocol:"SMB", Source:<remote>,
User:<auth user or "guest">, JobName:<pDocInfo.pDocName>, Queue:<share>,
data:<spool bytes>}` handed to `sink.save`, so PDL detection, save modes, the
dashboard, **and forwarding** all apply automatically.

## 6. Security

- Default **off** and **experimental**; documented limitations (non-445 port,
  no general file access, single printer share).
- Guest is allowed only when `require_auth:false`; NTLMv2 verified against
  configured `users` otherwise.
- Signing/encryption honored per client negotiation; never downgrade below what
  the client requires.
- The server exposes only `IPC$` + the one printer share; CREATE on any other
  path is refused (`STATUS_ACCESS_DENIED`).

## 7. Logging

Component `[SMB]`: `info` session established (user, dialect, signed/encrypted),
job captured; `warn` auth failure, unsupported dialect, refused path; `debug`
each SMB2 command + DCERPC opnum; `trace` raw PDU sizes. Never log password
material or session keys.

## 8. Testing

- **NTLMv2 (MS-NLMP §4.2 vectors):** NTOWFv2 and the NTLMv2 response computed for
  the spec's canonical user/password/domain/challenge match the published bytes.
- **SMB2 framing:** header parse/build round-trip; NEGOTIATE dialect selection for
  a 3.1.1 client request fixture.
- **DCERPC:** bind + a spoolss request fragment parse/build round-trip.
- **spoolss sequence:** a scripted `RpcStartDocPrinter`→`RpcWritePrinter`(xN)→
  `RpcEndDocPrinter` over an in-memory pipe yields the concatenated document and a
  populated `job`.
- **Integration (Linux/macOS, CI-capable):** drive the server with Go's own client
  bytes (the test constructs SMB2 PDUs) through `serveSMB` over a loopback
  connection and assert a job is captured. (A `smbclient` end-to-end is manual
  acceptance.)

## 9. Acceptance criteria

1. From Linux `smbclient //host/PRINTER -p 4445` (guest, then NTLMv2), a printed
   file is captured as an `SMB` job with the submitting user and document name.
2. SMB2 dialects 2.0.2–3.1.1 negotiate; a 3.1.1 client requiring encryption/signing
   succeeds.
3. `require_auth:true` rejects guest; wrong NTLMv2 credentials are refused with no
   capture.
4. Captured SMB jobs flow through PDL detection, save modes, dashboard, and
   forwarding like any other protocol.
5. `/api/config` redacts SMB user passwords.
6. No new module dependency (stdlib crypto/xml only); default-off; clearly
   documented as experimental and non-445.

## 10. Out of scope (YAGNI)

General file sharing, multiple shares, DFS, leases/oplocks beyond what a print
client needs, Kerberos (NTLMv2 only), SMB1, and printer *management* RPCs beyond
the job-submission opnums.
```
