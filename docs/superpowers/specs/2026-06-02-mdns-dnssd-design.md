# Design — mDNS/DNS-SD advertisement for printcap

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Track:** Legacy/ERP/Linux protocol expansion — **spec #1 of 4**
  (mDNS/DNS-SD → Mainframe EBCDIC+LPD → SNMPv3 → SMB/WSD)
- **Approach:** A — built-in, hand-rolled responder, pure stdlib, zero new dependencies

## 1. Problem & goal

printcap already *accepts* print jobs on every common transport (Raw/9100, LPR/LPD,
IPP/IPPS) but is only *discoverable* via SNMP. On Linux/CUPS, macOS, and iOS, clients
locate printers through **mDNS/DNS-SD (Bonjour)**, not SNMP. Without it, users must add
printcap by hand (IP + protocol + port).

**Goal:** make printcap auto-discoverable as a driverless printer on Windows, Linux/CUPS,
macOS, and iOS/AirPrint, while preserving its defining identity — a single static
executable with zero runtime dependencies and hand-rolled wire protocols.

**Non-goals (YAGNI):** DNS name compression in responses; hot-reconfigure of mDNS without an
engine restart (Save & Restart covers it); Wide-Area / unicast DNS-SD; GUI controls (these
land in the later "modern UI" track — config + console are fully functional now).

## 2. Constraints

- **Pure stdlib, zero new dependencies.** Consistent with the hand-rolled SNMP BER (`snmp.go`)
  and IPP (`ipp.go`) encoders; preserves the single-exe, minimal-dependency design the audit
  highlighted.
- **Portable, mostly Windows.** Windows 10+ ships an mDNS resolver and an installed Apple
  Bonjour service may already hold UDP 5353; macOS (`mDNSResponder`) and many Linux hosts
  (`avahi`) own it too. The responder must coexist or degrade gracefully — never fatal.
- **Single source of truth.** TXT values that duplicate IPP attributes (notably `URF`) must be
  derived from the same config that drives the IPP `Get-Printer-Attributes` response, so the
  two transports never drift.

## 3. Architecture

Slots into the existing "Engine owns every listener" model exactly like the SNMP agent.

### New files (one concern per file, matching the existing layout)

- **`dnsmsg.go`** — hand-rolled DNS wire encode/decode: questions and `PTR`/`SRV`/`TXT`/`A`/`AAAA`
  resource records. No name compression on responses (mDNS permits uncompressed). Same spirit
  as the BER primitives in `snmp.go`. Independently unit-testable.
- **`dnssd.go`** — the service model: the single place that reads `cfg`. Turns the live config
  plus the set of listeners that actually bound into the DNS-SD services and their TXT records.
- **`mdns.go`** — the responder: opens the multicast socket(s), runs the query/answer loop,
  and performs probe/announce/goodbye. Exposes `serveMDNS(...)`, analogous to `serveSNMP`.

### Engine integration (`engine.go`)

- After listeners come up, `Start()` calls `startMDNS(active)` and appends the responder to
  `e.closers`. **Only listeners that actually bound are advertised** (never announce a service
  that failed to bind).
- `Stop()` triggers **goodbye** packets (records at TTL 0) before the socket closes — clean
  withdrawal, matching the existing graceful-shutdown style.

### Config surface (`config.go`)

New `MDNSConf` added to `Config`, with an entry in `defaultConfig()`:

```jsonc
"mdns": {
  "enabled": true,        // master switch (also -mdns flag)
  "instance": "",         // service instance name; blank = printer.name
  "hostname": "",         // advertised <host>.local; blank = sanitized printer.name
  "airprint": true        // advertise the _universal sub-type + AirPrint TXT keys
}
```

- A `-mdns` bool flag is added for parity with the other listener flags (wired through
  `applyFlagOverrides`).
- No secrets, so no `/api/config` redaction needed.
- GUI wiring is deferred to the "modern UI" track.

## 4. What gets advertised

### Service types — auto-mirrored to bound listeners

Advertise a service only if its listener is up:

| Listener up                    | DNS-SD service          | Port               |
|--------------------------------|-------------------------|--------------------|
| IPP (or auto-TLS plaintext)    | `_ipp._tcp`             | IPP / auto-TLS port|
| IPPS (or auto-TLS)             | `_ipps._tcp`            | IPPS / auto-TLS port|
| Raw/9100                       | `_pdl-datastream._tcp`  | 9100               |
| LPD                            | `_printer._tcp`         | 515                |

Each service publishes the standard DNS-SD record set:
- browse `PTR`: `_ipp._tcp.local → <instance>._ipp._tcp.local`
- `SRV`: target `<host>.local`, the service port
- `TXT`: keys per the tables below
- `A` / `AAAA` for `<host>.local`

### AirPrint (when `airprint: true`)

- Register the `_universal._sub._ipp._tcp` (and `_ipps`) **sub-type PTR** pointing at the
  IPP/IPPS instance — the marker iOS requires.
- Also emit the `_cups._sub._ipp._tcp` browse sub-type so CUPS servers list it.

### Instance & host naming

- Instance defaults to `printer.name` ("printcap"); host defaults to a sanitized
  `printer.name` → `printcap.local`.
- **Name-collision handling (RFC 6762 §9):** lightweight probing — query the proposed name
  first; if answered, append ` (2)`, ` (3)`, … and re-probe (best-effort).

### TXT records — derived from `cfg.Printer`

IPP-only keys appear **only** on the IPP/IPPS services, never on socket/LPD (per the Bonjour
Printing Specification).

**`_ipp` / `_ipps`:**
`txtvers=1`, `qtotal=1`, `rp=ipp/print` (from `ipp_options.default_path`, leading slash
stripped), `ty=<make_and_model>`, `product=(<make_and_model>)`, `note=<location>`,
`pdl=<document_formats joined>`, `UUID=<printer-uuid>`, `adminurl=http://<host>:<dash>/`,
`Color=T|F` (from `printer.color`), `Duplex=T|F` (from `sides`), `URF=<urf string>` (mapped
from the `urf-supported` value already advertised in `ipp.go` — **required for AirPrint**),
`kind=document`; on `_ipps` add `TLS=1.2`.

**`_pdl-datastream` (9100):**
`txtvers=1`, `qtotal=1`, `ty`, `product`, `note`, `pdl`, `Transparent=T`, `Binary=T`.
No IPP-only keys.

**`_printer` (LPD):**
`txtvers=1`, `qtotal=1`, `rp=auto`, `ty`, `note`. No IPP-only keys.

> **Single source of truth:** the `URF` TXT value is mapped from the same `urf-supported`
> string printcap returns over IPP, so Bonjour and IPP never disagree about capabilities.

### Address selection

- `bind` is a specific IP → advertise that address.
- `bind = 0.0.0.0` / `::` → advertise all non-loopback interface IPv4/IPv6 addresses, so
  discovery works on whatever subnet the client is on.

## 5. Responder behavior

- **Socket:** open UDP `224.0.0.251:5353` (IPv4) and `ff02::fb:5353` (IPv6) via stdlib
  `net.ListenMulticastUDP` (sets `SO_REUSEADDR`, joins the group — no `x/net` dependency).
- **Query loop:** decode the DNS questions; for any question matching one of our names/service
  types, send the matching records. Honor the **QU bit** (unicast-response requested → reply
  unicast; else reply to the multicast group). Respect **known-answer suppression** best-effort
  (skip records already present in the query's answer section).
- **Lifecycle:** on start, lightweight **probe** for name collision, then **announce** (send
  unsolicited responses for all records, twice ~1 s apart, per RFC 6762); on stop, **goodbye**
  (same records at TTL 0).
- **Coexistence / degradation:** if 5353 can't be opened (Windows resolver / installed Bonjour
  holds it), `logWarn` and **disable mDNS without affecting any other listener** — never fatal.
  IPv6 socket failure is tolerated independently (IPv4 still serves). Join the group per usable
  interface; per-interface failures are logged at debug and skipped.

## 6. Error handling & logging

Uses the existing leveled, per-component logger with tag `[mDNS]`:

- `info`: "advertising N services as %q via mDNS" / "withdrawn".
- `warn`: 5353 unavailable (with the OS error); name-collision rename.
- `debug`: per-interface join results; announce/goodbye sent.
- `trace`: each query answered (question name/type + responder peer) — mirrors per-OID SNMP
  tracing.

## 7. Testing

**Unit (CI-friendly, no multicast required):**
- `dnsmsg.go` encode/decode round-trip for each record type (`PTR`/`SRV`/`TXT`/`A`/`AAAA`) and
  question parsing.
- TXT-builder table tests asserting exact keys per service — in particular `URF` **present** on
  `_ipp`/`_ipps` and **absent** on `_printer`/`_pdl-datastream`.
- Responder query→selected-records test driven with a crafted question over a loopback /
  in-memory `net.PacketConn`.
- Instance-rename-on-collision test.

**Manual acceptance (documented in the spec and ADMIN_GUIDE):**
- `dns-sd -B _ipp._tcp` (macOS) / `avahi-browse -rat` (Linux) shows printcap.
- `ippfind` resolves it.
- iOS "Print" sheet lists it (validates the AirPrint sub-type + `URF`).
- CUPS end-to-end: `lpadmin -E -v "$(ippfind)" -m everywhere` then `lp <file>` captures a job.

## 8. Affected files (summary)

- **New:** `dnsmsg.go`, `dnssd.go`, `mdns.go`, plus `*_test.go` for the unit tests above.
- **Modified:** `config.go` (`MDNSConf`, defaults), `main.go` (`-mdns` flag + override),
  `engine.go` (start/stop integration), `README.md` + `ADMIN_GUIDE.md` (discovery section,
  acceptance steps).

## 9. Acceptance criteria

1. With defaults, a macOS/Linux/iOS client on the same subnet discovers printcap without manual
   setup, and a driverless ("everywhere") queue created from that discovery successfully
   delivers a captured job.
2. iOS Print lists printcap (AirPrint sub-type + `URF` validated).
3. Only listeners that actually bound are advertised; disabling a protocol removes its service.
4. If UDP 5353 is unavailable, mDNS logs a warning and disables itself; all other listeners run
   normally.
5. On stop, goodbye packets withdraw the services (clients drop it promptly).
6. No new module dependencies in `go.mod`; the build remains a single static exe.
