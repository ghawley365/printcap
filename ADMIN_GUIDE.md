# printcap — Administrator Guide

A complete operational reference for deploying, configuring, securing, and
troubleshooting **printcap**, a self-contained network print-capture server for
Windows.

---

## Table of contents

1. [What printcap is](#1-what-printcap-is)
2. [System requirements](#2-system-requirements)
3. [Installation & deployment](#3-installation--deployment)
4. [Quick start](#4-quick-start)
5. [Privileged ports, Administrator, and the firewall](#5-privileged-ports-administrator-and-the-firewall)
6. [Configuration model](#6-configuration-model)
7. [Command-line flag reference](#7-command-line-flag-reference)
8. [Config file reference](#8-config-file-reference)
9. [Protocols in detail](#9-protocols-in-detail)
10. [Connecting print clients](#10-connecting-print-clients)
11. [SNMP discovery](#11-snmp-discovery)
12. [The web dashboard & JSON API](#12-the-web-dashboard--json-api)
13. [Captured output on disk](#13-captured-output-on-disk)
14. [Security & hardening](#14-security--hardening)
15. [Running as a Windows service](#15-running-as-a-windows-service)
16. [Logging & monitoring](#16-logging--monitoring)
17. [Performance & resource limits](#17-performance--resource-limits)
18. [Troubleshooting](#18-troubleshooting)
19. [Acceptance test procedure](#19-acceptance-test-procedure)
20. [Upgrade & uninstall](#20-upgrade--uninstall)
21. [Appendix A — SNMP OID map](#appendix-a--snmp-oid-map)
22. [Appendix B — IPP attributes advertised](#appendix-b--ipp-attributes-advertised)

---

## 1. What printcap is

printcap impersonates a network printer across every common print transport,
**captures the raw spool data** any host sends it, and is **discoverable**
(SNMP) and **observable** (web dashboard). Point a print queue at the machine
running printcap and every job that queue submits is written to disk with
metadata (who, when, from where, in what format).

| Capability | Default | Protocol |
|-----------|--------:|----------|
| Raw / JetDirect / AppSocket | TCP 9100 | Plain byte stream |
| LPR / LPD | TCP 515 | RFC 1179 |
| IPP | TCP 631 | IPP-over-HTTP |
| IPPS | TCP 6310 | IPP-over-HTTPS (TLS) |
| SNMP agent | UDP 161 | SNMP v1/v2c |
| Web dashboard | TCP 8631 | HTTP |

**Intended use:** print-infrastructure testing, driver/queue validation, and
authorized print-security assessment on networks you control. It receives jobs
addressed to it and answers SNMP queries about itself — it does **not** sniff or
intercept traffic destined for other devices.

---

## 2. System requirements

* **OS:** Windows 10 / 11 or Windows Server 2016+ (64-bit). The binary is a
  native `amd64` GUI-subsystem executable (also runs headless with `-console`).
* **Privileges:** Administrator only to bind ports below 1024 (515, 631, 161 —
  all on by default) or to install/remove the service. High ports and the GUI
  itself need no elevation.
* **Disk:** the executable is ~11 MB (the native GUI toolkit adds size). Plan
  capture storage according to expected job volume and size (spool files can be
  large — see §17).
* **Runtime:** none. No .NET, no Java, no DLLs, no installer. One `.exe`.
* **Network:** inbound TCP 9100/515/631/6310 and UDP 161 (whichever you enable),
  plus TCP 8631 for the dashboard.

---

## 3. Installation & deployment

printcap is xcopy-deployable.

1. Copy `printcap.exe` to a folder, e.g. `C:\printcap\`.
2. (Optional) Copy a config file alongside it, e.g. `C:\printcap\printcap.json`.
3. Decide where captures go (the `out_dir` / `-out` location). The folder is
   created automatically on first run.

Suggested layout:

```
C:\printcap\
  printcap.exe
  printcap.json        (your edited config)
  captures\            (created automatically)
```

### Building from source (optional)

Requires [Go](https://go.dev/dl/) 1.21+. From the source folder:

```
build.bat
```

or:

```
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w -H windowsgui" -o printcap.exe .
```

`-H windowsgui` builds the GUI subsystem (no console window); `-s -w` strips
debug info. The committed `rsrc_windows_amd64.syso` supplies the embedded
manifest (themed controls + high-DPI); regenerate it only if you edit
`printcap.manifest`.

### Launch modes

The same `printcap.exe` runs three ways:

| How you launch it | What happens |
|-------------------|--------------|
| Double-click (or run with no args) | Opens the **settings GUI** (minimizes to tray) |
| `printcap.exe -console` | Runs **headless** in the console |
| `printcap.exe -service …` / launched by the SCM | Runs as / manages the **Windows service** |

---

## 4. Quick start

### GUI

Double-click **printcap.exe**. The settings window opens. On the **Protocols &
Ports** tab, enable the protocols you want; on **General**, set the capture
directory and save mode. Click **Start**. Closing the window minimizes it to the
system tray (right-click the tray icon for Open / Dashboard / Capture folder /
Exit).

To bind ports below 1024 (515/631/161) or install the service, right-click
printcap.exe → **Run as administrator**.

### Console

From a command prompt in `C:\printcap\` (Administrator for privileged ports):

```
printcap.exe -console
```

This starts every enabled listener, writes jobs to `.\captures\`, runs the SNMP
agent, and serves the dashboard. You'll see:

```
printcap — network print server & spool capture
  printer    : "printcap" (printcap Virtual MFP)
  output dir : C:\printcap\captures  (mode=both)
  listen     : 9100:9100       on 0.0.0.0
  listen     : LPR:515         on 0.0.0.0
  listen     : IPP:631         on 0.0.0.0
  listen     : IPPS:6310       on 0.0.0.0
  listen     : SNMP:161        on 0.0.0.0
  listen     : dashboard:8631  on 0.0.0.0
  dashboard  : http://localhost:8631/
  (Ctrl+C to stop)
```

Open **http://localhost:8631/** and send a test print to the host's IP. The job
appears within ~2 seconds. Stop with **Ctrl+C**.

---

## 5. Privileged ports, Administrator, and the firewall

* **Ports < 1024** (515 LPR, 631 IPP, 161 SNMP) require an **Administrator**
  prompt on Windows. If you run un-elevated, those listeners fail to bind and
  log `listener stopped: ... bind: ... permission denied`; the others keep
  running. High ports (9100, 6310, 8631) need no elevation.
* **Windows Firewall** — printcap can add its own inbound allow rules. Use the
  GUI's **Service & Firewall** tab → *Allow through Firewall*, or the CLI
  (Administrator):

  ```
  printcap.exe -firewall add        :: program-scoped TCP + UDP inbound allow
  printcap.exe -firewall remove
  ```

  These are **program-scoped** (they allow the printcap exe inbound on any port),
  so they keep working if you reconfigure ports. To scope by port instead, add
  rules manually (Administrator PowerShell):

  ```powershell
  New-NetFirewallRule -DisplayName "printcap TCP" -Direction Inbound -Protocol TCP `
    -LocalPort 9100,515,631,6310,8631 -Action Allow
  New-NetFirewallRule -DisplayName "printcap SNMP" -Direction Inbound -Protocol UDP `
    -LocalPort 161 -Action Allow
  ```

* **Port conflicts:** Windows' own *Print Spooler* / LPD service or an existing
  IPP/SNMP service may already own 515/631/161. Stop the conflicting service or
  move printcap to alternate ports (see §7). The Windows SNMP Service in
  particular will hold UDP 161.

---

## 6. Configuration model

Settings are resolved in three layers, each overriding the previous:

```
built-in defaults  →  JSON config file (-config)  →  command-line flags
        (lowest priority)                              (highest priority)
```

* **Defaults** are sensible and complete — running with no arguments works.
* **Config file** overlays only the keys it contains; anything omitted keeps its
  default.
* **Flags** override individual settings for quick, one-off changes.

To produce a fully-populated template you can edit:

```
printcap.exe -dump-config printcap.json
```

`-dump-config` writes the **effective** config (defaults plus any `-config`/flags
you also passed) and exits without starting listeners. Use `-` to write to
stdout. A ready-made `printcap.sample.json` ships with the tool.

Typical production invocation:

```
printcap.exe -config C:\printcap\printcap.json
```

---

## 7. Command-line flag reference

| Flag | Type | Effect |
|------|------|--------|
| `-config <path>` | string | Load a JSON config file (overlaid on defaults). Default: `printcap.json` next to the exe. |
| `-console` | bool | Run headless in the console instead of launching the GUI. |
| `-service <cmd>` | string | Windows service control: `install` \| `remove` \| `start` \| `stop` \| `status`. |
| `-dump-config <path>` | string | Write effective config to `<path>` (or `-` for stdout) and exit. |
| `-bind <addr>` | string | Interface address all listeners bind to. Default `0.0.0.0` (all). Use `127.0.0.1` for local-only. |
| `-raw <port>` | int | Raw/JetDirect TCP port. `0` disables. Default 9100. |
| `-lpr <port>` | int | LPR/LPD TCP port. `0` disables. Default 515. |
| `-ipp <port>` | int | IPP (HTTP) TCP port. `0` disables. Default 631. |
| `-ipps <port>` | int | IPPS (TLS) TCP port. `0` disables. Default 6310. |
| `-auto-tls <port>` | int | One port that auto-detects TLS vs plaintext IPP. `0` disables. Overrides `-ipp`/`-ipps` if they share its number. |
| `-dash <port>` | int | Web dashboard TCP port. `0` disables. Default 8631. |
| `-snmp <port>` | int | SNMP agent UDP port. `0` disables. Default 161. |
| `-out <dir>` | string | Capture output directory. Default `captures`. |
| `-save <mode>` | string | `both` (raw + JSON), `raw` (spool only), or `meta` (metadata only, document bytes discarded). Default `both`. |
| `-cert <file>` | string | TLS certificate PEM for IPPS. Self-signed generated if empty. |
| `-key <file>` | string | TLS private key PEM for IPPS. Self-signed generated if empty. |
| `-community <str>` | string | SNMP community string. Default `public`. |
| `-model <str>` | string | Printer make-and-model advertised over IPP/SNMP. |

Anything not exposed as a flag (printer capabilities, SNMP identity details,
file-type policy, byte caps) is set via the config file.

### Common flag recipes

```
:: Only raw/9100 + IPP, nothing else
printcap.exe -lpr 0 -ipps 0 -snmp 0 -dash 0

:: IPP and IPPS share the standard port 631 (TLS auto-detect)
printcap.exe -auto-tls 631 -ipp 0 -ipps 0

:: Metadata-only audit (don't retain document contents)
printcap.exe -save meta

:: Local-only dashboard, impersonate a specific model
printcap.exe -bind 0.0.0.0 -dash 0 -model "HP LaserJet M607"

:: Move off privileged ports to run without Administrator
printcap.exe -lpr 1515 -ipp 1631 -snmp 1161
```

---

## 8. Config file reference

The config file is JSON. Every field below is shown with its default. Omit any
field to keep its default.

```jsonc
{
  "bind": "0.0.0.0",            // interface for all listeners
  "ports": {
    "raw9100": 9100,            // 0 disables each listener
    "lpr": 515,
    "ipp": 631,
    "ipps": 6310,
    "auto_tls": 0,             // single TLS-sniffing port (0 = off)
    "dashboard": 8631,
    "snmp": 161
  },
  "save": "both",              // both | raw | meta
  "out_dir": "captures",
  "max_job_mb": 0,             // per-job byte cap; 0 = unlimited

  "tls": {
    "cert_file": "",           // PEM cert for IPPS; blank = self-signed
    "key_file": ""             // PEM key for IPPS;  blank = self-signed
  },

  "raw": {                     // Raw/JetDirect/AppSocket options
    "extra_ports": [],         // additional raw ports, e.g. [9101, 9102]
    "parse_pjl": true,         // pull job name / user from a PJL preamble
    "split_on_uel": false      // split batched jobs on UEL into separate captures
  },

  "lpd": {                     // LPR/LPD options (enterprise compatibility)
    "accept_any_queue": true,  // record and accept any queue name
    "allowed_queues": [],      // if accept_any_queue is false, only these
    "require_privileged_source_port": false, // RFC1179 721-731; false = permissive
    "parse_pjl": true,         // fall back to PJL for job name / user
    "queue_defaults": {         // per-LPD-queue overrides (glob keys)
      "mvs*": { "code_page": "CP037", "carriage_control": "asa", "ebcdic": true }
    }
  },

  "ebcdic": {
    "enabled": true,            // transcode EBCDIC jobs to a -decoded.txt sidecar
    "default_code_page": "CP037", // CP037|CP500|CP1047|CP273|CP285|CP297
    "auto_detect": true,        // heuristically detect unmapped EBCDIC jobs
    "decoded_sidecar": true,    // write <base>-decoded.txt next to the raw spool
    "carriage_control": "auto"  // none | asa | machine | auto
  },

  "ipp_options": {             // IPP/IPPS resource paths
    "resource_paths": ["/ipp/print", "/ipp", "/printers/printcap", "/printer"],
    "default_path": "/ipp/print"
  },

  "printer": {
    "name": "printcap",
    "info": "printcap capture printer",
    "make_and_model": "printcap Virtual MFP",
    "location": "lab",
    "serial": "PC-0000-0001",
    "document_formats": [       // MIME types advertised AND (if enforced) accepted
      "application/octet-stream",
      "application/pdf",
      "application/postscript",
      "application/vnd.hp-PCL",
      "image/pwg-raster",
      "image/urf",
      "image/jpeg"
    ],
    "default_format": "application/octet-stream",
    "enforce_formats": false,   // true = reject IPP jobs whose format isn't listed
    "color": true,              // false = advertise monochrome only
    "sides": ["one-sided", "two-sided-long-edge", "two-sided-short-edge"],
    "resolutions": [300, 600],  // dpi
    "media": ["iso_a4_210x297mm", "na_letter_8.5x11in", "iso_a3_297x420mm"]
  },

  "snmp": {
    "enabled": true,
    "community": "public",
    "sys_descr": "printcap Virtual MFP; SNMP capture agent",
    "sys_name": "printcap",
    "sys_location": "lab",
    "sys_contact": "admin",
    "sys_object_id": "1.3.6.1.4.1.11.2.3.9.1", // vendor identity OID (HP-style default)
    "page_count": 0,            // reported lifetime page count
    "toner_level_pct": 100,     // reported supply level
    "v3_enabled": false,        // enable the SNMPv3 USM agent
    "allow_v1v2c": true,        // false = v3-only (drop v1/v2c)
    "engine_id": "",            // hex; blank = auto-generated (RFC 3411)
    "users": [                  // SNMPv3 USM users
      {
        "name": "admin",
        "level": "authPriv",        // noAuthNoPriv | authNoPriv | authPriv
        "auth_protocol": "SHA-256", // MD5 | SHA-1 | SHA-256 | SHA-512
        "auth_pass": "secretauth",
        "priv_protocol": "AES-128", // DES | AES-128 | AES-192 | AES-256
        "priv_pass": "secretpriv"
      }
    ]
  },

  "dashboard": {
    "enabled": true
  },

  "mdns": {
    "enabled": true,             // master switch (also -mdns)
    "instance": "",              // service name; blank = printer.name
    "hostname": "",              // advertised <host>.local; blank = sanitized printer.name
    "airprint": true             // advertise the _universal sub-type + URF key (iOS)
  },

  "smb": {
    "enabled": false,            // master switch (also -smb); experimental
    "port": 4445,                // non-445 listener port
    "share_name": "PRINTER",     // advertised print share name
    "require_auth": false,       // false = allow guest; true = NTLMv2 only
    "sign": true,                // SMB2 signing (AES-CMAC) when negotiated
    "encrypt": true,             // SMB3 encryption (AES-128-GCM) when negotiated
    "users": [                   // NTLMv2 credentials (passwords redacted in /api/config)
      { "user": "print", "password": "secret", "domain": "WORKGROUP" }
    ]
  },

  "wsd": {
    "enabled": false,            // master switch (also -wsd); experimental
    "port": 3911,                // SOAP HTTP port (WS-Discovery uses UDP 3702)
    "discovery": true            // run the WS-Discovery multicast responder
  },

  "log": {
    "level": "info",           // error | warn | info | debug | trace
    "file": "",                // path; empty = printcap.log next to the exe
    "format": "text",          // text | json — primary file/console rendering
    "json_file": "",           // separate JSON-lines file for SIEM shippers
    "max_size_mb": 10,         // rotate the file at this size
    "max_backups": 5,          // rotated files to keep (.1 .. .N)
    "console": true,           // also write to the console (-console mode)
    "protocol": false,         // promote per-connection detail to INFO
    "event_log": true,         // mirror warn/error to the Windows Event Log (service)
    "syslog": {
      "enabled": false,
      "network": "udp",        // udp | tcp
      "address": "",           // collector host:port, e.g. siem.example.com:514
      "facility": 16,          // 0-23; 16 = local0
      "rfc5424": false,        // true = RFC 5424; false = RFC 3164 (BSD)
      "app_name": "printcap"
    }
  },

  "forward": {
    "enabled": false,            // master switch (also -forward)
    "capture": "both",           // both | sent | orig
    "macros": {                  // reusable named byte blocks (\xNN-escapable)
      "pcl_reset": "\\x1bE"
    },
    "targets": [
      {
        "name": "lab-printer",
        "transport": "raw",      // raw | lpr | ipp | ipps
        "address": "10.0.0.20:9100",
        "timeout_ms": 30000,
        "queue": "auto",         // lpr: LPD queue ("auto"/blank = job's queue or "lp")
        "privileged_source_port": false, // lpr
        "tls_skip_verify": true, // ipps: accept self-signed downstream
        "document_format": "",   // ipp: blank = detected/forwarded format
        "when": {                // routing condition (empty = always)
          "protocols": ["IPP","9100"],
          "source_cidrs": ["10.0.0.0/24"],
          "users": [], "hosts": [], "job_name": "*invoice*",
          "queues": [], "doc_formats": [], "pdls": ["PCL","PostScript"],
          "contains": "@PJL",    // literal | /regex/ | hex:1b45
          "min_bytes": 0, "max_bytes": 0
        },
        "failure": "best_effort", // best_effort | spool_retry | block
        "retry": { "max_attempts": 5, "backoff_ms": 2000, "ttl_min": 60 },
        "transforms": [
          { "type": "inject_prefix", "data": "macro:pcl_reset" },
          { "type": "replace", "mode": "literal", "match": "ACME", "with": "Globex", "all": true,
            "when": { "pdls": ["PCL","PostScript","Text"] } },
          { "type": "replace", "mode": "regex", "match": "Draft\\s+\\d+", "with": "FINAL" },
          { "type": "replace", "mode": "hex", "match": "1b266c3153", "with": "1b266c3044" },
          { "type": "inject_suffix", "data": "macro:pcl_reset" }
        ]
      }
    ]
  }
}
```

### Field notes

* **`bind`** — set to `127.0.0.1` to make every listener local-only (useful when
  capturing from software on the same host, or to keep the dashboard private).
* **`save`**
  * `both` — write the spool file **and** a `.json` metadata sidecar.
  * `raw` — spool file only.
  * `meta` — `.json` only; **document bytes are discarded** (privacy-preserving
    audit of *who printed what* without retaining content).
* **`max_job_mb`** — caps each job at read time (bounded memory, not just
  truncated output). `0` = unlimited. Set a value when untrusted hosts can reach
  the tool.
* **`printer.document_formats`** — drives the IPP `document-format-supported`
  list. With `enforce_formats: true`, IPP jobs whose `document-format` isn't in
  the list are rejected with `client-error-document-format-not-supported` and
  not captured.
* **`printer.make_and_model` / `serial` / `name`** — also surface in SNMP
  (`hrDeviceDescr`, `prtGeneralSerialNumber`, `prtGeneralPrinterName`). Set these
  to impersonate a specific device for a discovery tool.
* **`snmp.sys_object_id`** — the vendor-identity OID returned for
  `sysObjectID.0`. The default is an HP-style enterprise OID; change it to match
  the vendor you're emulating.
* **`snmp.v3_enabled` / `allow_v1v2c` / `engine_id` / `users`** — turn on the
  SNMPv3 USM agent and define its users. With `v3_enabled: true` the same MIB is
  served over authenticated/encrypted SNMPv3; `allow_v1v2c: false` makes the
  agent v3-only (v1/v2c requests are dropped). `engine_id` is a hex string —
  leave it blank to auto-generate an RFC 3411 engine ID. Each entry in `users`
  has a `name`, a `level` (`noAuthNoPriv` | `authNoPriv` | `authPriv`), an
  `auth_protocol` (`MD5` | `SHA-1` | `SHA-256` | `SHA-512`) with `auth_pass`, and
  a `priv_protocol` (`DES` | `AES-128` | `AES-192` | `AES-256`) with `priv_pass`.
  Engine discovery (the client's probe for the agent's engine ID) is answered
  automatically.

  > **SECURITY NOTE:** SNMPv3 passphrases (`auth_pass` / `priv_pass`) are
  > secrets. They are **redacted from `/api/config`**, but they live in the
  > config file in clear text — protect it with NTFS ACLs (see §14). Prefer
  > `authPriv` (authenticated **and** encrypted); `authNoPriv` leaves payloads
  > readable and `noAuthNoPriv` offers no protection at all. A requested security
  > level cannot exceed the user's configured `level` (asking for `authPriv`
  > against an `authNoPriv` user is refused). The agent remains **read-only** —
  > there is no SET support over any version. Note that v1/v2c community strings
  > are still sent in clear text unless you set `allow_v1v2c: false`.
* **`tls.cert_file` / `key_file`** — supply a real certificate for IPPS if
  clients validate it. Left blank, printcap mints a fresh in-memory self-signed
  certificate at startup (clients must skip validation).
* **`ebcdic`** — transcode mainframe/midrange (z/OS, IBM i / AS-400) print jobs
  from EBCDIC to readable UTF-8. `enabled` is the master switch;
  `default_code_page` is the fallback when a job has no explicit mapping (one of
  the six built-ins below); `auto_detect` heuristically flags unmapped jobs as
  EBCDIC; `decoded_sidecar` writes the decoded text as `<base>-decoded.txt` next
  to the raw spool; `carriage_control` is `none` | `asa` | `machine` | `auto`
  (carriage-control interpretation for line printers).
  * **Built-in code pages** — `CP037` (US/Canada), `CP500` (International),
    `CP1047` (Open Systems / z/OS), `CP273` (Germany), `CP285` (UK), `CP297`
    (France).
  * **`lpd.queue_defaults`** — per-queue overrides keyed by a glob (e.g. `mvs*`),
    each mapping to `{ code_page, carriage_control, ebcdic }`. **Resolution order
    per job:** a matching `queue_defaults` glob wins first; otherwise, when
    `auto_detect` flags the bytes as EBCDIC, the global `default_code_page` is
    applied; otherwise the job is left raw (transcode off).
  * **Carriage-control timing** — **machine** carriage-control is applied to the
    raw bytes *before* decode, while **ASA** carriage-control is applied *after*
    decode (it operates on the first character of each decoded line).
  * **Control file** — the richer LPD control file captures Class (`C`) and Title
    (`T`); a FORTRAN carriage-control (`r`) data line hints ASA.
* **`forward`** — tee each captured job to one or more downstream printers,
  optionally rewriting it first. `enabled` (or `-forward`) is the master switch;
  each entry in `targets` is one downstream printer.
  * **`transport` + `address`** — `raw` uses `host:port` (e.g. `10.0.0.20:9100`);
    `lpr` uses `host:port` plus `queue` ("auto"/blank = the job's own queue, else
    `lp`) and `privileged_source_port` (bind a 721–731 source port for strict
    LPD servers); `ipp`/`ipps` use a full URI such as
    `ipp://host:631/ipp/print` plus `tls_skip_verify` (accept a self-signed
    downstream) and `document_format` (blank = the detected/forwarded format).
  * **`when`** — the routing condition; a target only fires when **every** field
    present matches (logical AND), and list fields match if **any** element
    matches. An empty `when` always matches. `contains` and `job_name` accept a
    literal, a `/regex/`, or a `hex:1b45` byte pattern.
  * **`transforms`** — an ordered list of steps applied to the forwarded copy.
    `replace` rewrites bytes in `literal`, `regex`, or `hex` mode (`all` replaces
    every occurrence); `inject_prefix` / `inject_suffix` prepend / append raw
    bytes. The `with` value and inject `data` support `\xNN` escapes and
    `macro:NAME` references into `forward.macros`. A per-transform `when` gates
    individual steps (same fields as the target `when`).
  * **`failure`** — what happens when a target can't be reached:
    * `best_effort` — always deliver if possible but **never block the sender**;
      delivery failures are only logged.
    * `spool_retry` — retry in memory with `retry.backoff_ms` up to
      `retry.max_attempts` or `retry.ttl_min`; retries are **not persisted**
      across a restart.
    * `block` — propagate the failure back to the inbound client (the print
      fails upstream).
  * **`capture`** — what lands on disk: `both` (default), `sent` (transformed
    only), or `orig` (original only). Transformed copies are written as
    `<base>-sent-<target><ext>` alongside the original.

  > **Length safety:** `replace` is intended for text/PCL/PostScript. Replacements
  > that change byte length can corrupt length-indexed formats (PDF cross-reference
  > tables, PCL transparent-data/raster blocks). Gate such rules with
  > `when.pdls` to restrict them to safe formats.
* **`mdns`** — Bonjour/DNS-SD advertisement: `enabled`, `instance` (service name;
  blank = `printer.name`), `hostname` (advertised `<host>.local`; blank =
  sanitized `printer.name`), `airprint` (advertise the `_universal` sub-type and
  `URF` key for iOS). Advertises only the listeners that actually bound. If UDP
  5353 is unavailable, mDNS disables itself and logs a warning; no other listener
  is affected.
* **`smb`** — **experimental** SMB2/3 print-share capture (off by default; enable
  with `-smb`). `port` (default `4445`, deliberately non-445 to avoid the OS SMB
  stack), `share_name`, `require_auth` (`false` allows guest; `true` requires a
  matching `users` entry), `sign` (SMB2 AES-CMAC signing), `encrypt` (SMB3
  AES-128-GCM), and `users` (`user`/`password`/`domain` for NTLMv2). Negotiates
  SMB 3.1.1 with preauth integrity. Passwords are redacted from `/api/config`.
  > **Security note:** this is a hand-rolled, experimental SMB server surface that
  > parses untrusted network input. Run it only on trusted segments, keep
  > `require_auth:true` with real credentials where possible, and prefer a
  > firewall rule scoping the `4445` port. It is not a general-purpose file server
  > — only the `\spoolss` print pipe over `IPC$` is serviced.
* **`wsd`** — **experimental** WSD (Web Services for Devices) print service, the
  protocol behind Windows "Add a device" (off by default; enable with `-wsd`).
  `port` (default `3911`, the SOAP HTTP endpoint `/wsd`; WS-Discovery additionally
  uses UDP `3702` multicast), and `discovery` (run the WS-Discovery responder —
  set `false` to serve only a directly-addressed XAddr). Captured jobs appear as
  `WSD` with the document name, user, and format; the document arrives as an
  MTOM/XOP attachment.
  > **Security note:** like the SMB surface, this hand-rolls SOAP/WS-Discovery/
  > MTOM parsing of untrusted network input — run it on trusted segments and scope
  > the `3911`/`3702` ports with a firewall rule. It is a capture endpoint, not a
  > full WSD spooler.

---

## 9. Protocols in detail

### Raw / JetDirect / AppSocket (TCP 9100)
No protocol overhead: the client opens a socket, streams the page-description
language (PCL/PostScript/PDF/etc.), and closes. printcap reads to EOF and treats
the whole stream as one job. There is **no** metadata on this channel, so user
and job name are unknown; the file extension is guessed from magic bytes.

### LPR / LPD (TCP 515)
RFC 1179. A short ACK-driven conversation: printcap acknowledges each
sub-command, receives a **control file** (ASCII metadata: `H`=host, `P`=user,
`J`=job name) and a **data file** (the spool bytes). User/host/job-name are
captured from the control file.

### IPP (TCP 631)
IPP-over-HTTP. The client POSTs an IPP envelope. printcap answers
`Get-Printer-Attributes` with a full driverless/IPP-Everywhere attribute set so
clients commit the job, then captures the document carried by `Print-Job` /
`Send-Document`. Captures `job-name`, `requesting-user-name`, and
`document-format`.

### IPPS (TCP 6310)
IPP over TLS. Same handling as IPP; the transport is encrypted with the
configured (or self-signed) certificate.

### Auto-TLS single port
If `auto_tls` is set, that one port serves **both** IPP and IPPS. printcap peeks
the first byte: `0x16` (a TLS handshake record) → TLS path; anything else →
plaintext. This lets a single port (e.g. the standard 631) accept both. When
`auto_tls` shares a number with `ipp`/`ipps`, those separate listeners are
disabled to avoid a conflict.

### SNMP (UDP 161)
See §11.

### Dashboard (TCP 8631)
See §12.

---

## 10. Connecting print clients

### Windows
**Settings → Bluetooth & devices → Printers & scanners → Add manually**, or the
classic *Add Printer* wizard → **Add a local printer** → **Create a new port**:

* **Raw/9100:** Port type *Standard TCP/IP Port*, host = printcap's IP, device
  type *Raw*, port number 9100.
* **LPR:** *Standard TCP/IP Port*, device type *LPR*, queue name anything (it's
  ignored). LPR requires the "LPD Print Service" / "LPR Port Monitor" Windows
  feature on some editions.
* **IPP/IPPS:** Add a printer by URL — `http://HOST:631/` or
  `https://HOST:6310/`.

Pick any driver (e.g. "Microsoft Print to PDF"-style generic, or a PCL/PS
driver) — printcap accepts whatever the driver emits.

### macOS / Linux (CUPS)
```
# IPP
lpadmin -p printcap -E -v ipp://HOST:631/ipp/print -m everywhere
# Raw/9100
lpadmin -p printcap -E -v socket://HOST:9100
# LPD
lpadmin -p printcap -E -v lpd://HOST/queue
lp -d printcap somefile.pdf
```

### Verifying capture
Watch the console log or the dashboard; each accepted job logs a line:

```
[IPP] captured 12345 bytes from 10.0.0.5:51840  user=alice job="Report.pdf" fmt=application/pdf -> 20260601-140444-0001-IPP-Report.pdf
```

---

## 11. SNMP discovery

The built-in agent answers the OID trees discovery/fleet tools query so the host
appears as a real printer:

* **System group (RFC 1213)** — `sysDescr`, `sysObjectID`, `sysUpTime`,
  `sysContact`, `sysName`, `sysLocation`, `sysServices`.
* **Host Resources MIB (RFC 2790)** — `hrDeviceType` returns the OID
  `hrDevicePrinter`, which is how scanners distinguish a printer from a PC; plus
  `hrDeviceDescr`, `hrPrinterStatus` (idle).
* **Printer MIB (RFC 3805)** — `prtGeneralPrinterName`, serial, page count,
  supply level, console "Ready" text.

Supported operations: **Get, GetNext, GetBulk** (v1 and v2c), so tools can both
probe known OIDs and `snmpwalk` the device. Requests with the wrong community
string are **dropped silently**. There is no SET support (read-only).

### Verify with net-snmp
```
snmpget  -v2c -c public HOST 1.3.6.1.2.1.1.1.0           # sysDescr
snmpget  -v2c -c public HOST 1.3.6.1.2.1.25.3.2.1.2.1    # -> hrDevicePrinter
snmpwalk -v2c -c public HOST 1.3.6.1.2.1.43              # Printer MIB
```

See [Appendix A](#appendix-a--snmp-oid-map) for the full OID map.

> **Note:** On Windows, the built-in **SNMP Service** also binds UDP 161. Stop
> it (`Stop-Service SNMP`) or run printcap's agent on a different port
> (`-snmp 1161`) to avoid a conflict.

---

## 12. The web dashboard & JSON API

Browse to `http://HOST:8631/`. The page auto-refreshes every 2 seconds and shows:

* **Stat cards** — total jobs, total bytes, per-protocol counts.
* **Listener pills** — which ports are active.
* **Job table** — time, protocol, source IP, user, host, job name, document
  format, size, and a **download** link for each saved spool file.

The dashboard keeps the **most recent 200 jobs** in memory for display; the full
history lives on disk in the capture folder. Document bytes are **not** held in
memory — downloads stream from the saved file.

### JSON API

| Endpoint | Returns |
|----------|---------|
| `GET /api/stats` | Totals, per-protocol counts, active listeners, printer identity, save mode. |
| `GET /api/jobs` | Array of recent jobs (metadata, newest first). |
| `GET /api/config` | Effective configuration, **with SNMP community and TLS key paths redacted**. |
| `GET /api/job?id=N` | Downloads the saved spool file for job `N` (`Content-Disposition: attachment`). 404 if no saved data (e.g. `-save meta`). |

> The dashboard has **no authentication** — anyone who can reach the port sees
> job metadata and can download captured documents. See §14.

---

## 13. Captured output on disk

Each accepted job produces, depending on `save` mode:

* a **raw spool file** — extension chosen from the document format or sniffed
  magic bytes: `.pdf`, `.ps`, `.pcl`, `.jpg`, else `.prn`.
* a **`.json` sidecar** — `protocol`, `source`, `received` (RFC3339),
  `job_name`, `user`, `host`, `document_format`, `bytes`, `saved_as`.

Filenames are unique and time-ordered:

```
<timestamp>-<seq>-<protocol>[-<jobname>].<ext>

20260601-140444-0001-IPP-Report.json
20260601-140444-0001-IPP-Report.pdf
```

`<seq>` is a per-run counter; `<jobname>` is sanitized (unsafe characters → `_`).
There is no automatic deletion or rotation — manage retention yourself (see
§16).

---

## 14. Security & hardening

### Built-in protections
* **Bounded memory.** Untrusted length fields (LPD `count`) are never used to
  pre-allocate; buffers grow only as bytes arrive. `max_job_mb` caps every job
  at read time.
* **Timeouts.** 60-second idle timeout on print connections (no goroutine leak
  on half-open sockets); HTTP listeners enforce read-header (15 s), write
  (10 min), and idle (2 min) timeouts plus a 1 MB header cap (defeats Slowloris).
* **TLS 1.2 minimum** for IPPS.
* **SNMP** is read-only, drops wrong-community requests silently.
* **Dashboard secrets** (community string, TLS key path) are redacted from
  `/api/config`.
* **Download path safety** — only files inside the capture directory are served.

### Operational considerations you must decide
* **The dashboard is unauthenticated.** On a shared network, bind it locally
  (`-bind 127.0.0.1`) or disable it (`-dash 0`). If remote access is needed,
  front it with a reverse proxy that adds authentication/TLS.
* **Captured spool files may contain sensitive documents.** Store the capture
  directory on an access-controlled volume; consider `-save meta` when you only
  need the audit trail, not contents. Apply NTFS ACLs and, where appropriate,
  disk encryption (BitLocker).
* **SNMP v1/v2c sends the community string in clear text** — this is inherent to
  the protocol. Treat SNMP as a discovery convenience, not a trust boundary.
  Disable with `-snmp 0` if not required.
* **`bind 0.0.0.0` exposes every listener on all interfaces.** Restrict to a
  management interface or use host/network firewall rules to limit who can
  reach it.
* **Run with least privilege.** Only use Administrator/privileged ports when you
  genuinely need 515/631/161; otherwise move to high ports and run as a normal
  account (or a dedicated service account — see §15).

---

## 15. Running as a Windows service

printcap has **built-in, native Windows service support** — it registers with
the Service Control Manager directly, no third-party wrapper needed. The same
exe is the GUI, the console tool, and the service.

### From the GUI
Open the **Windows Service** tab. Buttons: **Install**, **Remove**, **Start**,
**Stop**. Install writes the current settings to `printcap.json` first, so the
service starts with exactly what you see in the UI. Installing/removing requires
the GUI to be running elevated (right-click → **Run as administrator**).

When the service is installed, the GUI's main **Start/Stop** button and status
line track the *service* rather than the in-process engine.

### From the command line
Run an **Administrator** prompt:

```
printcap.exe -service install     :: register, auto-start at boot
printcap.exe -service start
printcap.exe -service status
printcap.exe -service stop
printcap.exe -service remove
```

* **Install** registers the service as **Automatic** start, running as
  **LocalSystem** (which can bind privileged ports), with the command line
  `printcap.exe -config <path-to-printcap.json>`. The config path is whatever was
  in effect when you installed (the `-config` flag, or `printcap.json` next to
  the exe).
* The service detects it was launched by the SCM and runs the capture engine
  headless. It logs to **`printcap.log`** next to the exe (rotating) and mirrors
  warnings/errors to the **Windows Event Log** (source "printcap") — see §16.
* **Remove** stops the service first, then deletes it.

### Service checklist
* Set `out_dir` to an **absolute path** in `printcap.json` — a service's working
  directory is `C:\Windows\System32`, not your folder. Example:
  `"out_dir": "C:\\printcap\\captures"`.
* Re-run `-service install` (or use the GUI Install button) after moving the exe,
  so the registered path stays correct.
* Confirm the firewall rules from §5 exist — services don't trigger the
  interactive allow prompt.
* To run as a dedicated low-privilege account instead of LocalSystem, change the
  service's "Log On" account in `services.msc` and grant it write access to the
  capture folder (and the right to bind any privileged ports you use).

---

## 16. Logging & monitoring

printcap has a leveled, multi-sink logging subsystem.

**Levels** (lowest → highest verbosity): `error`, `warn`, `info` (default),
`debug`, `trace`. Set via the GUI **Logging** tab, `log.level` in the config, or
`-loglevel` / `-v` (debug) / `-vv` (trace). Each line is:

```
2026-06-01 14:04:44.812 INFO  [IPP] captured 12345 bytes from 10.0.0.5 user=alice job="Report.pdf" queue=/ipp/print pdl=PDF -> 20260601-...-IPP-Report.pdf
```

with a **component** tag: `[app] [engine] [9100] [LPR] [IPP] [SNMP] [svc]`.

**What each level adds**
* `warn` — rejected jobs (disallowed LPD queue, non-privileged source port when
  required), wrong SNMP community, listener bind failures.
* `info` — every capture, listener start/stop.
* `debug` — connections, spool-file writes, IPP operations.
* `trace` — every LPD subcommand, every SNMP OID requested. Very verbose.

Tick **Verbose protocol logging** (`log.protocol`) to promote per-connection
detail to INFO without raising the whole level.

**Sinks**
* **File** — `printcap.log` next to the exe by default (`log.file` to change).
  **Rotates** at `log.max_size_mb` (default 10 MB), keeping `log.max_backups`
  files (`printcap.log.1`, `.2`, …). No external rotation needed.
* **Console** — when running `-console` (and `log.console`).
* **Dashboard** — the *Live log* panel with a **download full log** link, and
  `GET /api/logs?level=<lvl>&n=<n>` / `GET /api/logfile` (download).
* **Windows Event Log** — when running as a service with `log.event_log` on,
  warnings and errors appear in **Event Viewer → Windows Logs → Application**,
  source **"printcap"** (registered at service install).

**SIEM export.** Two independent feeds for shipping logs off-box:

* **JSON-lines file** (`log.json_file`) — one JSON object per line
  (`{"time","level","component","message"}`), rotated like the text log. Point a
  file shipper at it (Splunk Universal Forwarder, Filebeat, Fluent Bit). The
  human-readable `printcap.log` is kept separately. You can also set
  `log.format: "json"` to make the primary log itself JSON.
* **Remote syslog** (`log.syslog`) — ships every record to a collector over UDP
  or TCP, framed as RFC 3164 (BSD) or RFC 5424. Works with rsyslog, syslog-ng,
  Graylog, and Splunk. Severity maps error→err(3), warn→warning(4), info→info(6),
  debug/trace→debug(7); the PRI is `facility*8 + severity`. Example:

  ```
  "syslog": { "enabled": true, "network": "udp",
              "address": "siem.example.com:514", "facility": 16,
              "rfc5424": true, "app_name": "printcap" }
  ```

Both are configurable from the GUI's **Logging** tab (SIEM export group).

**Capture retention:** the capture folder grows without bound. Schedule cleanup,
e.g. delete files older than 30 days (Administrator PowerShell):

```powershell
Get-ChildItem C:\printcap\captures |
  Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) |
  Remove-Item -Force
```

**Health checks:** poll `GET /api/stats` (HTTP 200 + JSON) to confirm the
process is alive, or check the listening ports / Event Log.

---

## 17. Performance & resource limits

* Each connection is handled in its own lightweight goroutine; the tool handles
  many concurrent jobs comfortably. The dashboard retains metadata for the last
  **200** jobs in memory (document bytes are not retained in memory).
* **Memory per job** tracks the actual bytes received, bounded by `max_job_mb`
  when set. With `max_job_mb: 0` (unlimited), a single very large job is read
  fully into memory before writing — set a cap if that's a concern.
* **Disk** is the practical limit on long-running capture. A busy queue can
  produce large PostScript/PCL spool files (tens of MB each). Size the volume
  and set a retention policy (§16).
* **Idle timeout** (60 s) closes stalled connections so they don't accumulate.

---

## 18. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `bind: permission denied` on 515/631/161 | Not elevated for privileged ports | Run as Administrator, or move to high ports (`-lpr 1515` etc.) |
| `bind: address already in use` | Another service owns the port (Windows SNMP Service on 161; Print Spooler/LPD; an IPP service) | Stop the conflicting service or change printcap's port |
| Client says "printer offline" / job never arrives | Firewall blocking inbound, wrong IP/port, or wrong protocol type in the port config | Verify firewall rules (§5); confirm IP/port; match Raw vs LPR vs IPP |
| IPP job rejected | `enforce_formats: true` and the driver's `document-format` isn't listed | Add the format to `document_formats`, or set `enforce_formats: false` |
| IPPS client refuses to connect | Self-signed certificate not trusted | Provide a trusted cert via `tls.cert_file`/`key_file`, or configure the client to skip validation |
| `snmpget`/scanner gets no response | Wrong community string (silently dropped), SNMP disabled, or port conflict | Match `community`; ensure `snmp.enabled`; check port 161 ownership |
| Dashboard shows no jobs | Jobs going to a disabled/!wrong port, or `-save meta` (still lists them) | Confirm the listener for the protocol is enabled and the client targets the right port |
| Download link 404 | Job saved in `meta` mode (no file) or file was deleted/rotated | Use `both`/`raw` save mode; check retention cleanup |
| Captured file has `.prn` extension unexpectedly | Format wasn't advertised and magic bytes didn't match a known type | Normal — `.prn` is the raw-spool fallback; the bytes are intact |
| Service starts but writes nothing | Relative `out_dir` resolved against the service working directory | Use an absolute `out_dir` and `-config` path (§15) |

### Diagnostic steps
1. Run interactively (not as a service) from an Administrator prompt and watch
   the console — bind errors and per-job logs are immediate.
2. Confirm listeners: `netstat -ano | findstr "9100 515 631 6310 161 8631"`.
3. Test each path locally before involving real clients (see §19).

---

## 19. Acceptance test procedure

Run these from the printcap host (or another machine on the LAN) to confirm a
deployment is fully functional. Replace `HOST` with the server's IP.

1. **Process & ports**
   ```
   netstat -ano | findstr "9100 515 631 6310 161 8631"
   ```
   Expect a `LISTENING` line per enabled port.

2. **Dashboard**
   Open `http://HOST:8631/` → page loads, listener pills show your ports.

3. **Raw/9100** (PowerShell)
   ```powershell
   $c = New-Object System.Net.Sockets.TcpClient("HOST",9100)
   $s = $c.GetStream(); $b=[Text.Encoding]::ASCII.GetBytes("%!PS test`nshowpage`n")
   $s.Write($b,0,$b.Length); $c.Close()
   ```
   A `9100` job appears in the dashboard.

4. **IPP** — add an IPP printer at `http://HOST:631/`, print a test page; an
   `IPP` job appears with your user name.

5. **SNMP**
   ```
   snmpget -v2c -c public HOST 1.3.6.1.2.1.25.3.2.1.2.1
   ```
   Returns `hrDevicePrinter`.

6. **Download** — click *download* on a captured job; the spool file saves.

7. **Output on disk** — the capture folder contains matching `.json` + spool
   files.

8. **SNMPv3** — define an authPriv user, then from a client:
   `snmpget -v3 -l authPriv -u admin -a SHA-256 -A <auth> -x AES -X <priv> HOST 1.3.6.1.2.1.1.1.0`
   returns sysDescr. A wrong `-A`/`-X` is rejected with no data. With
   `allow_v1v2c:false`, `snmpget -v2c -c public` gets no reply.

9. **Forwarding** — set `forward.enabled:true` with a `raw` target pointing at a
   test printer (or `nc -l 9100`). Print a job; confirm it appears at the target,
   and that both `<base>...` and `<base>-sent-<target>...` files exist in the
   capture folder with the transform applied.

10. **EBCDIC capture** — map a test queue to CP037 in `lpd.queue_defaults`, send an
    EBCDIC job via LPR to that queue; confirm a readable `<base>-decoded.txt` is
    written and the job `.json` shows `code_page` and `decoded_as`. An ASCII job to
    an unmapped queue is captured unchanged (no sidecar).

11. **mDNS discovery** — on a macOS/Linux client on the same subnet:
    ```
    ippfind            # prints ipp://<host>.local:631/ipp/print
    avahi-browse -rat  # (Linux) lists printcap under _ipp._tcp
    ```
    The printer also appears in the macOS "Add Printer" Bonjour list and the iOS
    Print sheet.

12. **SMB print share (experimental)** — set `smb.enabled:true` (or `-smb`), then
    from a Linux/macOS client with Samba's `smbclient`:
    ```
    smbclient //HOST/PRINTER -p 4445 -N                # guest (require_auth:false)
    smbclient //HOST/PRINTER -p 4445 -U print%secret   # NTLMv2 (a configured user)
    smb> print somefile.pcl
    ```
    Confirm an `SMB` job is captured with the document name, flows through PDL
    detection + forwarding, and that `/api/config` redacts the SMB password.

13. **WSD (experimental)** — set `wsd.enabled:true` (or `-wsd`). On Windows:
    **Settings → Add a device** discovers printcap; install and print a test page;
    confirm a `WSD` job is captured with the document name, user, and format,
    flowing through PDL detection + forwarding. Stopping printcap sends a
    WS-Discovery **Bye** and the device disappears. (Architecture is pure SOAP/
    HTTP + multicast, so the discovery probe and `http://<host>:3911/wsd` SOAP/MTOM
    endpoints can also be exercised from Linux/macOS without Windows.)

If all thirteen pass, the deployment is good.

---

## 20. Upgrade & uninstall

**Upgrade:** stop the process/service, replace `printcap.exe` with the new
build, restart. Config files and captures are unaffected.

**Uninstall:**
1. Stop and remove the service if installed:
   `nssm stop printcap & nssm remove printcap confirm` (or
   `schtasks /delete /tn printcap /f`).
2. Remove the firewall rules:
   `Remove-NetFirewallRule -DisplayName "printcap TCP","printcap SNMP"`.
3. Delete the `C:\printcap\` folder (including captures, if no longer needed).

There is no registry footprint beyond any service entry you created.

---

## Appendix A — SNMP OID map

| OID | Name | Type | Source |
|-----|------|------|--------|
| `1.3.6.1.2.1.1.1.0` | sysDescr | OctetString | `snmp.sys_descr` |
| `1.3.6.1.2.1.1.2.0` | sysObjectID | OID | `snmp.sys_object_id` |
| `1.3.6.1.2.1.1.3.0` | sysUpTime | TimeTicks | live since start |
| `1.3.6.1.2.1.1.4.0` | sysContact | OctetString | `snmp.sys_contact` |
| `1.3.6.1.2.1.1.5.0` | sysName | OctetString | `snmp.sys_name` |
| `1.3.6.1.2.1.1.6.0` | sysLocation | OctetString | `snmp.sys_location` |
| `1.3.6.1.2.1.1.7.0` | sysServices | Integer | 72 |
| `1.3.6.1.2.1.25.3.2.1.2.1` | hrDeviceType | OID | `hrDevicePrinter` |
| `1.3.6.1.2.1.25.3.2.1.3.1` | hrDeviceDescr | OctetString | `printer.make_and_model` |
| `1.3.6.1.2.1.25.3.2.1.5.1` | hrDeviceStatus | Integer | 2 (running) |
| `1.3.6.1.2.1.25.3.5.1.1.1` | hrPrinterStatus | Integer | 3 (idle) |
| `1.3.6.1.2.1.25.3.5.1.2.1` | hrPrinterDetectedErrorState | OctetString | none |
| `1.3.6.1.2.1.43.5.1.1.16.1` | prtGeneralPrinterName | OctetString | `printer.name` |
| `1.3.6.1.2.1.43.5.1.1.17.1` | prtGeneralSerialNumber | OctetString | `printer.serial` |
| `1.3.6.1.2.1.43.10.2.1.4.1.1` | prtMarkerLifeCount | Counter32 | `snmp.page_count` |
| `1.3.6.1.2.1.43.11.1.1.8.1.1` | prtMarkerSuppliesMaxCapacity | Integer | 100 |
| `1.3.6.1.2.1.43.11.1.1.9.1.1` | prtMarkerSuppliesLevel | Integer | `snmp.toner_level_pct` |
| `1.3.6.1.2.1.43.16.5.1.2.1.1` | prtConsoleDisplayBufferText | OctetString | "Ready" |

References: RFC 1213 (MIB-II), RFC 2790 (Host Resources MIB), RFC 3805 (Printer
MIB v2).

---

## Appendix B — IPP attributes advertised

In response to `Get-Printer-Attributes`, printcap returns (driven by
`printer.*`):

* Identity: `printer-uri-supported`, `printer-name`, `printer-info`,
  `printer-make-and-model`, `printer-location`, `printer-uuid`.
* State: `printer-state` (idle), `printer-state-reasons` (none),
  `printer-is-accepting-jobs` (true), `queued-job-count`.
* Capabilities: `ipp-versions-supported` (1.1, 2.0), `ipp-features-supported`
  (`ipp-everywhere`), `operations-supported`, `charset-supported`,
  `document-format-supported` / `-default`, `compression-supported`,
  `pdl-override-supported`.
* Driverless/IPP-Everywhere: `sides-supported` / `-default`,
  `print-color-mode-supported` / `-default`, `media-supported` / `-default`,
  `printer-resolution-supported` / `-default`,
  `pwg-raster-document-resolution-supported`,
  `pwg-raster-document-type-supported`, `urf-supported`.

Job operations (`Print-Job`, `Create-Job`, `Send-Document`, `Validate-Job`)
return a job group with `job-uri`, `job-id`, `job-state` (completed), and
`job-state-reasons`. With `enforce_formats: true`, an unsupported
`document-format` yields status `client-error-document-format-not-supported`
(`0x040A`).

References: RFC 8011 (IPP/1.1), PWG 5100.14 (IPP Everywhere).

---

*printcap administrator guide. Pair with `README.md` for a feature overview and
`printcap.sample.json` for a config template.*
