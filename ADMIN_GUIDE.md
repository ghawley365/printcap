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
12. [The web dashboard & admin console](#12-the-web-dashboard--admin-console)
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
| SNMP agent | UDP 161 | SNMP v1/v2c (+ optional v3/USM) |
| Web dashboard | TCP 8631 | HTTP (admin console) |

**Intended use:** print-infrastructure testing, driver/queue validation, and
authorized print-security assessment on networks you control. In its default
configuration it receives jobs addressed to it and answers SNMP queries about
itself — it does **not** sniff or intercept traffic destined for other devices.

> **Optional intercept mode.** A separate, off-by-default *network interception*
> mode (Section 9a) can capture full-segment traffic to a pcap and, optionally,
> position printcap on-path via ARP. It is gated behind an **enforced operator
> authorization** and an explicit target allow-list, and is **only** for networks
> you are authorized to capture on. See Section 9a before enabling it.

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

printcap ships as a single self-contained `.exe`. Deploy it either by plain
xcopy or with the bundled Windows installer.

### Option A — xcopy (portable)

1. Copy `printcap.exe` to a folder, e.g. `C:\printcap\`.
2. (Optional) Copy a config file alongside it, e.g. `C:\printcap\printcap.json`.
3. Decide where captures go (the `out_dir` / `-out` location). The folder is
   created automatically on first run.

printcap is **fully portable**: every generated file (captures, the
spool/retry queue, logs) resolves **relative to the executable's directory**
unless you give an absolute path, so the same folder runs unchanged from a
network share or USB stick (see §6).

Suggested layout:

```
C:\printcap\
  printcap.exe
  printcap.json        (your edited config)
  captures\            (created automatically)
  spool\               (forward-retry queue + temp; created automatically)
  printcap.log         (created automatically)
```

### Option B — Windows installer (Inno Setup)

A signed/installable build is produced from `installer/printcap.iss` (Inno
Setup 6+; `iscc printcap.iss`). The installer:

* installs `printcap.exe` (plus `printcap.sample.json`, `README.md`, and this
  guide) into **Program Files** (`%ProgramFiles%\printcap`);
* offers two optional tasks under *Windows integration*:
  * **Install and start the Windows service** (runs unattended at boot);
  * **Add Windows Firewall rules for the configured listener ports** (one
    inbound rule **per configured port** — see §5);
* requires Administrator (it manages a service, the Event Log, and firewall
  rules);
* uninstalls cleanly — it stops and removes the service (which also
  deregisters the Event Log source) and deletes the firewall rules, but
  **deliberately keeps your captured data, the spool/retry queue, and
  `printcap.json`** (see §20).

Check the installed build at any time with:

```
printcap.exe -version
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
| Double-click (or run with no args) | Opens the **settings GUI** (tray icon while open; closing the window quits) |
| `printcap.exe -console` | Runs **headless** in the console |
| `printcap.exe -service …` / launched by the SCM | Runs as / manages the **Windows service** |

---

## 4. Quick start

### GUI

Double-click **printcap.exe**. The settings window opens. On the **Protocols &
Ports** tab, enable the protocols you want; on **General**, set the capture
directory and save mode. Click **Start**. A system-tray icon is available while
the window is open (right-click for Open / Dashboard / Capture folder / Exit).

> **Closing the GUI window quits printcap** — it stops the engine, releases the
> ports, and exits the process. For background capture that survives logout and
> window close, install the **Windows service** (§15) or run `-console`.

To bind ports below 1024 (515/631/161) or install the service, right-click
printcap.exe → **Run as administrator** (or accept the UAC prompt the service
and firewall actions raise — §5).

The GUI configures **100% of the configuration**: every printer field, the
Discovery/SMB/EBCDIC/Forward/DLP tabs, SNMPv3/USM users, storage folders,
notifications, and so on. Nested blocks (forward targets, transforms) are
edited as JSON, and **Save** runs the same validation as `-check` and shows any
issues before writing the file.

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
* **UAC self-elevation.** Running an admin-requiring command —
  `-service install|remove|start|stop` or `-firewall add|remove` — from a
  **non-elevated** prompt triggers a UAC consent prompt and re-launches that
  command elevated automatically. (`-service status` is read-only and does not
  elevate.) You no longer have to remember to open an Administrator prompt
  first.
* **Windows Firewall** — printcap can add its own inbound allow rules. Use the
  GUI's **Service & Firewall** tab → *Allow through Firewall*, or the CLI:

  ```
  printcap.exe -firewall add        :: per-port inbound allow rules for this exe
  printcap.exe -firewall remove
  ```

  Rules are now **per-port AND program-scoped**: printcap adds **one inbound
  allow rule per configured listener port** (named e.g. `printcap TCP 9100`,
  `printcap UDP 161`), each scoped to the printcap executable. `add` reads the
  ports from the live config, so re-run it after changing ports; `remove`
  deletes every printcap rule for the currently-configured ports. To scope by
  port manually instead, use Administrator PowerShell:

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

### Files, folders, and portability

printcap writes **all** generated files to configurable, executable-relative
folders, so the whole deployment is portable and nothing is ever auto-deleted
at shutdown:

| Content | Setting | Default |
|---------|---------|---------|
| Captured spool files + `.json`/decoded sidecars | `out_dir` (`-out`) | `<exe-dir>\captures` |
| Forward-retry queue (durable) + temp working files | `storage.spool_dir` | `<exe-dir>\spool` |
| Log file (rotating) | `log.file` (`-logfile`) | `<exe-dir>\printcap.log` |

**Relative paths resolve relative to the executable's directory**, not the
current working directory — important under the service, whose working
directory is `C:\Windows\System32`. Absolute paths are used verbatim. The
folders are created on first use; **nothing is auto-deleted** — manage
retention of captures, the `spool\forward-retry\dead\` dead-letter folder, and
old logs yourself (see §13, §16).

### Validating the config (`-check`)

Before starting listeners, dry-run the effective config:

```
printcap.exe -check
printcap.exe -config C:\printcap\printcap.json -check
```

`-check` validates the **effective** config (defaults + `-config` + flags),
prints every issue with a recommended fix, prints an
`N error(s), M warning(s)` summary, and **exits non-zero if there are any
errors** (so it slots into CI / a pre-deploy gate). It checks:

* **ports** — range (0–65535), privileged (<1024) warnings, and duplicate /
  conflicting listener ports (accounting for the `auto_tls` IPP+IPPS merge);
* **enums** — `save`, `log.level`, `log.format`, `log.syslog.network`,
  `ebcdic.carriage_control` / `default_code_page`, `lpd.queue_defaults[*]`,
  `forward.capture`, and each `forward.targets[*].transport` / `.failure`;
* **TLS** — that `cert_file`/`key_file` are set as a pair and the files exist;
* **storage** — that `out_dir` and `storage.spool_dir` can be created and
  written;
* **syslog** — that `address` is `host:port` and `facility` is 0–23 when
  enabled;
* **forward targets** — non-blank address and plausible `host:port` (raw/lpr)
  or URI (ipp/ipps);
* **DLP rules** — known `mode` (keyword|regex), non-blank pattern, and that
  regex patterns compile;
* **bind** — that a non-wildcard `bind` address is a valid IP or resolves.

The same validation runs **at startup** and logs each finding as a `[config]`
warning or error (non-fatal — the engine still starts and simply skips any
listener that can't bind). See §18 for using `-check` in troubleshooting.

---

## 7. Command-line flag reference

| Flag | Type | Effect |
|------|------|--------|
| `-config <path>` | string | Load a JSON config file (overlaid on defaults). Default: `printcap.json` next to the exe. |
| `-console` | bool | Run headless in the console instead of launching the GUI. |
| `-version` | bool | Print the printcap version (`printcap <ver>`) and exit. |
| `-check` | bool | Validate the effective config, print every issue + recommended fix, and exit **non-zero on errors** (see §6). |
| `-service <cmd>` | string | Windows service control: `install` \| `remove` \| `start` \| `stop` \| `status`. Self-elevates via UAC if not already elevated (except `status`). |
| `-firewall <cmd>` | string | Windows Firewall: `add` \| `remove` per-port inbound allow rules for this exe (§5). Self-elevates via UAC. |
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
  "out_dir": "captures",       // capture dir; relative = next to the exe
  "max_job_mb": 0,             // per-job byte cap; 0 = unlimited
  "notifications": true,       // GUI: show a tray balloon after each capture

  "storage": {
    "spool_dir": ""            // forward-retry queue + temp; blank = <exe-dir>/spool
  },

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

  "dlp": {                     // content inspection (alert-only; never blocks)
    "enabled": false,
    "rules": [                 // mode: keyword (substring) | regex (RE2)
      { "name": "US SSN", "mode": "regex", "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b" },
      { "name": "Confidential marking", "mode": "keyword", "pattern": "CONFIDENTIAL" }
    ]
  },

  "service": {                 // Windows run-as service account (blank = LocalSystem)
    "account": "",             // e.g. ".\\svc_printcap" or "DOMAIN\\user"
    "password": ""             // redacted in /api/config
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
* **`out_dir` / `storage.spool_dir` / `log.file`** — the three output
  locations. **Relative paths resolve relative to the executable** (portable);
  absolute paths are used as-is. `out_dir` holds captures; `storage.spool_dir`
  (blank = `<exe-dir>/spool`) holds the durable forward-retry queue and temp
  working files; `log.file` (blank = `<exe-dir>/printcap.log`) is the rotating
  log. None of these are auto-deleted — see §6 and §13.
* **`notifications`** — when `true` (default), the GUI shows a brief tray
  balloon after each capture. Set `false` to suppress the pop-ups (the console
  and service are unaffected).
* **`service.account` / `service.password`** — the Windows account the
  **installed service** runs as. Blank `account` = **LocalSystem** (the
  default; can bind privileged ports). Set `account` to `.\svc_printcap` or
  `DOMAIN\user` (with `password` if required) to run least-privilege; that
  account then needs write access to the capture/spool folders and the right
  to bind any privileged ports you use. `password` is stored in clear text in
  the config but **redacted in `/api/config`** — protect the file with ACLs
  (§14). These take effect at `-service install` time (§15).
* **`dlp`** — content inspection of captured documents (alert-only, never
  blocks). See §14.6.
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
  > against an `authNoPriv` user is refused). The v3 agent **validates the USM
  > privacy parameters and rejects malformed encrypted packets** (e.g. a bad
  > privacy-parameter length) rather than crashing. The agent remains
  > **read-only** — there is no SET support over any version. Note that v1/v2c
  > community strings are still sent in clear text unless you set
  > `allow_v1v2c: false`.
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
    * `spool_retry` — **durable** retry: the queued copy is persisted to
      `<spool_dir>/forward-retry` and retried with `retry.backoff_ms` up to
      `retry.max_attempts` or `retry.ttl_min`. Persisted items **survive a
      restart** — printcap **replays** them on the next start. A give-up (max
      attempts or TTL expired) is **dead-lettered** into the
      `<spool_dir>/forward-retry/dead/` sub-folder and **kept** for the
      operator (never auto-deleted).
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

## 9a. Network interception & full-traffic capture (optional, authorized use only)

> **Off by default. Authorized engagements only.** This mode captures traffic
> **not** addressed to printcap and can position the host on-path. Use it only on
> networks you have written authorization to capture on. Misuse may be illegal.

Enabled with `-intercept` (or `intercept.enabled: true`). It operates a layer
below the print listeners — it copies frames straight off the wire to a standard
libpcap file (`out_dir/capture.pcap`) and, optionally, reconstructs print jobs
from that traffic.

### Build requirement & platforms

| Platform | Backend | Build | Privilege |
|---|---|---|---|
| **macOS** | BPF (`/dev/bpf`) | plain `go build` (no cgo) | root, or membership in the `access_bpf` group |
| **Linux** | AF_PACKET socket | plain `go build` (no cgo) | root, or `CAP_NET_RAW` |
| **Windows** | Npcap | `CGO_ENABLED=1 go build -tags=npcap` (Npcap SDK) | Administrator + Npcap installed |

On macOS and Linux a default `go build` produces a binary that captures — no
cgo, no libpcap/Npcap. On Windows the live path needs the `-tags=npcap` build
(a default Windows build compiles everything *except* the capture driver and
logs that capture is unavailable). The rest of the feature — pcap file format,
stream carving, dashboard viewer/reassembly — is platform-neutral.

**macOS and Linux capture is passive (a read-only tap):** active ARP positioning
is offered **only** on the Windows/Npcap build. On Unix, `intercept.arp` is
ignored and the engine captures passively.

### Enforced authorization (`intercept.authorization`)

Intercept mode **refuses to start** unless an authorization record is present —
this is a precondition, not a comment:

| Field | Meaning |
|---|---|
| `acknowledged` | Operator attests they are authorized (also `-authorize`). Required `true`. |
| `operator` | Who is running the capture (`-operator`). Required. |
| `engagement` | Ticket / SOW reference granting authority (`-engagement`). Required. |
| `expiry` | Optional `YYYY-MM-DD` or RFC3339; capture refuses to start once past. |

`-check` reports any missing/expired authorization as a hard error. On start, a
prominent banner is logged and a provenance sidecar (`capture.pcap.authorization.txt`)
records who ran the capture, under what engagement, and when.

### Stream carving (`intercept.carve`)

Reconstructs print jobs from the captured traffic and feeds them through the same
pipeline as the live listeners, so documents land as typed files (`.jpg`, `.pcl`,
`.ps`, `.pdf`, …) **alongside** the raw pcap. On by default when intercept runs.

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Reconstruct files from captured streams. |
| `ports` | `[9100, 515, 631]` | Destination print ports to reassemble. |
| `max_stream_mb` | `256` | Per-stream size cap. |
| `idle_flush_sec` | `10` | Flush a stream idle this long. |

### Active ARP positioning (`intercept.arp`) — fail-closed

Optional on-path positioning. **There is no whole-subnet mode**: it acts only on
an explicit `targets` allow-list of host IPs and restores every cache it touched
on stop. With an empty `targets` list, positioning stays **off** regardless of
`enabled` (capture-only). `-check` validates the target/gateway IPs.

### Viewing captures

The dashboard's **Captures** panel renders the pcap as a color-coded, filterable
packet list (resets and ICMP errors highlighted; filter by class/protocol/text)
and offers a raw `.pcap` download. See §12.

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

## 12. The web dashboard & admin console

Browse to `http://HOST:8631/`. The dashboard is a live **admin console** that
streams updates over Server-Sent Events (no polling) and lets you search,
inspect, export, and prune captures, plus control listeners and the engine.

### UI features

* **Stat cards** — total jobs, total bytes, per-protocol counts; **live** via
  SSE.
* **Per-listener health** — each configured listener with its status, plus an
  **enable/disable** toggle (bounces the engine to apply).
* **Engine controls** — **Start / Stop / Restart** the capture engine from the
  toolbar.
* **Job table** with **search** (free-text `q`), **protocol filter**, **sort**
  (by any column) with **asc/desc** order, and **pagination**.
* **Job detail + text preview** — open a job to see its metadata and the first
  64 KiB of the captured bytes rendered as text.
* **Delete** — remove a job and all of its on-disk artifacts (spool file,
  `.json` sidecar, decoded sidecar, and any `-sent-*` transformed copies).
* **Export** — download the (filtered) job list as **CSV** or **JSON**.
* **Live log level** — change the running log level from the UI without a
  restart.
* **Settings editor** — edit *every* config field from the browser (scalars as
  inputs, list/map blocks as JSON), then **Save** or **Save & restart**. Secrets
  display as `***` and are preserved if left unchanged. Writes are refused from
  non-loopback clients unless `dashboard.allow_remote_admin` is set (see §14).
* **Captures viewer** — a packet window for intercept mode (§9a):
  * **Go live** — a scrolling, real-time view fed from an in-memory ring as
    packets arrive (pause / clear / auto-scroll; shows a "missed N" notice if a
    burst overruns the ring). **Refresh (static)** reads the saved pcap instead.
  * **Filtering** — by free text, **port**, **service** (HTTP/EWS, HTTPS, IPP,
    raw/9100, LPR, SNMP, SMB, WSD, mDNS), packet **class** (RST/ICMP-error/SYN/
    FIN/data), and protocol. Resets and ICMP errors are color-coded.
  * **Follow TCP stream** — click any TCP row to reassemble both directions
    (client→server / server→client) with an auto/text/hex view; HTTP shows as
    text, so **printer web-API (EWS/REST) and IPP exchanges are readable**. Each
    direction is downloadable, and the whole `.pcap` is one click away.

  Printer **API traffic** (the embedded web server / REST API on ports 80 and
  8080) is captured and reassembled like any other stream; HTTPS (443) is
  captured to the pcap but encrypted, so it can't be reassembled without keys.
* **Light / dark theme** toggle.

> **Note:** apply settings from *either* the native GUI *or* the web editor, not
> both against the same running instance at the same moment.

The dashboard keeps the **most recent 200 jobs** in memory for display; the full
history lives on disk in the capture folder. Document bytes are **not** held in
memory — previews and downloads stream from the saved file.

### JSON / API endpoints

**Read (GET):**

| Endpoint | Returns |
|----------|---------|
| `GET /api/stats` | Totals, per-protocol counts, active listeners, printer identity, save mode. |
| `GET /api/jobs` | **Paginated** envelope `{jobs, total, offset, limit}`. Query: `q`, `protocol`, `sort`, `order` (`asc`\|`desc`), `offset`, `limit` (default 50). |
| `GET /api/job?id=N` | Downloads the saved spool file for job `N` (`Content-Disposition: attachment`). 404 if no saved data (e.g. `-save meta`). |
| `GET /api/jobpreview?id=N` | First 64 KiB of the saved spool file as `text/plain` (for the detail preview). |
| `GET /api/export?format=csv\|json` | The filtered job list (same query params as `/api/jobs`, no pagination) as a downloadable CSV or JSON file. |
| `GET /api/listeners` | Runtime status of every configured listener. |
| `GET /api/events` | **Server-Sent Events** stream of live stats, listeners, and level (pushed on connect, then ~every 1.5 s). |
| `GET /api/config` | Effective configuration with **all secrets redacted** (SNMP community, SNMPv3 auth/priv passphrases, SMB passwords, service password, TLS cert/key paths). |
| `GET /api/logs?level=&n=` | Recent log entries (newest first), filtered by minimum level, capped by `n`. |
| `GET /api/logfile` | Downloads the active log file. |
| `GET /api/version` | `{ "version": "<ver>" }`. |

**State-changing (POST):**

| Endpoint | Effect |
|----------|--------|
| `POST /api/jobdelete?id=N` | Delete job `N` and its on-disk artifacts. |
| `POST /api/control?action=stop\|start\|restart` | Stop / start / restart the capture engine (responds, then bounces asynchronously — the dashboard briefly drops on stop/restart). |
| `POST /api/listener?name=<n>&enabled=<bool>` | Enable/disable a single listener, then restart the engine to apply. |
| `POST /api/loglevel?level=<lvl>` | Change the live log level without restarting. |

> **CSRF guard:** every **state-changing** endpoint requires the request header
> **`X-Requested-With: printcap`** (a browser cannot set a custom header on a
> cross-origin "simple" request without a CORS preflight, which this server
> never grants — so a site the operator visits can't drive-by POST to the local
> dashboard). The built-in UI sends this header automatically; if you script
> these endpoints with `curl`, add `-H "X-Requested-With: printcap"`.
>
> **No authentication.** The dashboard is **intentionally unauthenticated** —
> anyone who can reach the port sees job metadata and can download captured
> documents (the CSRF header is *not* an auth control). Bind it to a trusted
> segment or loopback (`-bind 127.0.0.1`), disable it (`-dash 0`), or front it
> with an authenticating reverse proxy if exposure is a concern. See §14.
>
> **Settings writes are loopback-only by default.** The settings editor's save
> endpoint refuses requests that did not originate from the local machine unless
> `dashboard.allow_remote_admin: true`. **Enabling that flag lets any host that
> can reach the dashboard rewrite the entire configuration** — including output
> paths, the forward-proxy targets (i.e. where captured jobs are sent), and the
> service account — on an unauthenticated service. Leave it `false` unless the
> dashboard is on a trusted, access-controlled segment. (Caveat: do not place a
> reverse proxy on the same host as the dashboard — every proxied request then
> appears to come from loopback and defeats this gate.)

---

## 13. Captured output on disk

Each accepted job produces, depending on `save` mode:

* a **raw spool file** — extension chosen from the document format or sniffed
  magic bytes: `.pdf`, `.ps`, `.pcl`, `.jpg`, else `.prn`.
* a **`.json` sidecar** — `protocol`, `source`, `received` (RFC3339),
  `job_name`, `user`, `host`, `queue`, `document_format`, `pdl`, `bytes`,
  `saved_as`, plus (when applicable) EBCDIC fields (`code_page`, `decoded_as`,
  `class`, `title`), `dlp_matches` (the names of any DLP rules the job hit —
  see §14.6), and `forwards` (per-target forward results).
* an EBCDIC **`-decoded.txt` sidecar** when a job is transcoded (see §9 / §8).
* transformed **`-sent-<target>` copies** for forwarded jobs (see §8).

Filenames are unique and time-ordered:

```
<timestamp>-<seq>-<protocol>[-<jobname>].<ext>

20260601-140444-0001-IPP-Report.json
20260601-140444-0001-IPP-Report.pdf
```

`<seq>` is a per-run counter; `<jobname>` is sanitized (unsafe characters → `_`).
Captures land in `out_dir`; the durable forward-retry queue (and its
`forward-retry\dead\` dead-letter folder) lives under `storage.spool_dir`
(see §6). **There is no automatic deletion or rotation of captures or
dead-lettered items — manage retention yourself** (see §16).

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
* **SNMP** is read-only, drops wrong-community requests silently. The **SNMPv3**
  agent validates USM privacy parameters and rejects malformed encrypted
  packets rather than crashing.
* **Secret redaction.** Secrets are stored **plaintext in the config file** but
  **redacted** everywhere they would otherwise be exposed — in `/api/config`
  and in logs. This covers the **SNMP community string**, **SNMPv3 auth/priv
  passphrases**, **SMB user passwords**, the **service password**, and the
  **TLS cert/key file paths**. Because the file itself holds them in clear,
  protect it with filesystem ACLs (see below).
* **Dashboard hardening.**
  * **CSRF guard** — state-changing endpoints require the
    `X-Requested-With: printcap` header (§12), blocking cross-site drive-by
    POSTs.
  * **No script execution from captured bytes** — responses that serve
    attacker-controlled file bytes (spool previews/downloads, log downloads)
    send `X-Content-Type-Options: nosniff` and a restrictive
    `Content-Security-Policy` (`default-src 'none'; sandbox`), so a hostile
    captured document can't run as script in the dashboard origin.
  * **CSV-injection-safe export** — cells that begin with `=`, `+`, `-`, `@`,
    tab, or CR are quoted so a malicious job name/user can't become a formula
    when the CSV export is opened in Excel/Sheets.
* **Download path safety** — only files inside the capture directory are served
  (filenames are constrained with `filepath.Base`).

### Operational considerations you must decide
* **The dashboard is unauthenticated.** On a shared network, bind it locally
  (`-bind 127.0.0.1`) or disable it (`-dash 0`). If remote access is needed,
  front it with a reverse proxy that adds authentication/TLS.
* **Captured spool files may contain sensitive documents.** Store the capture
  directory on an access-controlled volume; consider `-save meta` when you only
  need the audit trail, not contents. Apply NTFS ACLs and, where appropriate,
  disk encryption (BitLocker).
* **Protect the config file with ACLs.** Secrets (SNMP community, SNMPv3
  auth/priv passphrases, SMB passwords, the service password) live in
  `printcap.json` in **clear text** — they are only redacted in `/api/config`
  and logs, not on disk. Restrict the file (and the install folder) to
  administrators / the service account.
* **SNMP v1/v2c sends the community string in clear text** — this is inherent to
  the protocol. Treat SNMP as a discovery convenience, not a trust boundary.
  Disable with `-snmp 0` if not required.
* **`bind 0.0.0.0` exposes every listener on all interfaces.** Restrict to a
  management interface or use host/network firewall rules to limit who can
  reach it.
* **Run with least privilege.** Only use Administrator/privileged ports when you
  genuinely need 515/631/161; otherwise move to high ports and run as a normal
  account (or a dedicated service account — see §15).

### 14.6 Content inspection (DLP)

The `dlp` block scans **captured** documents for sensitive content and raises an
alert. It is **inspection-only** — it **never blocks or rejects** a job; it only
tags and logs. Off by default (`dlp.enabled: false`).

**How it works**

* Each captured job is scanned against every rule in `dlp.rules`. A rule has a
  `name`, a `mode` (`keyword` = case-insensitive substring, or `regex` = RE2),
  and a `pattern`.
* Matching runs over **both the raw captured bytes and the EBCDIC-decoded
  text** (the decoded sidecar from §9), so a mainframe job whose plaintext only
  exists after EBCDIC decoding is still inspected.
* On a hit, printcap **tags the job** — the matched rule names appear as
  `dlp_matches` in the job `.json` and in the dashboard/CSV export — and logs a
  **`[DLP]`** warning naming the job, source, and rules matched, e.g.:

  ```
  2026-06-01 14:04:44.812 WARN  [DLP] job "Report.pdf" from 10.0.0.5:51840 matched rule(s): US SSN, Confidential marking
  ```

**Configuration example**

```jsonc
"dlp": {
  "enabled": true,
  "rules": [
    { "name": "US SSN", "mode": "regex",
      "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b" },
    { "name": "Confidential marking", "mode": "keyword",
      "pattern": "CONFIDENTIAL" }
  ]
}
```

`printcap -check` validates rules (known `mode`, non-blank `pattern`, regex
compiles) before you deploy them (§6).

> **Limitation:** matching is over the document bytes (and any EBCDIC decode),
> so it does **not** see content inside **compressed page-description
> languages** — notably **PDF**, whose text/streams are usually deflated.
> Keyword/regex rules will not match such compressed content. DLP is most
> effective on text, PostScript, PCL, and EBCDIC line-printer streams.

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
The service commands **self-elevate** via UAC, so you can run them from an
ordinary prompt (a consent dialog appears); a pre-elevated Administrator prompt
also works:

```
printcap.exe -service install     :: register, auto-start at boot
printcap.exe -service start
printcap.exe -service status       :: read-only; does not elevate
printcap.exe -service stop
printcap.exe -service remove
```

* **Install** registers the service as **Automatic (Delayed Start)** — it
  starts after the network stack is up — with the command line
  `printcap.exe -config <path-to-printcap.json>` (the config path in effect when
  you installed: the `-config` flag, or `printcap.json` next to the exe).
* **Failure recovery.** Install configures the SCM **recovery actions** so the
  service **auto-restarts on crash**, giving unattended resilience without a
  watchdog.
* **Run-as account.** By default the service runs as **LocalSystem** (which can
  bind privileged ports). Set `service.account` (e.g. `.\svc_printcap` or
  `DOMAIN\user`) and `service.password` in `printcap.json` **before** installing
  to register the service under a dedicated least-privilege account instead;
  that account needs write access to the capture/spool folders and the right to
  bind any privileged ports you use. (`service.password` is redacted in
  `/api/config`; protect the config file — §14.)
* The service detects it was launched by the SCM and runs the capture engine
  headless. It logs to **`printcap.log`** next to the exe (rotating) and mirrors
  warnings/errors to the **Windows Event Log** (source "printcap") — see §16.
* **Remove** stops the service first, then deletes it (and deregisters the
  Event Log source).

### Start the tray GUI at login
The GUI's **Windows Service** tab has a **Start printcap when I sign in**
checkbox that adds/removes a per-user *Run* entry, so the tray app launches at
login. This is for the **interactive GUI** only — for unattended,
session-independent background capture use the **service** (or `-console`).

### Service checklist
* Set `out_dir` to an **absolute path** in `printcap.json` — a service's working
  directory is `C:\Windows\System32`, not your folder. Example:
  `"out_dir": "C:\\printcap\\captures"`. (The same applies to
  `storage.spool_dir` and `log.file` if you override them — relative paths
  resolve against the **exe directory**, not System32; see §6.)
* Re-run `-service install` (or use the GUI Install button) after moving the exe,
  so the registered path stays correct.
* Confirm the firewall rules from §5 exist — services don't trigger the
  interactive allow prompt.
* To run least-privilege, prefer `service.account`/`service.password` (above)
  at install time, or change the service's "Log On" account later in
  `services.msc`.

---

## 16. Logging & monitoring

printcap has a leveled, multi-sink logging subsystem.

**Levels** (lowest → highest verbosity): `error`, `warn`, `info` (default),
`debug`, `trace`. Set via the GUI **Logging** tab, `log.level` in the config, or
`-loglevel` / `-v` (debug) / `-vv` (trace). Each line is:

```
2026-06-01 14:04:44.812 INFO  [IPP] captured 12345 bytes from 10.0.0.5 user=alice job="Report.pdf" queue=/ipp/print pdl=PDF -> 20260601-...-IPP-Report.pdf
```

with a **component** tag: `[app] [engine] [9100] [LPR] [IPP] [SNMP] [svc]
[config] [DLP] [fwd]`.

The level can be changed **live** without a restart — from the dashboard
toolbar or `POST /api/loglevel?level=<lvl>` (§12) — in addition to the GUI,
`log.level`, and `-loglevel`/`-v`/`-vv`.

**What each level adds**
* `warn` — rejected jobs (disallowed LPD queue, non-privileged source port when
  required), wrong SNMP community, listener bind failures, **config validation
  findings** (`[config]` — the same checks `-check` runs, logged at startup),
  and **`[DLP]` content-inspection alerts** (§14.6).
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
| A listener is missing / something seems misconfigured | A port conflict, bad enum, unwritable folder, etc. | Run `printcap.exe -config … -check` for a full list of issues + recommended fixes (§6); the same findings are logged as `[config]` at startup |
| `dlp.rules` not matching, or a forward target failing repeatedly | Regex typo / wrong transport-address form | `-check` flags non-compiling regexes and implausible target addresses; check `[DLP]` / `[fwd]` log lines |
| A spooled forward never delivers | Target down; job is in the durable retry queue | Inspect `storage.spool_dir`\\`forward-retry` (and `…\dead\` for give-ups); items replay on restart (§9) |

### Diagnostic steps
1. **Validate the config** first: `printcap.exe -config <file> -check`. It prints
   every issue with a recommended fix and exits non-zero on errors (§6).
2. Run interactively (not as a service) from an Administrator prompt and watch
   the console — bind errors, `[config]` warnings, and per-job logs are immediate.
3. Confirm listeners: `netstat -ano | findstr "9100 515 631 6310 161 8631"`.
4. Test each path locally before involving real clients (see §19).

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

14. **Config validation (`-check`)** — run
    `printcap.exe -config <file> -check`. A clean config prints
    `0 error(s), 0 warning(s)` and exits 0. Introduce a fault (e.g. set two
    listeners to the same port, or `save: "xyz"`); `-check` reports the issue
    with a recommended fix and exits non-zero.

15. **DLP tagging** — set `dlp.enabled:true` with a rule, e.g.
    `{ "name":"US SSN", "mode":"regex", "pattern":"\\b\\d{3}-\\d{2}-\\d{4}\\b" }`.
    Send a job whose content contains a matching value (e.g. `123-45-6789`).
    Confirm the job `.json` lists the rule under `dlp_matches`, the dashboard
    shows the tag, and a `[DLP]` WARN line names the job and rule(s). The job is
    still captured normally (DLP never blocks).

16. **Dashboard admin features** — in `http://HOST:8631/`: **filter** the job
    table by protocol and search text; open a job's **detail/preview**;
    **delete** a job and confirm its files disappear from the capture folder;
    **export** the list as CSV and JSON; toggle a listener **off** (per-listener
    health control) and confirm that port stops `LISTENING`, then back on. (State
    changes require the `X-Requested-With: printcap` header, which the UI sends;
    a scripted `curl` without it gets HTTP 403.)

17. **Durable forwarding** — set a target with `failure: "spool_retry"` pointing
    at a port with **no** listener (so delivery fails). Print a job; confirm a
    queued item appears under `storage.spool_dir`\\`forward-retry`. **Stop
    printcap, then restart it** and confirm the item is **replayed** (a
    `spool: replaying item …` log line). Start a listener at the target and
    confirm delivery completes and the queued item is removed; or let it exhaust
    `retry.ttl_min`/`max_attempts` and confirm it is **dead-lettered** into
    `forward-retry\dead\` (kept, not deleted).

If all seventeen pass, the deployment is good.

---

## 20. Upgrade & uninstall

**Upgrade:** stop the process/service, replace `printcap.exe` with the new
build, restart. Config files, captures, and the spool/retry queue are
unaffected. After replacing the exe, re-run `-service install` so the
registered path stays correct (§15). Confirm the new build with
`printcap.exe -version`.

**Uninstall (installer build):** use *Apps & features* / the bundled
uninstaller. It stops and removes the service (deregistering the Event Log
source) and deletes the firewall rules, but **deliberately keeps** your
captured data, the spool/retry queue, and `printcap.json` — remove those
manually if you no longer need them.

**Uninstall (xcopy build):**
1. Stop and remove the service if installed (self-elevates via UAC):
   `printcap.exe -service stop` then `printcap.exe -service remove`. This also
   deregisters the Event Log source.
2. Remove the firewall rules: `printcap.exe -firewall remove` (deletes the
   per-port printcap rules for the currently-configured ports).
3. Delete the `C:\printcap\` folder (including `captures\`, `spool\`, and
   `printcap.log`, if no longer needed).

The only persistent system footprint is the service entry, the Event Log
source, the firewall rules (all removed above), and — if you enabled
*start at login* (§15) — a per-user *Run* registry value, which that checkbox
removes when unticked.

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
