# printcap

A single-file, self-contained Windows utility that acts as a configurable
network **print server** — it impersonates a printer across every common print
transport, captures the raw spool data sent to it, is **discoverable over SNMP**
like a real device, and gives you a **live web dashboard** of everything it
catches. Point any host's print queue at the machine running `printcap` and
every job is written to disk.

It ships with a **native Windows settings GUI** (minimizes to the system tray)
and can **install itself as a Windows service** to run unattended at boot.

No runtime, no installer, no dependencies — one `printcap.exe`.

## What it does

| Capability | Default port | Notes |
|-----------|-------------:|-------|
| Raw / JetDirect / AppSocket | TCP 9100 | Plain byte stream — the most common path |
| LPR / LPD | TCP 515 | RFC 1179; extracts host/user/job-name from the control file |
| IPP | TCP 631 | IPP-over-HTTP; full driverless/IPP-Everywhere attribute set |
| IPPS | TCP 6310 | IPP-over-TLS; self-signed cert generated in memory |
| SNMP agent | UDP 161 | v1/v2c; answers Get/GetNext/GetBulk so scanners discover it as a printer |
| Web dashboard | TCP 8631 | Live job feed, per-protocol stats, one-click downloads |

A single port can serve **both** IPP and IPPS by sniffing the TLS handshake — see `auto_tls`.

**Enterprise-ready capture:** every protocol has configurable options —

* **RAW/9100:** extra multi-port listeners (9101/9102), PJL job-name/user parsing, UEL job-splitting
* **LPR/LPD:** accept-any-queue (records the queue name), allowed-queue allow-list, lenient source-port policy (captures from SAP access-method U, IBM AS/400 RMTOUTQ, z/OS, Linux/CUPS), PJL fallback
* **IPP/IPPS:** configurable advertised resource paths (`/ipp/print`, `/printers/…`), supply your own cert/key or generate a self-signed one
* **PDL auto-detection:** PostScript, PDF, PCL, PCL-XL, PWG Raster, Apple URF, XPS, AFP, ZPL, EPL, Prescribe, TIFF/JPEG/PNG and more — seen through any PJL preamble
* **Windows Firewall:** one click (or `-firewall add`) to allow the listeners through

## Build

Needs [Go](https://go.dev/dl/). Then:

```
build.bat
```

or directly:

```
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w -H windowsgui" -o printcap.exe .
```

`-H windowsgui` means no console window pops up when the GUI launches. The
embedded application manifest (`rsrc_windows_amd64.syso`, committed) gives the
GUI themed controls and high-DPI awareness; regenerate it only if you edit
`printcap.manifest`. Result: one self-contained `printcap.exe`, no dependencies.

## Run

### GUI (default)

Double-click **printcap.exe**. A settings window opens with tabs for the capture
directory, each protocol's enable toggle + port, printer identity, SNMP, and the
Windows service. **Start/Stop** runs the capture engine; closing the window
minimizes it to the **system tray** (right-click the tray icon for Open /
Dashboard / Capture folder / Exit). Settings are saved to `printcap.json` next
to the exe.

> The GUI runs un-elevated. To bind ports below 1024 (515/631/161) or install
> the service, right-click → **Run as administrator**.

### Console (headless)

```
printcap.exe -console
```

Binds the enabled ports, writes jobs to `captures\`, runs the SNMP agent and
dashboard, logs to the console. Open **http://localhost:8631/**.

### Windows service

```
printcap.exe -service install     (as Administrator)
printcap.exe -service start
printcap.exe -service status
printcap.exe -service stop
printcap.exe -service remove
```

The service runs automatically at boot using the settings in `printcap.json`.
You can do all of this from the GUI's **Windows Service** tab instead. When the
service is installed, the GUI's Start/Stop button controls the *service*;
otherwise it runs the engine in-process.

Ports below 1024 (515, 631, 161) require Administrator, and Windows Firewall
will prompt to allow it the first time.

## Configuration

Everything is configurable. Three layers, applied in order: **built-in defaults
→ JSON config file → command-line flags** (flags win).

### Quick flags

```
printcap.exe -ipp 631 -ipps 0 -lpr 0 -raw 9100      # only 9100 + IPP
printcap.exe -auto-tls 631 -ipps 0                  # IPP and IPPS share port 631
printcap.exe -save meta                             # log who printed what, discard data
printcap.exe -bind 192.168.1.50                     # bind one interface only
printcap.exe -snmp 0 -dash 0                         # disable SNMP and the dashboard
printcap.exe -model "HP LaserJet M607" -community public
printcap.exe -cert mycert.pem -key mykey.pem        # real TLS cert for IPPS
```

| Flag | Meaning |
|------|---------|
| `-config <file>` | Load a JSON config file |
| `-dump-config <file>` | Write the effective config to a file (or `-` for stdout) and exit |
| `-console` | Run headless in the console instead of the GUI |
| `-service <cmd>` | `install` \| `remove` \| `start` \| `stop` \| `status` |
| `-firewall <cmd>` | `add` \| `remove` Windows firewall inbound rules (Administrator) |
| `-v` / `-vv` | Verbose: debug / trace logging |
| `-loglevel <lvl>` | `error` \| `warn` \| `info` \| `debug` \| `trace` |
| `-logfile <path>` | Log file path (default `printcap.log` next to the exe) |
| `-bind` | Interface to bind all listeners to |
| `-raw` / `-lpr` / `-ipp` / `-ipps` | Per-protocol ports (`0` disables) |
| `-auto-tls` | One port that auto-detects TLS vs plaintext IPP |
| `-dash` / `-snmp` | Dashboard / SNMP ports (`0` disables) |
| `-out` | Capture output directory |
| `-save` | `both` \| `raw` \| `meta` |
| `-cert` / `-key` | TLS cert/key PEM for IPPS (self-signed if omitted) |
| `-community` | SNMP community string |
| `-model` | Printer make-and-model advertised over IPP/SNMP |

### Full config file

For everything else (printer identity, advertised capabilities, SNMP details,
file-type policy), dump a template and edit it:

```
printcap.exe -dump-config printcap.json
notepad printcap.json
printcap.exe -config printcap.json
```

A ready-to-edit `printcap.sample.json` is included. Key sections:

* **`printer`** — `name`, `info`, `make_and_model`, `location`, `serial`;
  `document_formats` (MIME types advertised **and** accepted),
  `enforce_formats` (reject IPP jobs whose format isn't in the list),
  `color`, `sides`, `resolutions` (dpi), `media`. These drive the IPP
  `Get-Printer-Attributes` response, so you can impersonate a specific device or
  restrict it to certain page-description languages.
* **`snmp`** — `enabled`, `community`, `sys_descr`, `sys_name`, `sys_location`,
  `sys_contact`, `sys_object_id` (vendor OID), `page_count`, `toner_level_pct`.
* **`tls`** — `cert_file` / `key_file` (self-signed if blank).
* **`raw`** — `extra_ports` (e.g. `[9101, 9102]`), `parse_pjl`, `split_on_uel`.
* **`lpd`** — `accept_any_queue`, `allowed_queues`,
  `require_privileged_source_port` (RFC 1179 721–731; default off = permissive),
  `parse_pjl`.
* **`ipp_options`** — `resource_paths` (advertised printer-uri paths),
  `default_path`.
* **`log`** — `level` (error/warn/info/debug/trace), `file`, `format`
  (text/json), `json_file` (separate JSON-lines feed), `max_size_mb`,
  `max_backups`, `console`, `protocol` (promote per-connection detail to INFO),
  `event_log` (Windows Event Log), and `syslog` (`enabled`, `network`,
  `address`, `facility`, `rfc5424`, `app_name`) for remote collectors.
* **`max_job_mb`** — per-job byte cap (`0` = unlimited).

All of these are also editable in the GUI (RAW & LPR, IPP & TLS tabs), which has
a built-in **Help** button with a full protocol / PDL / troubleshooting guide.

## Dashboard

`http://<host>:8631/` shows live stat cards (total jobs, total bytes,
per-protocol counts), the configured listeners, and a table of captured jobs
(time, protocol, source IP, user, host, job name, format, size) with a
**download** link per job, plus a **live log** panel with a level filter. It
auto-refreshes every 2 s. JSON API: `/api/stats`, `/api/jobs`, `/api/config`,
`/api/job?id=N` (download), `/api/logs?level=debug&n=300`.

## Logging

Leveled, per-component, multi-sink logging:

* **Levels:** `error` → `warn` → `info` (default) → `debug` → `trace`. Each line
  is tagged with a component: `[engine] [9100] [LPR] [IPP] [SNMP] [svc] [app]`.
* **Protocol detail:** debug/trace log every connection, LPD subcommand, IPP
  operation, and SNMP OID. The `log.protocol` switch (or the GUI checkbox)
  promotes that detail to INFO so it shows without raising the whole level.
* **Sinks:** rotating **file** (`printcap.log`, size-based rotation with N
  backups), **console** (`-console` mode), the **dashboard** live-log panel
  (with a **download full log** link), and the **Windows Event Log** (warn/error)
  when running as a service.
* **SIEM export:** a **JSON-lines** file for file-tailing shippers (Splunk
  forwarder, Filebeat, Fluent Bit), and **remote syslog** (UDP/TCP, RFC 3164 or
  RFC 5424) for collectors like rsyslog, Graylog, and Splunk. You can also set
  the primary file format to `json`.
* **Quick verbose:** `printcap.exe -console -v` (debug) or `-vv` (trace).

The GUI has a **Logging** tab (level, format, rotation, JSON-lines + syslog
export, toggles, Open Log File) and the Help window has a full logging guide.

## SNMP discovery

The built-in agent answers the OID trees discovery tools query:

* **System group** (RFC 1213) — `sysDescr`, `sysObjectID`, `sysName`, …
* **Host Resources MIB** (RFC 2790) — `hrDeviceType` returns `hrDevicePrinter`,
  which is how scanners distinguish a printer from a PC.
* **Printer MIB** (RFC 3805) — `prtGeneralPrinterName`, serial, page count,
  toner level, console "Ready" text.

It supports Get, GetNext and GetBulk, so tools can both probe known OIDs and
`snmpwalk` it. Requests with the wrong community string are dropped silently.

Verify with net-snmp:

```
snmpwalk -v2c -c public <host> 1.3.6.1.2.1.1
snmpget  -v2c -c public <host> 1.3.6.1.2.1.25.3.2.1.2.1   # -> hrDevicePrinter
```

### SNMPv3 (USM)

Enable `snmp.v3_enabled` and define `snmp.users` to serve the same MIB over
authenticated/encrypted SNMPv3. Each user sets a `level` (noAuthNoPriv |
authNoPriv | authPriv), an `auth_protocol` (MD5 | SHA-1 | SHA-256 | SHA-512) +
`auth_pass`, and a `priv_protocol` (DES | AES-128 | AES-192 | AES-256) +
`priv_pass`. v1/v2c keep working unless `allow_v1v2c:false`. Example:

    snmpget -v3 -l authPriv -u admin -a SHA-256 -A secretauth \
            -x AES -X secretpriv HOST 1.3.6.1.2.1.1.1.0

A requested security level may not exceed the user's configured level. Engine
discovery (the SNMPv3 probe for the agent's engine ID) is answered automatically.
Passphrases are redacted from the dashboard's `/api/config`.

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

## Output

Each job produces (depending on `-save`):

* a raw spool file — extension guessed from document format or magic bytes
  (`.pdf`, `.ps`, `.pcl`, `.jpg`, else `.prn`)
* a `.json` sidecar: protocol, source IP, timestamp, user, host, job name,
  document format, byte count

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

## Mainframe & EBCDIC (z/OS, IBM i / AS-400)

Mainframe and midrange hosts print over LPR/LPD and often send **EBCDIC** data
with ASA or machine carriage-control. printcap transcodes these to readable UTF-8
while keeping the raw bytes: it writes a `<base>-decoded.txt` sidecar alongside
the raw spool.

Configure under `ebcdic` (`enabled`, `default_code_page`, `auto_detect`,
`decoded_sidecar`, `carriage_control`) and map specific LPD queues under
`lpd.queue_defaults`, e.g.
`"mvs*": {"code_page":"CP037","carriage_control":"asa","ebcdic":true}`.
Resolution order per job: a matching `lpd.queue_defaults` glob → the global
default when `auto_detect` flags the bytes as EBCDIC → otherwise left raw.
Built-in code pages: **CP037** (US/Canada), **CP500** (International), **CP1047**
(Open Systems / z/OS), **CP273** (Germany), **CP285** (UK), **CP297** (France).
The richer LPD control file also captures Class (`C`) and Title (`T`); a FORTRAN
carriage-control (`r`) data line hints ASA.

## How clients reach it

* **Raw/9100** — add a "Standard TCP/IP Port" printer pointing at the host, "Raw", port 9100.
* **LPR** — same wizard, choose "LPR", any queue name.
* **IPP/IPPS** — add an IPP printer with URL `http://HOST:631/` (or `https://HOST:6310/`). CUPS/macOS/Linux work too.

## Production hardening

The tool is built to be left running on a network, not just demoed:

* **Bounded memory.** Untrusted length fields (LPD `count`) are never used to
  pre-allocate — buffers grow only as bytes actually arrive. Set `max_job_mb`
  to cap every job (raw/9100, LPR, IPP body) at read time; `0` means unlimited,
  so set a value if the host faces untrusted senders.
* **Timeouts everywhere.** Print connections have a 60 s idle timeout (no
  goroutine leaks from half-open sockets); HTTP listeners set read-header,
  write, and idle timeouts and a header-size cap (defeats Slowloris).
* **TLS 1.2 minimum** for IPPS.
* **SNMP** drops requests with the wrong community string silently and only
  exposes a fixed, read-only MIB (no SET support).
* **Dashboard secrets** (SNMP community, TLS key paths) are redacted from
  `/api/config`.

Two operational caveats to decide on for your environment:

* **The dashboard has no authentication.** Anyone who can reach its port sees
  captured job metadata and can download spool files. On a shared network, set
  `bind` to `127.0.0.1` (local only) or disable it with `-dash 0`.
* **SNMP is UDP** and community strings are sent in clear text (true of all
  SNMP v1/v2c). Treat it as a discovery convenience, not a security boundary;
  disable with `-snmp 0` if not needed.

## Scope / intent

A capture/diagnostic tool for print-infrastructure testing and security
assessment on networks you are authorized to test. It receives jobs sent to it
and answers SNMP queries about itself; it does not intercept traffic destined
elsewhere.
