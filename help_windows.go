//go:build windows

package main

import (
	"strings"

	"github.com/lxn/walk"
	dec "github.com/lxn/walk/declarative"
)

// showHelp opens (or re-focuses) the Help & Troubleshooting window.
func showHelp() {
	if helpWin != nil {
		helpWin.Show()
		helpWin.SetFocus()
		return
	}
	_ = dec.MainWindow{
		AssignTo: &helpWin,
		Title:    "printcap — Help & Troubleshooting",
		MinSize:  dec.Size{Width: 720, Height: 560},
		Size:     dec.Size{Width: 780, Height: 640},
		Layout:   dec.VBox{},
		Children: []dec.Widget{
			dec.TabWidget{
				Pages: []dec.TabPage{
					helpPage("Getting started", helpOverview),
					helpPage("Protocols", helpProtocols),
					helpPage("PDLs", helpPDLs),
					helpPage("SNMPv3 (USM)", helpSNMPv3),
					helpPage("Discovery", helpDiscovery),
					helpPage("SMB share", helpSMB),
					helpPage("Mainframe / EBCDIC", helpEBCDIC),
					helpPage("Forward proxy", helpForward),
					helpPage("Content (DLP)", helpDLP),
					helpPage("Enterprise sources", helpEnterprise),
					helpPage("Dashboard", helpDashboard),
					helpPage("Packet capture", helpIntercept),
					helpPage("Files & storage", helpStorage),
					helpPage("Logging", helpLogging),
					helpPage("Troubleshooting", helpTrouble),
				},
			},
		},
	}.Create()
	if helpWin != nil {
		helpWin.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
			helpWin = nil // allow it to be recreated next time
		})
		helpWin.Show()
	}
}

func helpPage(title, body string) dec.TabPage {
	return dec.TabPage{
		Title:  title,
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.TextEdit{
				Text:     strings.ReplaceAll(body, "\n", "\r\n"),
				ReadOnly: true,
				VScroll:  true,
			},
		},
	}
}

const helpOverview = `printcap — network print capture

printcap impersonates a network printer across every common print transport,
captures the raw spool data sent to it, answers SNMP discovery like a real
device, and shows a live web dashboard of everything it catches.

QUICK START
New to printcap? The "Quick Start" tab is the simple view: status, a big
Start/Stop, and one-click buttons for the dashboard, capture window, folder, and
this help. Everything below is the detailed (advanced) path through the tabs.
1. On the "Protocols & Ports" tab, enable the protocols you need and set ports.
2. On "General", choose a capture directory and a save mode.
3. Click Start. Send a print job to this machine's IP address.
4. Click "Open Dashboard" to watch jobs arrive, or "Open Folder" for the files.

EVERYTHING IS CONFIGURABLE HERE
The GUI now exposes every feature through its tabs: General, Protocols & Ports,
RAW & LPR, IPP & TLS, Printer Identity, SNMP (incl. SNMPv3/USM), Discovery
(mDNS + WSD), SMB Share, Mainframe / EBCDIC, Forward Proxy, Content / DLP,
Logging, and Service & Firewall. Each tab has a matching help page in this
window.

RUN MODES
- GUI (this window): runs the capture engine in-process. CLOSING THE WINDOW
  QUITS printcap -- the engine stops and the process exits. That is expected.
  For always-on capture that survives logoff/reboot, install the Windows
  service (Service & Firewall tab) or run "printcap.exe -console".
- Service: install on the "Service & Firewall" tab to run unattended at boot.
  When the service is installed, Start/Stop here controls the service.
- Console: run "printcap.exe -console" for a headless command-line mode.

PRIVILEGES & FIREWALL
- Ports below 1024 (515, 631, 161) and installing the service require running
  printcap as Administrator. Service install and firewall rules now prompt for
  Administrator automatically (a UAC dialog) -- you no longer have to relaunch
  by hand.
- Use "Allow through Firewall" on the Service & Firewall tab so other machines
  can reach the listeners.

SAVE MODES
- both: raw spool file + a .json metadata sidecar (default)
- raw:  spool file only
- meta: metadata only; document bytes are discarded (privacy-preserving audit)

HANDY COMMAND-LINE FLAGS
- printcap.exe -check     validate the effective config and print recommended
                          fixes (duplicate/privileged ports, bad paths, ...).
- printcap.exe -version   print the version and exit.
- printcap.exe -console   run headless (no GUI window).
`

const helpProtocols = `PROTOCOLS

RAW / JetDirect / AppSocket (TCP 9100)
  The simplest and most common path: the sender streams the print data and
  closes the socket. No metadata on the wire.
  Options (RAW & LPR tab):
   - Extra raw ports: multi-port print servers use 9101/9102 for ports 2/3.
   - Parse PJL: pulls job name / user from an @PJL preamble if present.
   - Split on UEL: when a spooler sends several jobs on one connection, capture
     each (framed by the Universal Exit Language) as a separate job.

LPR / LPD (TCP 515)  — RFC 1179
  An ACK-driven conversation. printcap captures the queue name plus host, user,
  and job name from the LPD control file.
  Options (RAW & LPR tab):
   - Accept any queue: recommended; record whatever queue the sender names.
   - Allowed queues: when "accept any" is off, only these names are accepted.
   - Require privileged source port: RFC 1179 says clients use ports 721-731.
     Leave OFF to accept jobs from appliances and apps that use high ports.
   - Parse PJL in data: fills job name / user from PJL if the control file lacks
     them.

IPP (TCP 631) and IPPS (TCP 6310, TLS)
  IPP-over-HTTP(S). printcap answers Get-Printer-Attributes with a full
  driverless / IPP-Everywhere attribute set so clients commit the job, then
  captures the document. The IPP resource path the client used is recorded.
  Options (IPP & TLS tab):
   - Advertised paths: e.g. /ipp/print, /ipp, /printers/<name>, /printer.
   - Primary path: used in the printer-uri.
   - Certificate / key: supply a PEM cert+key for IPPS, or click
     "Generate self-signed cert + key" to create one. Blank = self-signed in
     memory (clients must skip validation).

Auto-TLS single port
  One port can serve BOTH IPP and IPPS by sniffing the first byte (0x16 = TLS).
  Enable it on Protocols & Ports as "IPP+IPPS auto-detect".

SNMP agent (UDP 161)
  Answers Get / GetNext / GetBulk for the system, Host-Resources and Printer
  MIBs so fleet scanners discover this host as a printer. Read-only; requests
  with the wrong community string are dropped. Configure identity on the SNMP
  tab. For secure SNMPv3/USM see the "SNMPv3 (USM)" help page.

Discovery (mDNS/Bonjour + WSD)
  Advertisement only -- these make printcap show up automatically in print
  dialogs and in Windows "Add a device". The actual capture still happens over
  the listeners above. See the "Discovery" help page.

SMB print share (experimental)
  An SMB2/3 share so Windows shops can "Add a printer" by browsing to it. Off by
  default, on a non-445 port. See the "SMB share" help page.

Web dashboard (TCP 8631)
  Live job feed, per-protocol stats, and per-job download/preview/delete. Not
  password-protected -- bind to loopback or disable it on a shared network. See
  the "Dashboard" help page.
`

const helpPDLs = `PAGE-DESCRIPTION LANGUAGES (PDLs)

printcap auto-detects the PDL of every captured job (shown as "pdl=" in the log
and in the dashboard) and picks a matching file extension. Detection sees
through any UEL + @PJL preamble first, then matches magic bytes.

Detected PDLs and extensions:
  PostScript ............ .ps    (%!)
  PDF ................... .pdf   (%PDF)
  PCL (PCL5) ............ .pcl   (ESC E / ESC & / ESC ( / ESC *)
  PCL-XL (PCL6) ......... .pclxl () HP-PCL XL)
  PWG Raster ............ .pwg   (RaS2 / RaS3)
  Apple Raster (URF) .... .urf   (UNIRAST)
  XPS / OpenXPS ......... .xps   (PK.. ZIP container)
  AFP (IBM MO:DCA) ...... .afp   (0x5A structured fields)
  ZPL (Zebra) ........... .zpl   (^XA ... ^XZ)
  EPL (Eltron) .......... .epl
  Prescribe (Kyocera) ... .pre   (!R!)
  TIFF / JPEG / PNG ..... .tif / .jpg / .png
  ESC/P, ESC/POS ........ .escp  (ESC @)
  Plain text ............ .txt
  Unknown ............... .prn   (raw fallback; bytes are intact)

Notes:
 - Kyocera KPDL is PostScript-compatible and is detected as PostScript.
 - IPDS (IBM) and SAP/SAPGOF are transported but may show as Unknown/AFP; the
   raw bytes are always preserved regardless of detection.
 - The IPP "document-format" the client advertised is recorded separately and
   used as a hint when byte-sniffing is inconclusive.

The advertised IPP document-format-supported list is configurable in the JSON
config (printer.document_formats); enable "Reject IPP jobs with unsupported
document formats" on the Printer Identity tab to emulate a device that only
accepts certain PDLs.
`

const helpEnterprise = `CAPTURING FROM ENTERPRISE SYSTEMS

SAP
  - Access method U ("Print on LPDHOST using Berkeley protocol") sends standard
    LPR/LPD. Point the SAP output device's host at this machine; printcap's LPR
    listener captures it. The SAP queue/host-printer name is recorded.
  - Access method S (SAPLPD / SAP protocol) and F/L also ultimately deliver via
    LPD or a host spooler. Use access method U for the cleanest capture.
  - Keep "Accept any queue" ON and "Require privileged source port" OFF.

IBM i (AS/400 / iSeries)
  - Create a remote output queue (CRTOUTQ ... RMTSYS(*INTNETADR)
    RMTPRTQ('queue') CNNTYPE(*IP) DEST(*OTHER) TRANSFORM(*YES/*NO)). This sends
    RFC 1179 LPR; printcap captures it. Host print transform (*YES) yields PCL/
    PostScript; *NO yields SCS/AFP/IPDS.
  - IBM i can also print via IPP — use the IPP listener.

IBM z/OS mainframe
  - z/OS Infoprint / PSF can route via LPR (NETSPOOL / IP PrintWay) to this
    host, or via IPP. AFP/IPDS data is captured raw.

  EBCDIC line-data from z/OS, IBM i, or AS/400 is decoded to readable UTF-8 (and
  written as a -decoded.txt sidecar). Code page, carriage control, and per-queue
  overrides are on the "Mainframe / EBCDIC" tab -- see that help page.

Linux / Unix / CUPS
  - lpadmin -p printcap -E -v lpd://HOST/queue        (LPR)
  - lpadmin -p printcap -E -v socket://HOST:9100      (RAW)
  - lpadmin -p printcap -E -v ipp://HOST:631/ipp/print -m everywhere  (IPP)

Windows
  - Add a Standard TCP/IP Port (Raw 9100 or LPR) pointing at this host, or add
    an IPP printer at http://HOST:631/.

General guidance for "accept from anything":
  - LPR: Accept any queue = ON, Require privileged source port = OFF.
  - RAW: enable Parse PJL; enable Split on UEL if a spooler batches jobs.
  - IPP: keep several resource paths advertised so different clients match.
`

const helpLogging = `LOGGING

printcap has a leveled, multi-sink logging system. Every event is tagged with a
component ([engine], [9100], [LPR], [IPP], [SNMP], [svc], [app]) and a level.

LEVELS (Logging tab -> Log level)
  error  - failures only
  warn   - + rejected jobs, wrong SNMP community, bind problems
  info   - + each capture, listener start/stop (the normal default)
  debug  - + connections, spool-file writes, IPP operations
  trace  - + every LPD subcommand, every SNMP OID requested (very verbose)

VERBOSE PROTOCOL LOGGING
  Tick "Verbose protocol logging" to promote per-connection / per-operation
  detail to INFO so it shows even at the default level. Or just set the level to
  debug / trace.

WHERE LOGS GO
  - File: printcap.log next to the exe by default (set a path on the Logging
    tab). It rotates at the configured size, keeping N backups (.1, .2, ...).
  - Console: shown when running with -console (tick "Also log to console").
  - Dashboard: the "Live log" panel streams recent entries with a level filter
    (http://HOST:8631/, or the JSON at /api/logs?level=debug&n=300). It also has
    a live log-level control -- change the running engine's level on the fly
    (no restart, no config edit) right from the browser.
  - Windows Event Log: when running as a service with "Mirror to Event Log"
    enabled, warnings and errors appear in Event Viewer -> Windows Logs ->
    Application, source "printcap".

SIEM EXPORT (Splunk / ELK / Graylog)
  Two independent feeds on the Logging tab:
  - JSON-lines file: one JSON object per line (time, level, component,
    message). Point a file shipper (Splunk Universal Forwarder, Filebeat,
    Fluent Bit) at it. The human-readable printcap.log is kept separately.
  - Remote syslog: ship every record to a syslog collector over UDP or TCP.
    Set host:port, facility (16 = local0), and RFC 3164 (BSD) or RFC 5424
    framing. Works with rsyslog, syslog-ng, Graylog, Splunk, etc.
  You can also set "File format" to json to make printcap.log itself JSON.

DOWNLOAD
  The dashboard's Live log panel has a "download full log" link
  (http://HOST:8631/api/logfile).

COMMAND LINE
  printcap.exe -console -v          (debug)
  printcap.exe -console -vv         (trace)
  printcap.exe -console -loglevel debug -logfile C:\logs\printcap.log

Buttons: "Open Log File" opens the current log; "Open Folder" opens its
directory.
`

const helpTrouble = `TROUBLESHOOTING

First step: validate your config
  Run "printcap.exe -check" -- it validates the effective config and prints
  recommended fixes (duplicate ports, privileged ports, bad/missing paths,
  conflicting options). Fastest way to find a misconfiguration.

The window closed and capture stopped
  That's expected: closing the GUI window exits printcap. For background capture
  that keeps running after you close the window (or log off), install the
  Windows service on the Service & Firewall tab, or run "printcap.exe -console".

"bind: permission denied" / a listener didn't start
  Ports 515, 631, 161 need Administrator. Right-click printcap -> Run as
  administrator, or move to high ports (e.g. LPR 1515) on Protocols & Ports.
  "printcap -check" flags privileged ports and duplicate port assignments.

UAC / "run as Administrator" for service or firewall
  Installing/removing the service and adding firewall rules now prompt for
  Administrator automatically (a UAC dialog pops up). Approve it; you don't have
  to relaunch printcap by hand.

"bind: address already in use"
  Another service owns the port. On Windows the built-in SNMP Service holds UDP
  161, and the Print Spooler / an LPD service may hold 515/631. Stop the
  conflicting service or change printcap's port.

Jobs never arrive
  - Check the firewall: Service & Firewall tab -> Allow through Firewall.
  - Confirm the client targets this host's IP and the right port/protocol type
    (Raw vs LPR vs IPP).
  - Watch the status: click Start; the status bar should read "Running".

LPR client says "rejected" or hangs
  - Turn ON "Accept any queue" and turn OFF "Require privileged source port".
  - Some clients send the data file before the control file — printcap handles
    both orders.

IPP job rejected (document-format)
  - Turn OFF "Reject IPP jobs with unsupported document formats" (Printer tab),
    or add the format to printer.document_formats in the config.

IPPS client refuses to connect
  - The default certificate is self-signed. Click "Generate self-signed cert +
    key" and import the cert into the client, or supply a trusted cert/key, or
    configure the client to skip validation.

PDL shows as "Unknown"
  - The bytes are still captured intact (saved as .prn). Unknown just means the
    format wasn't recognized by magic bytes (e.g. a proprietary or encrypted
    stream). The IPP document-format, if advertised, is recorded too.

Dashboard shows nothing / download is missing
  - Ensure the dashboard port is enabled. In "meta" save mode no spool file is
    written, so downloads are unavailable by design.

Service installed but captures nothing
  - Set an ABSOLUTE capture directory (a service's working directory is
    C:\Windows\System32). The service logs to printcap-service.log next to the
    exe.

Where are my files?
  - Click "Open Folder". Each job is <timestamp>-<seq>-<proto>[-<job>].<ext>
    plus a matching .json with all the metadata.
`

const helpSNMPv3 = `SNMPv3 (USM) — secure SNMP

The SNMP tab can run the agent in secure SNMPv3 mode (User-based Security Model)
in addition to, or instead of, the legacy v1/v2c community model. Fleet and
monitoring tools (HP Web Jetadmin, PRTG, SolarWinds, LibreNMS, Nagios) use this
to authenticate and optionally encrypt their queries.

SETTINGS (SNMP tab)
- Enable SNMPv3: turns on USM. The agent advertises its engine ID and answers
  authenticated requests.
- Disallow v1/v2c: when ticked, the legacy community model is refused and only
  authenticated v3 requests are answered. Leave it off to accept both.
- Engine ID: the agent's authoritative USM engine ID. Blank = derived from the
  hostname. Keep it stable so clients don't have to re-discover.

USM USERS
Add one or more users, each with:
- Username (the security name the client sends).
- Auth protocol + passphrase: MD5, SHA-1, SHA-256, or SHA-512. This proves the
  request wasn't tampered with (authNoPriv).
- Priv protocol + passphrase: DES, AES-128, AES-192, or AES-256. This encrypts
  the request/response (authPriv). Leave the priv fields blank for authNoPriv.

A user with neither auth nor priv is noAuthNoPriv (discovery only). Passphrases
are localized to this agent's engine ID, so the same passphrase on a different
engine produces different keys — that's normal.

The agent is read-only: it never accepts SNMP Set, so monitoring tools can read
identity, page counts, and toner levels but cannot change anything.
`

const helpDiscovery = `DISCOVERY — mDNS / Bonjour and WSD

Both features here are ADVERTISEMENT / DISCOVERY only. They help clients FIND
printcap automatically; the print job itself is still captured over the normal
listeners (RAW 9100, LPR, IPP/IPPS). Configure them on the "Discovery" tab.

mDNS / DNS-SD (Bonjour)  — UDP 5353 multicast
Advertises printcap as a driverless printer on the local network so it appears
automatically in print dialogs on macOS and iOS (AirPrint), Linux/CUPS, and
Windows. No driver, no manual IP entry — the user just picks it from the list.
  Fields:
   - Instance name: the friendly name shown in the picker. Blank = the printer
     name from the Printer Identity tab.
   - Hostname: the .local hostname advertised. Blank = a sanitized form of the
     printer name.
   - AirPrint: advertise the AirPrint (_ipp._tcp + URF) service so iPhones and
     iPads can print to it. On by default.

WSD — Web Services for Devices  (experimental)
This is how modern Windows finds printers under "Add a device / Add a printer."
  - Print service port: TCP 3911 by default.
  - Discovery: runs the WS-Discovery responder on UDP 3702 multicast so Windows
    sees printcap during a network scan. Turn it off to keep the print endpoint
    but stay invisible to discovery.
WSD is experimental — if a Windows box doesn't pick it up, fall back to adding a
Standard TCP/IP (RAW 9100) or IPP port by hand.
`

const helpSMB = `SMB SHARE (experimental)

An experimental SMB2/3 print share, so Windows shops that "add a printer" by
browsing the network can point at printcap the same way they point at a real
print server. It is a CAPTURE SINK, not a file server — it accepts a print job
over the SMB print path and captures it; it does not share files or folders.

Off by default. Configure on the "SMB Share" tab.

SETTINGS
- Enable: turns the listener on.
- Port: 4445 by default. Real SMB is TCP 445, but Windows already owns 445 on
  most machines, so printcap uses a non-445 port to avoid the conflict. Clients
  must be told the alternate port.
- Share name: the share clients connect to (default PRINTER).
- Require authentication: when OFF, unauthenticated clients get a GUEST session
  (easiest for testing). When ON, clients must log in as one of the configured
  users (NTLMv2).
- Users: username / password / domain credentials accepted for NTLMv2 logon.
- Sign / Encrypt: SMB3 message signing and encryption. On by default.

TESTING
  smbclient //HOST/PRINTER -p 4445 -U guest%        (Linux/macOS)
  or in Windows, Add Printer -> select a shared printer -> \\HOST\PRINTER
Then send a test page; it shows up on the dashboard like any other capture.

Experimental: the SMB stack implements the print path, not a full file server.
If a client is fussy, use RAW 9100 or IPP instead.
`

const helpEBCDIC = `MAINFRAME / EBCDIC

Print streams from IBM mainframes and midrange systems (z/OS, IBM i, AS/400)
are usually EBCDIC, not ASCII/UTF-8 — so the raw capture looks like garbage.
printcap decodes EBCDIC line-data to readable UTF-8. Configure on the
"Mainframe / EBCDIC" tab.

CODE PAGES
Pick the default EBCDIC code page that matches the host:
  CP037  — US / Canada (most common)
  CP500  — International
  CP1047 — Latin-1 / Open Systems (z/OS Unix)
  CP273  — Germany / Austria
  CP285  — UK
  CP297  — France
Auto-detect: when on, printcap inspects the bytes and picks a code page if it
can, falling back to your default.

DECODED SIDECAR
With "decoded sidecar" enabled, each EBCDIC job is saved twice: the raw capture
(intact, original bytes) plus a "<name>-decoded.txt" file holding the readable
UTF-8 text. The decoded text is also what the dashboard previews and what the
DLP content scanner searches.

CARRIAGE CONTROL
Mainframe line-data carries page/line control in the first byte of each record:
  none    — no carriage-control byte
  asa     — ANSI/ASA control characters (space, 0, 1, +, ...)
  machine — IBM machine code carriage control
  auto    — detect, and let an LPD control-file hint upgrade to ASA
This controls how line breaks and page ejects are rendered in the decoded text.

PER-QUEUE OVERRIDES
Different LPD queues can carry different code pages. Under the LPR queue
defaults you can map a queue name (glob) to its own code page and carriage
control, overriding the global defaults for jobs that arrive on that queue.
`

const helpForward = `FORWARD PROXY — tee / relay captured jobs

The forward proxy can re-send every captured job to one or more downstream
printers, so printcap sits transparently in the path while still capturing.
Off by default. Configure on the "Forward Proxy" tab.

TARGETS
Each target has a transport and an address:
  raw   — JetDirect/AppSocket, host:9100
  lpr   — LPR/LPD, host + queue name
  ipp   — IPP over HTTP
  ipps  — IPP over TLS
You can have several targets (e.g. capture + send to two real printers).

TRANSFORMS
Before sending, a target can rewrite the stream:
  - replace: literal, regex (RE2), or hex match -> replacement.
  - inject_prefix / inject_suffix: prepend/append bytes (e.g. a PJL banner).
Transforms support macros — define name=value pairs once and reference them as
macro:NAME inside an injection.

ROUTING ("when")
A target (or an individual transform step) can carry a "when" condition so it
only fires for matching jobs (e.g. a given queue, user, host, or PDL). Jobs that
don't match are simply not forwarded to that target.

FAILURE POLICY (per target)
  best_effort — try once; if the downstream is down, log it and move on.
  block       — treat a delivery failure as a hard error for that job.
  spool_retry — persist the job to disk and keep retrying with backoff. This
                NOW SURVIVES A RESTART: queued items are written to the spool
                folder and replayed automatically when printcap starts again.
                Items that exhaust their attempts/TTL are moved to a "dead/"
                subfolder and kept for you to inspect (never silently dropped).

CAPTURE MODE (both | sent | orig)
  orig — keep the original bytes you captured.
  sent — keep what was actually sent downstream (post-transform).
  both — keep both (the sent copy is saved as a "-sent-<target>" file).
Per-target outcomes (ok / failed / queued) are recorded in each job's .json and
shown on the dashboard.
`

const helpDLP = `CONTENT INSPECTION (DLP)

printcap can scan the content of captured documents for sensitive material and
flag it. This is INSPECTION ONLY — it tags and alerts, it NEVER blocks or
modifies a job. Off by default. Configure rules on the "Content / DLP" tab.

RULES
Each rule has a name and a pattern:
  - keyword: case-insensitive substring match (e.g. "CONFIDENTIAL", "SSN").
  - regex:   RE2 regular expression (e.g. a credit-card or account-number
             pattern).
The rule name is what gets reported on a match.

WHAT A MATCH DOES
  - Tags the job with the matching rule name(s) — visible on the dashboard and
    stored in the job's .json sidecar (and the CSV/JSON export).
  - Raises a "[DLP]" alert in the log so a SIEM/syslog feed can catch it.
That's all — the document is still captured and (if forwarding is on) still
forwarded. DLP does not stop anything.

WHAT IT CAN SEE
Matching runs against the raw captured bytes plus, for mainframe jobs, the
EBCDIC-decoded text. So plain text and uncompressed PostScript match well.
Compressed PDFs (with deflated streams) and binary/raster PCL won't reveal their
text to a plain-text pattern unless the content is decoded first — keep that in
mind when writing rules.
`

const helpDashboard = `WEB DASHBOARD

A live web console for everything printcap captures. Default address:
http://localhost:8631  (port set on Protocols & Ports; disable it there if you
don't want it). Open it from the GUI's "Open Dashboard" button or the tray menu.

WHAT IT SHOWS
- Live stats: totals per protocol/PDL, bytes captured, and recent activity, all
  updating live.
- Job list: searchable, sortable, and paginated. Click a job for its detail —
  full metadata, a text preview of the content, a download link, and a delete
  button.
- Listeners: per-listener status with enable/disable toggles.
- Engine control: Start / Stop / Restart the capture engine from the browser.
- Export: download the (filtered) job list as CSV or JSON.
- Live log panel with a level filter and a live log-level control (change the
  running level without a restart).
- Settings editor: edit EVERY config field from the browser and Save (or Save &
  restart). Secrets show as *** and are kept if you don't change them. Writes are
  refused from other machines unless dashboard.allow_remote_admin is set.
- Captures: a packet window for intercept mode — live view, filtering, and TCP
  stream reassembly (see the "Packet capture" tab).
- Light / dark theme.

DELETING JOBS
The per-job delete button removes a job from the list AND deletes its on-disk
files (the spool file and its .json). Nothing is deleted unless you ask.

SECURITY
The dashboard is intentionally NOT password-protected — it's a local utility and
adding accounts would get in the way. It exposes captured documents and lets you
control the engine, so if you don't fully trust the network, bind printcap to
127.0.0.1 (loopback) or turn the dashboard port off. Anyone who can reach the
port can view and download captures.
`

const helpIntercept = `NETWORK INTERCEPTION & PACKET CAPTURE

Off by default. AUTHORIZED USE ONLY — this mode captures traffic that is NOT
addressed to printcap. Use it only on networks you have written authorization to
capture on. Misuse may be illegal.

ENABLING
- In the GUI: the "Capture" tab — tick "Enable network interception", pick the
  capture adapter (the list is pre-filled with this machine's adapters), and fill
  in the authorization. Or click "Open Capture Window" for a live packet view.
- Headless: run with -intercept (or set intercept.enabled in the config).
- It REFUSES TO START until you record an authorization: acknowledge it and set
  an operator name and an engagement/ticket reference
  (-authorize -operator NAME -engagement TICKET). An optional expiry date stops
  capture once the engagement window has passed. "printcap -check" reports any
  missing or expired authorization as an error.
- On Windows, live capture needs Npcap installed (npcap.com) and a build made
  with the Npcap SDK (built with -tags=npcap). A plain build logs that capture is
  unavailable and captures nothing. (macOS and Linux builds capture with no extra
  driver — root / access_bpf / CAP_NET_RAW.)

WHAT IT DOES
- Writes ALL traffic on the capture interface to a standard capture.pcap in the
  output folder (Wireshark/tshark can open it).
- Reconstructs streams into typed files (.pcl/.ps/.pdf/.jpg, and HTTP). By
  default it carves ALL ports ("Reconstruct ALL ports"); untick it to limit
  carving to the listed print/API ports (9100, 515, 631, 80, 8080).
- "Disable IPv6" drops IPv6 from the capture, carving, and the live view (IPv4
  only) — handy to cut IPv6 multicast/neighbor-discovery noise.
- A capture-time filter (intercept.capture_filter, same syntax as the viewer's
  display filter, e.g. "addr==10.0.0.50" or "port==9100") keeps the pcap small by
  recording only matching packets — works on every platform.
- Writes capture.pcap.authorization.txt next to the pcap recording WHO ran the
  capture and under what engagement.

ACTIVE ARP POSITIONING (Windows + Npcap only, optional)
Stays OFF unless you list explicit target IPs — there is NO whole-subnet mode. It
acts only on the hosts you list (and the gateway) and restores their ARP caches
on stop. macOS/Linux capture is strictly passive (a read-only tap; no ARP).

MFP FOCUS
Set "MFP / printer IP" to the printer's IP. It is auto-added as an ARP target,
and the capture window's "MFP only" checkbox narrows the view to traffic to/from
that IP.

MULTI-HOMED (printer LAN + internet)
Pick the "Printer network adapter" (capture/ARP side) and the "Internet adapter
(uplink)". With IP forwarding on, the PC routes the printer's traffic toward the
uplink so it keeps working.

AUTO-NAT (ICS)
Different-subnet uplinks also need NAT. Fill in the two "Auto-NAT (ICS)" fields
with the Windows CONNECTION names (e.g. internet="Wi-Fi", printer="Ethernet").
printcap then turns on Internet Connection Sharing at Start and turns it OFF
again at Stop — no manual step. (Standalone scripts/ics-enable.ps1 and
ics-disable.ps1 do the same by hand.) CAVEAT: ICS sets the printer-side adapter
to 192.168.137.1 with its own DHCP+NAT; it suits "this PC is the printer's
router". For a transparent MITM on an existing LAN, use RRAS NAT instead. Leave
the ICS fields blank to skip auto-NAT.

CLEANUP
Stop (or quitting) restores every poisoned ARP cache and returns IPv4 forwarding
to its prior state — printcap only disables forwarding if it was the one that
enabled it. Nothing it changed is left behind.

VIEWING CAPTURES
Two places show the captured packets, with the same live view + reassembly:
- The GUI "Capture Window" (Capture tab -> Open Capture Window): a live, color-
  coded packet table. Double-click a TCP row to follow/reassemble its stream.
  NOTE: this window shows packets only when the engine runs IN-PROCESS (this GUI),
  not when printcap runs as the installed Windows service (separate process) — use
  the dashboard on the service host for that.
- The web Dashboard "Captures" panel (same features, reachable from any browser).

- GO LIVE: a real-time, scrolling packet view fed as packets arrive (pause /
  clear / auto-scroll; shows "missed N" if a burst overruns the buffer).
  "Refresh (static)" instead reads the saved pcap.
- FILTER with a Wireshark-style display filter in the Filter box. Terms are
  ANDed (space-separated); a bare word is a substring match. Fields:
    src dst addr ip      e.g.  dst==10.0.0.5   addr~10.0.0
    sport dport port     e.g.  port==9100      dport>=1024
    proto svc class      e.g.  proto==arp      svc==http   class==reset
    len ipver            e.g.  len>100         ipver!=6
  Operators: ==  !=  ~ (contains)  and  >  <  >=  <=  for numbers.
  The "Hide IPv6" checkbox is a quick shortcut for ipver!=6 in the view.
- PACKET DETAILS: select a row and click "Packet details" (or click the # in the
  web viewer) for a full layered decode — Ethernet/ARP/IP/TCP/UDP/ICMP fields
  plus a hex+ASCII dump, like Wireshark's detail pane.
- COLOR CODING: errors and resets are RED; print jobs (raw/9100, LPR, IPP) and
  SNMP are GREEN; HTTPS (443) is BLUE.
- ROW TYPES: TCP/UDP/ICMP rows are decoded; ARP rows show who-has/is-at (you'll
  see many during ARP positioning); "non-IP" rows are other L2 frames (the
  EtherType is shown in Info).

DISABLE IPv6 — two effects
- The "Disable IPv6" checkbox on the Capture tab (and the capture window) drops
  IPv6 at CAPTURE time, so it never reaches the pcap/ring — this takes effect on
  the next Start.
- The "Hide IPv6" checkbox in the capture window hides IPv6 from the live VIEW
  immediately (no restart). Use that for an instant effect.
- FOLLOW STREAM: click any TCP row to reassemble both directions (client->server
  and server->client), viewable as text or hex. HTTP renders as text, so the
  printer's WEB API (EWS/REST) and IPP exchanges are readable. Each direction and
  the whole .pcap are downloadable.
`

const helpStorage = `FILES & STORAGE

WHERE THINGS GO
- Captures: the output folder (General tab). Each job is a spool file plus a
  matching .json metadata sidecar (and, for EBCDIC jobs, a -decoded.txt).
- Spool folder: the forward-proxy retry queue (spool_retry items and their
  "dead/" give-ups) and temporary working files live here.
- Logs: a "logs" subfolder of the output folder (printcap.log, plus the optional
  JSON-lines log) — see the Logging tab. Logging defaults to verbose (trace).
- Captures (intercept mode): capture.pcap and its authorization sidecar in the
  output folder.

PORTABLE BY DESIGN
Relative folder paths resolve relative to the printcap EXECUTABLE, not the
current directory. So you can put printcap.exe and its config on a USB stick or
a network share and carry it between machines — captures, spool, and logs follow
the exe. (Absolute paths are used as-is; a Windows SERVICE needs absolute paths
because its working directory is C:\Windows\System32.)

RETENTION IS YOURS
Nothing is ever deleted automatically. printcap will keep capturing until the
disk fills, so you manage retention yourself: archive or clear the output folder
periodically. You can delete individual jobs (file + metadata) from the
dashboard, or just delete files from the folder.

The spool folder's "dead/" subfolder holds forward jobs that gave up retrying —
it's kept on purpose so you can inspect or replay them; clear it when you're
done with them.
`
