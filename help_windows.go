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
					helpPage("Enterprise sources", helpEnterprise),
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
1. On the "Protocols & Ports" tab, enable the protocols you need and set ports.
2. On "General", choose a capture directory and a save mode.
3. Click Start. Send a print job to this machine's IP address.
4. Click "Open Dashboard" to watch jobs arrive, or "Open Folder" for the files.

RUN MODES
- GUI (this window): runs the engine in-process; closing the window minimizes
  to the system tray.
- Service: install on the "Service & Firewall" tab to run unattended at boot.
  When the service is installed, Start/Stop here controls the service.
- Console: run "printcap.exe -console" for a headless command-line mode.

PRIVILEGES & FIREWALL
- Ports below 1024 (515, 631, 161) and installing the service require running
  printcap as Administrator (right-click -> Run as administrator).
- Use "Allow through Firewall" on the Service & Firewall tab so other machines
  can reach the listeners.

SAVE MODES
- both: raw spool file + a .json metadata sidecar (default)
- raw:  spool file only
- meta: metadata only; document bytes are discarded (privacy-preserving audit)
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
  tab.

Web dashboard (TCP 8631)
  Live job feed, per-protocol stats, and per-job downloads. No authentication —
  bind to 127.0.0.1 or disable it on a shared network.
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
    (http://HOST:8631/, or the JSON at /api/logs?level=debug&n=300).
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

"bind: permission denied" / a listener didn't start
  Ports 515, 631, 161 need Administrator. Right-click printcap -> Run as
  administrator, or move to high ports (e.g. LPR 1515) on Protocols & Ports.

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
