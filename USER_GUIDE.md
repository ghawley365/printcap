# printcap — End-User Guide

*Developed by Gary Hawley — gary.hawley@gmail.com*

A friendly, step-by-step guide to using **printcap**, the network print-capture
tool. This guide is written for the people who *operate* printcap day to day —
no deep networking background required. Where something is genuinely technical,
there's a plain-language explanation and a pointer to the [Glossary](#15-glossary).

> For configuration-file reference, command-line flags, and deployment details,
> see the **ADMIN_GUIDE.md** instead. This document focuses on *using* the app.

---

## Contents

1. [What printcap does](#1-what-printcap-does)
2. [Before you start](#2-before-you-start)
3. [Installing & launching](#3-installing--launching)
4. [The 60-second Quick Start](#4-the-60-second-quick-start)
5. [Capturing print jobs (the core feature)](#5-capturing-print-jobs-the-core-feature)
6. [The web Dashboard](#6-the-web-dashboard)
7. [The Settings tabs (Advanced view)](#7-the-settings-tabs-advanced-view)
8. [Network packet capture (intercept mode)](#8-network-packet-capture-intercept-mode)
9. [The Capture Window & reading packets](#9-the-capture-window--reading-packets)
10. [Filtering like a pro](#10-filtering-like-a-pro)
11. [Per-packet details](#11-per-packet-details)
12. [Finding, saving & exporting your files](#12-finding-saving--exporting-your-files)
13. [Running as a Windows service](#13-running-as-a-windows-service)
14. [Troubleshooting & FAQ](#14-troubleshooting--faq)
15. [Glossary](#15-glossary)

---

## 1. What printcap does

printcap pretends to be a network printer. When a computer, server, or
multifunction printer (MFP) sends a print job to printcap's IP address, printcap
**accepts the job and saves it** — both the raw data and a readable copy of the
document where possible — instead of putting ink on paper. It speaks every common
print "language" (RAW/JetDirect on port 9100, LPR/LPD on 515, IPP on 631, and
more), answers printer-discovery requests (SNMP, Bonjour/AirPrint, WSD) so it
looks like a real device, and shows everything it catches in a live web
dashboard.

It has two big jobs:

- **Print capture** — collect and inspect the documents sent *to* it. This is
  the everyday use and needs no special privileges.
- **Network capture (intercept mode)** — record raw network traffic on an
  adapter so you can analyze what a printer and its clients are actually saying
  to each other. This is an **authorized-use-only** diagnostic/security feature
  (see [Section 8](#8-network-packet-capture-intercept-mode)).

You can drive printcap three ways, and they all share the same settings:

| Surface | Best for |
|---|---|
| **Windows app (GUI)** | Day-to-day operation on a desktop. Has a **Quick Start** tab for newcomers and Advanced tabs for everything else. |
| **Web Dashboard** | Watching captures live, from any browser, including on another machine. |
| **Command line / service** | Unattended/background operation (see [Section 13](#13-running-as-a-windows-service)). |

---

## 2. Before you start

- **A Windows PC** (printcap is Windows-first; it also runs on macOS/Linux for
  capture). You usually need to run it **as Administrator** so it can open
  low-numbered ports (like 515 and 631) and the firewall.
- **The printcap program file** (`printcap.exe`). There are two builds:
  - `printcap.exe` — the **full** build, includes live network packet capture
    (needs **Npcap**, see below).
  - `printcap-nocapture.exe` — print capture only, no packet-capture engine.
- **Npcap** *(only if you'll use network packet capture)* — a free Windows
  component that lets programs read network traffic. printcap will detect if it's
  missing and offer to take you to the download page. See
  ["PCAP / Npcap" in Troubleshooting](#npcap--pcap-not-installed).
- **Authorization** *(only for intercept mode)* — written permission to capture
  traffic on the network you're testing. printcap **will not start** intercept
  mode until you fill in who you are and your engagement reference.

---

## 3. Installing & launching

printcap is a **single self-contained file** — there's no installer for the app
itself. To run it:

1. Copy `printcap.exe` to a folder you can write to (e.g. `C:\printcap\`).
2. **Right-click → Run as administrator.** The main window opens.
3. The first time, printcap creates a settings file (`printcap.json`) and a
   capture folder next to the program.

If Windows SmartScreen warns about an unrecognized app, choose **More info → Run
anyway** (the file is unsigned). Your security team can verify the build hash
shown by `printcap.exe -version`.

---

## 4. The 60-second Quick Start

The **Quick Start** tab (the first tab, designed for non-technical staff) is all
most people need:

1. Open printcap. You land on **Quick Start**.
2. Read the **Status** line — it shows whether capture is running.
3. Click **Start**. printcap is now listening as a printer.
4. On another computer, **add a printer** pointing at this PC's IP address (any
   common type works — see [Section 5](#5-capturing-print-jobs-the-core-feature))
   and print a test page.
5. Click **Open Dashboard** to watch the job arrive, or **Open Capture Folder**
   to see the saved files.
6. Click **Stop** when you're done.

Other one-click buttons on Quick Start:

- **Open Capture Window ▸** — watch live network packets (intercept mode).
- **Save Settings** — write your configuration to disk.
- **Help** — the built-in, plain-language help for every feature.

> Everything beyond this is the **Advanced view** — the other tabs across the top
> ([Section 7](#7-the-settings-tabs-advanced-view)). Quick Start never hides
> anything; it's just the simple front door.

---

## 5. Capturing print jobs (the core feature)

### 5.1 Turn on the protocols you need

On the **Protocols & Ports** tab, switch on the print methods you expect and set
their ports. The common ones:

| Protocol | Port | Used by |
|---|---|---|
| **RAW / JetDirect / AppSocket** | 9100 | Most network printers and Windows "Standard TCP/IP" ports |
| **LPR / LPD** | 515 | Enterprise systems — SAP, IBM AS/400, z/OS mainframe, Linux/CUPS |
| **IPP / IPPS** | 631 | Modern printing, AirPrint, CUPS |

Set further options on the **RAW & LPR** and **IPP & TLS** tabs (resource paths,
TLS certificate, per-queue mainframe settings, etc.).

### 5.2 Choose where and how jobs are saved

On the **General** tab:

- **Capture directory** — where saved jobs and logs go. (Logs land in a `logs`
  sub-folder.)
- **Save mode**:
  - **Both** *(default)* — save the raw spool data **and** a small `.json`
    description of each job.
  - **Raw** — just the document bytes.
  - **Meta** — just the description; the document itself is discarded.
- **Max job size** — a safety cap so a runaway job can't fill your disk
  (0 = no limit).

### 5.3 Make this PC discoverable (optional)

On the **Discovery** tab you can answer **mDNS/DNS-SD** (Bonjour/AirPrint) and
**WSD** so the fake printer shows up in "Add Printer" browsers automatically. On
the **SNMP** tab, printcap can answer printer-discovery queries (including secure
**SNMPv3**) so it looks like a real device to management tools.

### 5.4 Send a test job and confirm

Print anything to this PC's IP from another machine. Within a second or two the
job appears under **Captured jobs** in the dashboard, and the files appear in your
capture folder. printcap automatically detects the document type (PDF, PostScript,
PCL, JPEG, plain text, EBCDIC mainframe data, …) and names the readable copy
accordingly.

---

## 6. The web Dashboard

Click **Open Dashboard** (or browse to `http://<this-pc-ip>:<dashboard-port>/`).
The dashboard has these sections:

- **Settings** — the same configuration as the GUI tabs, editable from a browser.
  Secrets (passwords, community strings) are shown as `***` and preserved unless
  you change them. *Changes from another machine are read-only unless an admin has
  enabled remote administration.*
- **Network capture** — the live/saved packet viewer
  ([Sections 9–11](#9-the-capture-window--reading-packets)).
- **Listeners** — which print protocols are up, and buttons to **Start /
  Restart / Stop** the engine.
- **Captured jobs** — every job caught, searchable, with **CSV/JSON export** and
  per-job preview/download.
- **Live log** — a real-time, filterable log (error → trace) with a one-click
  **download full log**.

There's a **light/dark theme** toggle, and the dashboard auto-refreshes.

---

## 7. The Settings tabs (Advanced view)

Every feature is configurable through the GUI tabs. Each tab has a matching page
in the in-app **Help** window.

| Tab | What it controls |
|---|---|
| **Quick Start** | The simple landing page (status + big action buttons). |
| **General** | Capture folder, save mode, job size cap, notifications. |
| **Protocols & Ports** | Which print protocols/ports are enabled. |
| **RAW & LPR** | RAW/9100 options; LPR/LPD queues and per-queue mainframe defaults. |
| **IPP & TLS** | IPP/IPPS resource paths and the TLS certificate. |
| **Printer Identity** | The make/model/name printcap reports as. |
| **SNMP** | SNMP v1/v2c identity and secure **SNMPv3 (USM)** users. |
| **Discovery** | mDNS/DNS-SD (Bonjour/AirPrint) and WSD advertisement. |
| **SMB Share** | Experimental SMB2/3 print share. |
| **Mainframe / EBCDIC** | Decode mainframe (EBCDIC) print streams to readable text. |
| **Forward Proxy** | Relay captured jobs onward to a real printer. |
| **Content / DLP** | Scan captured documents for sensitive content and flag matches. |
| **Logging** | Log file, verbosity, and **SIEM export** (JSON-lines + syslog). |
| **Capture** | Network packet capture / intercept mode ([Section 8](#8-network-packet-capture-intercept-mode)). |
| **Service & Firewall** | Install as a Windows service; open firewall ports. |

---

## 8. Network packet capture (intercept mode)

Intercept mode records raw network traffic on a chosen network adapter into a
**.pcap** file (the standard format Wireshark reads) and shows it live. Use it to
see exactly what a printer and its clients exchange.

> ⚠️ **Authorized use only.** Capturing network traffic may only be done on
> networks you have **written permission** to test. printcap enforces this: on
> the **Capture** tab, the **Authorization** box (your name + engagement/ticket
> reference, with an optional expiry) **must be filled in or capture refuses to
> start.** Those details are stamped into a record saved next to every capture.

### 8.1 The simplest case — passive capture

1. On the **Capture** tab (or in the Capture Window), pick the **Printer network
   adapter** — the network card connected to the printer's network.
2. Fill in the **Authorization** box.
3. Click **Start capture**. Packets stream into the viewer and into a `.pcap`
   file in your capture folder.

This is **passive** — printcap just listens. It does not change the network.

### 8.2 Focus on one printer (MFP)

Set the **MFP / printer IP** field to the printer's address. Two things happen:

- The **"MFP only"** toggle in the Capture Window filters the view to just that
  printer's traffic.
- (Windows) if you turn on active positioning, that IP is automatically the
  in-scope target.

### 8.3 Keeping a printer online while you capture (multi-homed + NAT)

*Windows only, advanced.* If you place the PC **between** a printer and the rest
of the network (two network adapters), printcap can route the printer's traffic
so it keeps working while you watch it:

- **Printer network adapter** — the side the printer is on.
- **Internet adapter (uplink)** — the side with internet/network access.
- **Auto-NAT (ICS)** — fill in the two connection-name boxes (e.g. `Ethernet`
  and `Wi-Fi`, chosen from the drop-downs) and printcap turns on Windows Internet
  Connection Sharing when you Start and **turns it off again when you Stop**.

> **Note:** ICS gives the printer side the fixed address `192.168.137.1`. It fits
> the "this PC is the printer's router" setup. For capturing on an *existing*
> network where the printer keeps its own address, your admin should use RRAS NAT
> instead. Leave the ICS boxes blank to skip auto-NAT.

### 8.4 Cleanup is automatic

When you click **Stop** (or close the app), printcap puts everything back the way
it found it — any network changes it made are reverted, and Internet Connection
Sharing is switched off. The Capture Window confirms this in its status line.

### 8.5 Reconstruct documents from captured traffic (carve)

On the **Capture** tab, **Reconstruct files (carve)** rebuilds whole print jobs
out of the captured packets and saves them as typed files (`.pdf`, `.pcl`,
`.ps`, `.jpg`, …) alongside the raw `.pcap` — so you get the documents, not just
the packets.

---

## 9. The Capture Window & reading packets

Open it with **Open Capture Window ▸** (Quick Start) or from the dashboard's
**Network capture** section.

### 9.1 Live vs. saved

- **Live** — a scrolling, real-time view as packets arrive. It shows a "missed N"
  notice if traffic outruns the buffer.
- **Static / Refresh** — reads the saved `.pcap` from disk, with paging.

### 9.2 The columns

| Column | Meaning |
|---|---|
| **#** | Packet number (click it on the web to open full details). |
| **Time** | When it was captured. |
| **Proto** | TCP, UDP, ICMP, **ARP**, or non-IP, plus a service tag (HTTP, IPP, raw…). |
| **Source / Destination** | Who sent it / who it's going to. Click an IP to filter to it. |
| **Len** | Size in bytes. |
| **Info** | A human-readable summary (ports, TCP flags, ARP "who-has", ICMP type…). |

### 9.3 Row colors

- **Red** — errors and connection resets (problems worth noticing).
- **Green** — print jobs (RAW/9100, LPR, IPP) and SNMP.
- **Blue** — encrypted HTTPS (port 443).

### 9.4 Row types you'll see

- **TCP / UDP / ICMP** — normal traffic, fully decoded.
- **ARP** — "who has 10.0.0.9? tell 10.0.0.1" / "10.0.0.9 is at <MAC>". You'll see
  a lot of these during active positioning; that's expected.
- **non-IP** — other low-level frames; the Info column shows the EtherType.

### 9.5 Following a conversation

**Double-click** any TCP row to **follow the stream** — printcap reassembles both
directions (client→server and server→client). Web/API traffic (HTTP) is shown as
readable text, so printer web pages, EWS, REST, and IPP exchanges are legible.
Each direction is downloadable, and the whole `.pcap` is one click away.

---

## 10. Filtering like a pro

The viewer has a **Wireshark-style display filter**. Type terms in the **Filter**
box; separate terms with spaces (they all must match), and a plain word matches
anywhere in the row.

### 10.1 Fields and operators

| Group | Fields | Operators |
|---|---|---|
| Addresses | `src` `dst` `addr` `ip` | `==` `!=` `~` (contains) |
| Ports | `sport` `dport` `port` | `==` `!=` `>` `<` `>=` `<=` |
| Classification | `proto` `svc` `class` `color` `info` | `==` `!=` `~` |
| Numbers | `len` `ipver` | `==` `!=` `>` `<` `>=` `<=` |

### 10.2 Examples

| Type this | To see |
|---|---|
| `addr==10.0.0.50` | only the printer at 10.0.0.50 |
| `port==9100` | print (RAW/JetDirect) traffic |
| `svc==http` | the printer's web pages / API |
| `proto==arp` | ARP "who-has / is-at" messages |
| `class==reset` | dropped/reset connections |
| `ipver!=6` | hide IPv6 |
| `dst==10.0.0.50 len>200` | big packets going to the printer |

### 10.3 Shortcuts

- **Quick filters** — one-click buttons (Print 9100, IPP, Web/API, ARP, Resets,
  ICMP errors, SNMP) fill the filter box for you.
- **Click any IP** in a row to instantly filter to that address.
- **Click a column header** to sort by it (click again to reverse).
- **Hide IPv6** checkbox — the same as typing `ipver!=6`.
- **MFP only** checkbox — limits the view to the printer IP you set.

### 10.4 Capture-time filter (keep the file small)

The filters above narrow what you *see*. To control what gets *recorded*, set
**`intercept.capture_filter`** (same syntax) — only matching packets are written
to the `.pcap`. Handy for long captures. (On Windows, `intercept.bpf` is an
alternative using classic libpcap syntax; it's Windows/Npcap-only.)

---

## 11. Per-packet details

To see everything about one packet:

- **Web dashboard:** click the packet's **#** number.
- **Windows Capture Window:** click a row to select it, then click **Packet
  details**.

A popup shows the **layer-by-layer decode** — Ethernet (MAC addresses,
EtherType), IP (addresses, TTL, protocol), TCP/UDP (ports, flags, sequence
numbers), ICMP, or ARP — followed by a **hex + ASCII dump** of the raw bytes, just
like Wireshark's detail pane. If the packet was only partially captured, the dump
says so and points you to the full `.pcap`.

> **Tip:** in the live Windows view, your selected row stays selected even as new
> packets arrive, so you can open details mid-capture without the row jumping away.

---

## 12. Finding, saving & exporting your files

Everything lands under your **Capture directory** (set on **General**):

- **Captured print jobs** — raw spool files plus `.json` descriptions, and any
  reconstructed documents (`.pdf`, `.pcl`, …).
- **Network captures** — `capture.pcap` (open in Wireshark) plus a small record of
  who ran the capture and under what authorization.
- **Logs** — in the `logs` sub-folder; download the current log from the
  dashboard's **Live log** section.

From the dashboard you can **export the job list as CSV or JSON**, preview or
download any single job, and download the full `.pcap`.

---

## 13. Running as a Windows service

To capture around the clock without anyone logged in, install printcap as a
Windows **service** from the **Service & Firewall** tab (or the command line). The
service starts at boot and runs unattended. The same tab can open the required
ports in **Windows Defender Firewall**.

> **Live capture & the service:** when printcap runs as a service, packet capture
> happens inside the *service* process. The desktop Capture Window can't show
> those packets live — use the **web dashboard's** Network capture view on the
> service machine instead, or stop the service and capture from the GUI.

---

## 14. Troubleshooting & FAQ

### Npcap / "PCAP" not installed
Live **network** capture needs **Npcap** (the Windows packet-capture driver).
If it's missing, printcap tells you and offers the download page
(`https://npcap.com`). Install it (default options are fine), then restart
printcap. You also need the **full** `printcap.exe` build — the
`printcap-nocapture.exe` build has no capture engine. *(Print-job capture does
**not** need Npcap.)*

### "Port already in use" / a listener failed
Another program (often the Windows Print Spooler or a real printer driver) is
already using the port. printcap names the failing listener and the reason on the
**Listeners** panel and in the log. Free the port, change printcap's port for that
protocol, or stop the conflicting program.

### Nothing gets captured when I print
- Is the engine **Started**? Check the Status line / Listeners panel.
- Did you point the other computer at **this PC's IP** and the **right port**
  (9100 for most)?
- Is **Windows Firewall** blocking the port? Use **Service & Firewall** to open
  it.
- Are you running printcap **as Administrator** (needed for ports below 1024 like
  515/631)?

### I see IPv6 packets I don't want
Use the **Hide IPv6** checkbox (or filter `ipver!=6`) to hide them from the view
immediately. To stop recording them entirely, tick **Disable IPv6** before you
**Start** capture (it takes effect on the next start).

### "ring overrun — older packets dropped"
Traffic arrived faster than the live view could keep up, so the oldest live
packets scrolled out of memory. The **`.pcap` file on disk is still complete** —
open it with **Refresh (static)** or in Wireshark to see everything.

### I can't select a packet row in the Capture Window
This was fixed: single-click selects a row and the selection now sticks during
live capture. If you're on an older build, update to the latest. Then select a
row and click **Packet details**, or double-click to follow the stream.

### What are all the "ARP" / "non-IP" rows?
ARP is the normal "who-has / is-at" address chatter on a network — you'll see lots
during active positioning. "non-IP" rows are other low-level frames; the Info
column shows what kind.

### My settings didn't save
Click **Save Settings** (Quick Start) or **Save** in the GUI. From the web
dashboard, settings changes are **read-only from other machines** unless an admin
has enabled remote administration.

---

## 15. Glossary

| Term | Plain meaning |
|---|---|
| **MFP** | Multifunction printer (print/scan/copy device). |
| **RAW / 9100 / JetDirect** | The most common network print method (TCP port 9100). |
| **LPR / LPD (515)** | An older/enterprise print protocol (SAP, AS/400, mainframe, Linux). |
| **IPP / IPPS (631)** | Modern internet printing; IPPS is the encrypted version. |
| **SNMP** | How management tools discover and query devices; **SNMPv3** is the secure version. |
| **pcap / .pcap** | The standard capture-file format that Wireshark reads. |
| **Npcap** | The free Windows component that lets programs read network traffic. |
| **Packet** | One small chunk of data sent across the network. |
| **ARP** | The network's "who has this address?" address-lookup chatter. |
| **MAC address** | A network card's hardware address (e.g. `a4:5e:60:…`). |
| **TCP / UDP / ICMP** | Common network transport types; ICMP includes "errors"/ping. |
| **TTL** | "Time to live" — how many hops a packet may travel before being dropped. |
| **NAT / ICS** | Address translation that lets one network reach another; ICS is Windows' built-in version. |
| **Intercept / on-path capture** | Recording traffic by placing the capture host in its path. **Authorized use only.** |
| **Carve** | Rebuilding whole files/documents out of captured packets. |
| **DLP** | Data-loss prevention — scanning documents for sensitive content. |
| **EBCDIC** | The text encoding used by IBM mainframes. |

---

*printcap — authorized print and network-capture use only. When in doubt about
permission to capture on a network, stop and ask.*
