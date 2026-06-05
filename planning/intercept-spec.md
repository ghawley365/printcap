# printcap "intercept" mode — network interception & full-traffic capture

## Summary

Add a new operating mode to printcap that captures **all** network traffic on an
authorized customer segment (not just print ports) to a standard pcap file, while
transparently passing traffic through so nothing is disrupted. Optionally position
printcap on-path actively via ARP cache poisoning, scoped to an explicit target
allow-list. Intended for authorized engagements (print-capture / migration /
forensic / pentest work) where the operator has permission to capture.

## Background / context

- printcap is a Go (1.26), Windows-first network print-server emulator + capture
  tool. It already has L7 print listeners (raw/9100, LPR, IPP/IPPS), an SNMP
  agent, mDNS/DNS-SD, experimental SMB/WSD, a transform-and-forward print proxy,
  a web dashboard, durable spool, a Windows GUI, and a Windows service installer.
- Existing pieces are all **application-layer**: the forwarder operates on TCP
  streams after the OS hands them to a `net.Listener`. The new mode operates a
  layer below (L2/L3 — raw frames).
- The engine ([engine.go]) owns listeners as `io.Closer`s and tears them down in
  `Stop()`. New mode should register as a closer and follow the same lifecycle.
- Project conventions: subagent-driven TDD, hand-rolled wire formats (SMB, NTLM,
  mDNS, DNS all hand-rolled), loopback/host-neutral acceptance tests, single
  static `.exe` build.

## An exploratory spike already exists (uncommitted)

A first-pass implementation was written and can be used as **reference or
discarded**. It established a few facts worth carrying into the plan:

- `gopacket/pcap` on Windows loads `wpcap.dll` at runtime via syscall (NOT cgo),
  so the whole feature **cross-compiles for Windows from macOS with
  `CGO_ENABLED=0`** and the static-exe build story survives. Npcap is a runtime
  dependency on the host only.
- The pcap file format is trivial and was hand-rolled pure-Go (no dep needed for
  writing), keeping ~80% of the feature buildable/testable on non-Windows.
- Spike files: `pcapfile.go` (+test), `packet_source.go`, `intercept.go` (+test),
  `capture_stub.go` (non-Windows), `capture_windows.go` (Npcap live source +
  netsh forwarding), `arp_windows.go` (ARP resolve/poison/restore), plus config
  block, `-intercept` flag, and engine wiring.

## Goals

1. Capture full network traffic (all protocols/ports) to a libpcap pcap file
   readable by Wireshark/tshark.
2. Transparent pass-through — never stop or degrade traffic (kernel IP forwarding,
   not a userspace relay).
3. Optional active on-path positioning via ARP poisoning, **scoped to an explicit
   target allow-list** (fail-closed: no whole-subnet mode).
4. Clean teardown that restores ARP caches and forwarding state on stop.
5. Fit existing printcap conventions: config block, engine lifecycle as a closer,
   TDD, cross-compiling static Windows exe.

## Non-goals / constraints

- Windows is the primary capture host (Npcap). Non-Windows builds must still
  compile (stub/capture-only).
- Authorized use only — and now *enforced*, not merely asserted. Intercept mode
  refuses to start (and `-check` errors) unless the operator acknowledges
  authorization and records an operator + engagement reference, with an optional
  expiry window; a loud start-up banner and a per-capture provenance sidecar
  (`<pcap>.authorization.txt`) stamp who ran it and under what authority. Scope
  controls (target allow-list, restore-on-stop) are product features, not optional.
- Avoid breaking the no-cgo static build.

## Known open questions (for the interview)

- Forwarding on Windows without a reboot (netsh global vs per-interface vs
  userspace relay fallback) — what's acceptable?
- ~~Should L7 print-spool decode layer on top of the pcap (correlated capture)?~~
  RESOLVED: implemented. The interceptor reassembles client->printer TCP streams
  on the configured print ports (`intercept.carve`, default 9100/515/631) and
  feeds each completed stream through the same `detectPDL`/`extForFormat` + capture
  sink the live listeners use, so documents are saved as typed files (.jpg, .pcl,
  .ps, .pdf, …) alongside the raw pcap. IPP (631) streams are unwrapped via the
  existing `parseIPP`; 9100 carries the document directly; 515/LPR is best-effort
  raw for now. Pure-Go frame/TCP dissection keeps it testable off-Windows.
- Dashboard/GUI integration and runtime enable/disable toggle.
- Config validation (`-check`) rules for the new mode.
- IPv6 / NDP positioning, or IPv4/ARP only for v1?
- Capture-only (tap/SPAN) vs active ARP — how is mode selected and defaulted?
- Rotation/size limits for long captures; where files land.
- Test strategy for the L2 path that can't run on the dev Mac.
