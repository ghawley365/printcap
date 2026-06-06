//go:build windows

package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	dec "github.com/lxn/walk/declarative"
)

// gui_intercept_windows.go adds packet capture to the native GUI: a "Capture" tab
// in the main window (enable + adapter + authorization + carve/ARP) and a
// standalone live packet window with a color-coded TableView and TCP stream
// reassembly. The adapter pickers are pre-filled from the adapters the system
// reports (listCaptureDevices).

// ---- main-window Capture tab widgets ----
var (
	uiIntEnabled    *walk.CheckBox
	uiIntIface      *walk.ComboBox
	uiIntUplink     *walk.ComboBox
	uiIntMFP        *walk.LineEdit
	uiIntICSPub     *walk.ComboBox
	uiIntICSPrv     *walk.ComboBox
	uiIntPromisc    *walk.CheckBox
	uiIntNoV6       *walk.CheckBox
	uiIntCapFilter  *walk.LineEdit
	uiIntCarveAll   *walk.CheckBox
	uiIntAck        *walk.CheckBox
	uiIntOperator   *walk.LineEdit
	uiIntEngagement *walk.LineEdit
	uiIntExpiry     *walk.LineEdit
	uiIntCarveEn    *walk.CheckBox
	uiIntCarvePorts *walk.LineEdit
	uiIntArpEn      *walk.CheckBox
	uiIntArpTargets *walk.LineEdit

	captureDevs []captureDevice // index i maps to combo index i+1 (0 = auto)
)

// interfaceLabels returns combo labels (with an "auto" first entry) and the
// matching device list.
func interfaceLabels() ([]string, []captureDevice) {
	devs := listCaptureDevices()
	labels := make([]string, 0, len(devs)+1)
	labels = append(labels, "(auto-detect — first non-loopback adapter)")
	for _, d := range devs {
		labels = append(labels, captureDeviceLabel(d))
	}
	return labels, devs
}

// ensureCurrentIface keeps the configured interface selectable even when it is
// not among the currently-enumerated adapters (e.g. a config copied from another
// machine, or an adapter that is down), so opening the picker never silently
// drops the stored value.
func ensureCurrentIface(labels []string, devs []captureDevice, name string) ([]string, []captureDevice) {
	if name == "" {
		return labels, devs
	}
	for _, d := range devs {
		if d.Name == name {
			return labels, devs
		}
	}
	d := captureDevice{Name: name, Desc: name + " (configured, not currently present)"}
	return append(labels, captureDeviceLabel(d)), append(devs, d)
}

// ifaceIndexFor returns the combo index for a stored interface name in devs
// (0 = auto). Each combo keeps its OWN device slice so opening the capture window
// (which re-enumerates) can't desync the main tab's index->device mapping.
func ifaceIndexFor(devs []captureDevice, name string) int {
	for i, d := range devs {
		if d.Name == name && name != "" {
			return i + 1
		}
	}
	return 0
}

func ifaceFromCombo(devs []captureDevice, idx int) string {
	if idx <= 0 || idx-1 >= len(devs) {
		return ""
	}
	return devs[idx-1].Name
}

func intsToCSV(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ", ")
}

func captureTab() dec.TabPage {
	labels, devs := interfaceLabels()
	labels, devs = ensureCurrentIface(labels, devs, cfg.Intercept.Interface)
	labels, devs = ensureCurrentIface(labels, devs, cfg.Intercept.UplinkIface)
	captureDevs = devs
	uplinkLabels := make([]string, len(labels))
	copy(uplinkLabels, labels)
	uplinkLabels[0] = "(none — single-homed; no internet routing)"
	return dec.TabPage{
		Title:  "Capture",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.Label{Text: "Network interception captures ALL traffic on the chosen adapter — AUTHORIZED USE ONLY. On Windows this needs an Npcap build with Npcap installed (npcap.com)."},
			dec.GroupBox{
				Title:  "Packet capture",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntEnabled, Text: "Enable network interception", OnClicked: onEnableInterceptClicked},
					dec.Label{Text: "Printer network adapter:"}, dec.ComboBox{AssignTo: &uiIntIface, Model: labels},
					dec.Label{Text: "Internet adapter (uplink):"}, dec.ComboBox{AssignTo: &uiIntUplink, Model: uplinkLabels},
					dec.Label{Text: "MFP / printer IP:"}, dec.LineEdit{AssignTo: &uiIntMFP, ToolTipText: "the printer's IP — used as the ARP target and the 'MFP only' capture filter"},
					dec.Label{Text: "Auto-NAT (ICS) internet conn.:"}, dec.ComboBox{AssignTo: &uiIntICSPub, Editable: true, Model: connectionNames(), ToolTipText: "Windows connection with internet, e.g. \"Wi-Fi\" — set both ICS fields to auto-enable Internet Connection Sharing (and clean it up on stop)"},
					dec.Label{Text: "Auto-NAT (ICS) printer conn.:"}, dec.ComboBox{AssignTo: &uiIntICSPrv, Editable: true, Model: connectionNames(), ToolTipText: "Windows connection on the printer side, e.g. \"Ethernet\". Note: ICS sets this adapter to 192.168.137.1"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntPromisc, Text: "Promiscuous mode"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntNoV6, Text: "Disable IPv6 (capture IPv4 only)"},
					dec.Label{Text: "Capture filter (record only):"}, dec.LineEdit{AssignTo: &uiIntCapFilter, ToolTipText: "optional — record only matching packets to the pcap, e.g. addr==10.0.0.50 or port==9100 (same syntax as the viewer; blank = capture everything)"},
				},
			},
			dec.GroupBox{
				Title:  "Authorization (capture refuses to start without it)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntAck, Text: "I am authorized to capture on this network"},
					dec.Label{Text: "Operator:"}, dec.LineEdit{AssignTo: &uiIntOperator},
					dec.Label{Text: "Engagement / ticket:"}, dec.LineEdit{AssignTo: &uiIntEngagement},
					dec.Label{Text: "Expiry (YYYY-MM-DD, optional):"}, dec.LineEdit{AssignTo: &uiIntExpiry},
				},
			},
			dec.GroupBox{
				Title:  "Reconstruct files (carve)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntCarveEn, Text: "Reconstruct print + HTTP/API jobs from captured streams"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntCarveAll, Text: "Reconstruct ALL ports (not just the list below)"},
					dec.Label{Text: "Ports (when not all):"}, dec.LineEdit{AssignTo: &uiIntCarvePorts},
				},
			},
			dec.GroupBox{
				Title:  "Active ARP positioning (Windows/Npcap only — leave OFF unless authorized)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiIntArpEn, Text: "Enable ARP positioning (requires explicit target IPs)"},
					dec.Label{Text: "Target IPs (comma-separated):"}, dec.LineEdit{AssignTo: &uiIntArpTargets},
				},
			},
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.PushButton{Text: "Open Capture Window ▸", OnClicked: showCaptureWindow},
					dec.HSpacer{},
				},
			},
			dec.VSpacer{},
		},
	}
}

// onEnableInterceptClicked nudges the user to install Npcap when they turn on
// interception and the live-capture prerequisites aren't met.
func onEnableInterceptClicked() {
	if uiIntEnabled != nil && uiIntEnabled.Checked() && (!captureBuilt || !npcapInstalled()) {
		ensureNpcap(mw)
	}
}

// applyInterceptUI copies the Capture tab into cfg (called from applyUIToConfig).
func applyInterceptUI() {
	if uiIntEnabled == nil {
		return
	}
	cfg.Intercept.Enabled = uiIntEnabled.Checked()
	cfg.Intercept.Interface = ifaceFromCombo(captureDevs, uiIntIface.CurrentIndex())
	cfg.Intercept.UplinkIface = ifaceFromCombo(captureDevs, uiIntUplink.CurrentIndex())
	cfg.Intercept.MFPIP = strings.TrimSpace(uiIntMFP.Text())
	cfg.Intercept.ICSPublic = strings.TrimSpace(uiIntICSPub.Text())
	cfg.Intercept.ICSPrivate = strings.TrimSpace(uiIntICSPrv.Text())
	cfg.Intercept.Promiscuous = uiIntPromisc.Checked()
	cfg.Intercept.DisableIPv6 = uiIntNoV6.Checked()
	cfg.Intercept.CaptureFilter = strings.TrimSpace(uiIntCapFilter.Text())
	cfg.Intercept.Carve.AllPorts = uiIntCarveAll.Checked()
	cfg.Intercept.Authorization.Acknowledged = uiIntAck.Checked()
	cfg.Intercept.Authorization.Operator = strings.TrimSpace(uiIntOperator.Text())
	cfg.Intercept.Authorization.Engagement = strings.TrimSpace(uiIntEngagement.Text())
	cfg.Intercept.Authorization.Expiry = strings.TrimSpace(uiIntExpiry.Text())
	cfg.Intercept.Carve.Enabled = uiIntCarveEn.Checked()
	cfg.Intercept.Carve.Ports = parseIntList(uiIntCarvePorts.Text())
	cfg.Intercept.ARP.Enabled = uiIntArpEn.Checked()
	cfg.Intercept.ARP.Targets = splitCSV(uiIntArpTargets.Text())
}

// refreshInterceptUI loads cfg into the Capture tab (called from refreshUIFromConfig).
func refreshInterceptUI() {
	if uiIntEnabled == nil {
		return
	}
	uiIntEnabled.SetChecked(cfg.Intercept.Enabled)
	uiIntIface.SetCurrentIndex(ifaceIndexFor(captureDevs, cfg.Intercept.Interface))
	uiIntUplink.SetCurrentIndex(ifaceIndexFor(captureDevs, cfg.Intercept.UplinkIface))
	uiIntMFP.SetText(cfg.Intercept.MFPIP)
	uiIntICSPub.SetText(cfg.Intercept.ICSPublic)
	uiIntICSPrv.SetText(cfg.Intercept.ICSPrivate)
	uiIntPromisc.SetChecked(cfg.Intercept.Promiscuous)
	uiIntNoV6.SetChecked(cfg.Intercept.DisableIPv6)
	uiIntCapFilter.SetText(cfg.Intercept.CaptureFilter)
	uiIntCarveAll.SetChecked(cfg.Intercept.Carve.AllPorts)
	uiIntAck.SetChecked(cfg.Intercept.Authorization.Acknowledged)
	uiIntOperator.SetText(cfg.Intercept.Authorization.Operator)
	uiIntEngagement.SetText(cfg.Intercept.Authorization.Engagement)
	uiIntExpiry.SetText(cfg.Intercept.Authorization.Expiry)
	uiIntCarveEn.SetChecked(cfg.Intercept.Carve.Enabled)
	uiIntCarvePorts.SetText(intsToCSV(cfg.Intercept.Carve.Ports))
	uiIntArpEn.SetChecked(cfg.Intercept.ARP.Enabled)
	uiIntArpTargets.SetText(strings.Join(cfg.Intercept.ARP.Targets, ", "))
}

// ================= native capture window =================

var (
	captureWin     *walk.MainWindow
	captureTV      *walk.TableView
	captureModel   *packetTableModel
	cwIface        *walk.ComboBox
	cwUplink       *walk.ComboBox
	cwMfp          *walk.LineEdit
	cwMfpOnly      *walk.CheckBox
	cwNoV6         *walk.CheckBox
	cwAck          *walk.CheckBox
	cwOperator     *walk.LineEdit
	cwEngagement   *walk.LineEdit
	cwFilter       *walk.LineEdit
	cwStatus       *walk.Label
	cwStartBtn     *walk.PushButton
	cwDevs         []captureDevice // the capture window's own adapter list
	captureCursor  uint64
	capturePolling bool
)

// packetTableModel backs the live packet TableView.
type packetTableModel struct {
	walk.TableModelBase
	rows   []packetSummary
	frames [][]byte // raw (header-truncated) bytes per row, for the detail popup
	link   int      // link type of the capture (for dissecting frames)
}

func (m *packetTableModel) RowCount() int { return len(m.rows) }

func (m *packetTableModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) {
		return ""
	}
	r := m.rows[row]
	switch col {
	case 0:
		return r.No
	case 1:
		return r.Time
	case 2:
		if r.Svc != "" {
			return r.Proto + "/" + r.Svc
		}
		return r.Proto
	case 3:
		return r.Src
	case 4:
		return r.Dst
	case 5:
		return r.Len
	case 6:
		return r.Info
	}
	return ""
}

// StyleCell color-codes rows: red = errors/resets, green = print jobs + SNMP,
// blue = HTTPS (443). Matches the packetSummary.Color computed by the dissector.
func (m *packetTableModel) StyleCell(style *walk.CellStyle) {
	i := style.Row()
	if i < 0 || i >= len(m.rows) {
		return
	}
	switch m.rows[i].Color {
	case "red":
		style.TextColor = walk.RGB(0xd7, 0x3a, 0x49) // readable red on white
	case "green":
		style.TextColor = walk.RGB(0x1a, 0x7f, 0x37) // light/medium green
	case "blue":
		style.TextColor = walk.RGB(0x1f, 0x6f, 0xeb) // light blue
	}
}

func showCaptureWindow() {
	if captureWin != nil {
		captureWin.Show()
		captureWin.SetFocus()
		return
	}
	labels, devs := interfaceLabels()
	labels, devs = ensureCurrentIface(labels, devs, cfg.Intercept.Interface)
	labels, devs = ensureCurrentIface(labels, devs, cfg.Intercept.UplinkIface)
	cwDevs = devs
	uplinkLabels := make([]string, len(labels))
	copy(uplinkLabels, labels)
	uplinkLabels[0] = "(none — single-homed)"
	logInfo("intercept", "GUI capture window: %d adapter(s) available", len(devs))
	captureModel = &packetTableModel{}

	err := (dec.MainWindow{
		AssignTo: &captureWin,
		Title:    "printcap — Packet capture",
		MinSize:  dec.Size{Width: 920, Height: 560},
		Size:     dec.Size{Width: 1120, Height: 680},
		Layout:   dec.VBox{},
		Children: []dec.Widget{
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.Label{Text: "Printer adapter:"},
					dec.ComboBox{AssignTo: &cwIface, Model: labels, MinSize: dec.Size{Width: 320}},
					dec.PushButton{AssignTo: &cwStartBtn, Text: "▶ Start capture", OnClicked: onCaptureStartStop},
					dec.PushButton{Text: "Packet details", OnClicked: onCapturePacketDetail},
					dec.PushButton{Text: "Clear", OnClicked: onCaptureClear},
					dec.PushButton{Text: "Open .pcap folder", OnClicked: openFolder},
					dec.HSpacer{},
				},
			},
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.CheckBox{AssignTo: &cwAck, Text: "Authorized"},
					dec.Label{Text: "Operator:"}, dec.LineEdit{AssignTo: &cwOperator, MinSize: dec.Size{Width: 120}},
					dec.Label{Text: "Engagement:"}, dec.LineEdit{AssignTo: &cwEngagement, MinSize: dec.Size{Width: 120}},
					dec.Label{Text: "Filter:"}, dec.LineEdit{AssignTo: &cwFilter, MinSize: dec.Size{Width: 240}, ToolTipText: "display filter: dst==10.0.0.5  port==9100  proto==arp  ipver!=6  len>100  svc==http  addr~10.0  (space = AND; bare word = substring)"},
					dec.HSpacer{},
				},
			},
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.Label{Text: "Internet uplink:"},
					dec.ComboBox{AssignTo: &cwUplink, Model: uplinkLabels, MinSize: dec.Size{Width: 240}},
					dec.Label{Text: "MFP IP:"}, dec.LineEdit{AssignTo: &cwMfp, MinSize: dec.Size{Width: 120}},
					dec.CheckBox{AssignTo: &cwMfpOnly, Text: "MFP only", OnClicked: onCaptureClear},
					dec.CheckBox{AssignTo: &cwNoV6, Text: "Hide IPv6", OnClicked: onCaptureClear},
					dec.HSpacer{},
				},
			},
			dec.TableView{
				AssignTo:         &captureTV,
				MinSize:          dec.Size{Width: 0, Height: 360},
				ColumnsOrderable: true,
				Columns: []dec.TableViewColumn{
					{Title: "#", Width: 60},
					{Title: "Time", Width: 100},
					{Title: "Proto", Width: 90},
					{Title: "Source", Width: 175},
					{Title: "Destination", Width: 175},
					{Title: "Len", Width: 60},
					{Title: "Info", Width: 360},
				},
				Model:           captureModel,
				OnItemActivated: onCaptureFollow,
			},
			dec.Label{AssignTo: &cwStatus, Text: "Idle. Pick an adapter and Start. Double-click a TCP row to follow its stream, or select a row and click \"Packet details\" for the full decode. (Live capture needs an Npcap build on Windows.)"},
		},
	}).Create()
	if err != nil || captureWin == nil {
		walk.MsgBox(mw, "Capture window", "Could not open the packet capture window:\n\n"+fmt.Sprint(err), walk.MsgBoxIconError)
		captureWin = nil
		return
	}
	captureTV.SetCellStyler(captureModel)
	cwIface.SetCurrentIndex(ifaceIndexFor(cwDevs, cfg.Intercept.Interface))
	cwUplink.SetCurrentIndex(ifaceIndexFor(cwDevs, cfg.Intercept.UplinkIface))
	cwMfp.SetText(cfg.Intercept.MFPIP)
	cwNoV6.SetChecked(cfg.Intercept.DisableIPv6)
	cwAck.SetChecked(cfg.Intercept.Authorization.Acknowledged)
	cwOperator.SetText(cfg.Intercept.Authorization.Operator)
	cwEngagement.SetText(cfg.Intercept.Authorization.Engagement)
	captureWin.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		stopCapturePolling()
		captureWin = nil
	})
	if captureBuilt && !npcapInstalled() {
		cwStatus.SetText("⚠ Npcap not detected — you'll be prompted to install it when you click Start.")
	}
	captureWin.Show()
}

func onCaptureClear() {
	if captureModel == nil {
		return
	}
	captureModel.rows = nil
	captureModel.frames = nil
	captureModel.PublishRowsReset()
}

// restartEngineForCapture applies a cfg change by stopping (to drain handlers and
// clear the running flag) and starting again — engine.Start() is a no-op while
// running, so a plain Start would not pick up the new intercept settings.
func restartEngineForCapture() error {
	if engineRunning() {
		if err := engineStop(); err != nil {
			return err
		}
	}
	return engineStart()
}

func onCaptureStartStop() {
	if capturePolling {
		cfg.Intercept.Enabled = false
		stopCapturePolling()
		// Stopping restarts the engine without the interceptor, whose teardown
		// restores ARP caches and IP forwarding — cleaning up everything we touched.
		if err := restartEngineForCapture(); err != nil {
			walk.MsgBox(captureWin, "Stop failed", err.Error(), walk.MsgBoxIconError)
		}
		cwStartBtn.SetText("▶ Start capture")
		cwStatus.SetText("Stopped — ARP caches and IP forwarding restored.")
		return
	}

	// Live capture in THIS window needs the engine running in-process: as an
	// installed service it runs in another process whose ring this GUI can't see.
	if serviceInstalled() {
		walk.MsgBox(captureWin, "Live capture unavailable in service mode",
			"printcap is installed as a Windows service, so capture runs in the service process and this window cannot show its packets live.\n\nEither remove/stop the service and capture from this GUI, or open the web dashboard's Captures view on the service host.",
			walk.MsgBoxIconWarning)
		return
	}

	// Npcap is required for live capture; prompt to install it if it's missing.
	if !ensureNpcap(captureWin) {
		return
	}

	// Apply the window's quick settings into cfg, then restart the engine.
	cfg.Intercept.Interface = ifaceFromCombo(cwDevs, cwIface.CurrentIndex())
	cfg.Intercept.UplinkIface = ifaceFromCombo(cwDevs, cwUplink.CurrentIndex())
	cfg.Intercept.MFPIP = strings.TrimSpace(cwMfp.Text())
	cfg.Intercept.DisableIPv6 = cwNoV6.Checked()
	cfg.Intercept.Enabled = true
	cfg.Intercept.Authorization.Acknowledged = cwAck.Checked()
	cfg.Intercept.Authorization.Operator = strings.TrimSpace(cwOperator.Text())
	cfg.Intercept.Authorization.Engagement = strings.TrimSpace(cwEngagement.Text())
	if err := restartEngineForCapture(); err != nil {
		walk.MsgBox(captureWin, "Start failed", err.Error(), walk.MsgBoxIconError)
		return
	}
	if interceptModule == nil {
		walk.MsgBox(captureWin, "Capture not started",
			"Interception did not start. Check that the authorization fields are filled in, an adapter is selected, and (on Windows) that this is an Npcap build with Npcap installed. See the log for details.",
			walk.MsgBoxIconWarning)
		return
	}
	captureCursor = 0
	captureModel.rows = nil
	captureModel.frames = nil
	captureModel.PublishRowsReset()
	startCapturePolling()
	cwStartBtn.SetText("■ Stop capture")
	cwStatus.SetText("Capturing…")
}

func startCapturePolling() {
	if capturePolling {
		return
	}
	capturePolling = true
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			w := captureWin // local ref: avoid a nil-deref if Closing clears it
			if !capturePolling || w == nil {
				return
			}
			w.Synchronize(pumpCaptureRows)
		}
	}()
}

func stopCapturePolling() { capturePolling = false }

func pumpCaptureRows() {
	if captureModel == nil || captureWin == nil {
		return
	}
	recs, link, cursor, firstNo, dropped := captureLive.since(captureCursor, 2000)
	captureCursor = cursor
	captureModel.link = link
	f := captureFilter{q: strings.TrimSpace(cwFilter.Text())}
	if cwNoV6 != nil && cwNoV6.Checked() {
		f.noV6 = true // immediate view filter (capture-time drop applies on next Start)
	}
	if cwMfpOnly != nil && cwMfpOnly.Checked() {
		if a, err := netip.ParseAddr(strings.TrimSpace(cwMfp.Text())); err == nil {
			f.host = a.String() // "MFP only" → show just traffic to/from the printer
		}
	}
	added := 0
	for i, rec := range recs {
		s := dissectSummary(link, rec.data)
		s.No = int(firstNo) + i
		s.Len = rec.origLen
		s.Time = rec.ts.Format("15:04:05.000")
		if captureMatch(s, f) {
			captureModel.rows = append(captureModel.rows, s)
			captureModel.frames = append(captureModel.frames, append([]byte(nil), rec.data...))
			added++
		}
	}
	trimmed := 0
	if len(captureModel.rows) > 5000 {
		trimmed = len(captureModel.rows) - 5000
		captureModel.rows = captureModel.rows[trimmed:]
		captureModel.frames = captureModel.frames[trimmed:]
	}
	// Only refresh the table when something actually changed, and preserve the
	// user's row selection across the refresh (so "Packet details" works while
	// capturing). Auto-scroll to the newest row only when nothing is selected.
	if added > 0 || trimmed > 0 {
		sel := captureTV.CurrentIndex()
		captureModel.PublishRowsReset()
		if sel >= 0 {
			if ns := sel - trimmed; ns >= 0 && ns < len(captureModel.rows) {
				captureTV.SetCurrentIndex(ns)
				captureTV.EnsureItemVisible(ns)
			}
		} else if n := len(captureModel.rows); n > 0 {
			captureTV.EnsureItemVisible(n - 1)
		}
	}
	seq, _ := captureLive.stats()
	status := fmt.Sprintf("Capturing — %d packets seen, %d shown", seq, len(captureModel.rows))
	if dropped > 0 {
		status += " · ring overrun (older packets dropped)"
	}
	cwStatus.SetText(status)
}

// onCaptureFollow reassembles the selected row's TCP conversation and shows both
// directions in a text window.
func onCaptureFollow() {
	if captureModel == nil {
		return
	}
	i := captureTV.CurrentIndex()
	if i < 0 || i >= len(captureModel.rows) {
		return
	}
	r := captureModel.rows[i]
	a, err1 := netip.ParseAddrPort(r.Src)
	b, err2 := netip.ParseAddrPort(r.Dst)
	if err1 != nil || err2 != nil {
		walk.MsgBox(captureWin, "Follow stream", "This row is not a TCP/UDP flow with ip:port endpoints.", walk.MsgBoxIconInformation)
		return
	}
	ab, ba, _, err := followStream(interceptPcapPath(cfg.Intercept), a, b)
	if err != nil {
		walk.MsgBox(captureWin, "Follow stream", "Could not read the capture file: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "=== %s -> %s  (%d bytes, client to server) ===\r\n", a, b, len(ab))
	sb.WriteString(sanitizeStream(ab))
	fmt.Fprintf(&sb, "\r\n\r\n=== %s -> %s  (%d bytes, server to client) ===\r\n", b, a, len(ba))
	sb.WriteString(sanitizeStream(ba))
	showTextWindow("Follow TCP stream — "+r.Src+" / "+r.Dst, sb.String())
}

// onCapturePacketDetail shows the full layered decode + hex dump of the selected
// packet (the same per-packet detail as the dashboard's popup).
func onCapturePacketDetail() {
	if captureModel == nil {
		return
	}
	i := captureTV.CurrentIndex()
	if i < 0 || i >= len(captureModel.frames) {
		walk.MsgBox(captureWin, "Packet details", "Select a packet row first.", walk.MsgBoxIconInformation)
		return
	}
	d := dissectDetail(captureModel.link, captureModel.frames[i])
	d.No = captureModel.rows[i].No
	// The live ring keeps only header bytes; note when the wire frame was longer.
	if full := captureModel.rows[i].Len; full > d.Len {
		d.Hex += fmt.Sprintf("\n(showing first %d of %d bytes — download the .pcap for the full payload)\n", d.Len, full)
	}
	showTextWindow(fmt.Sprintf("Packet #%d details", d.No), detailText(d))
}

// sanitizeStream renders captured bytes as readable text (control bytes -> '.'),
// capped for display.
func sanitizeStream(b []byte) string {
	const max = 32768
	note := ""
	if len(b) > max {
		note = fmt.Sprintf("\r\n… %d more bytes (download the pcap for the full stream)", len(b)-max)
		b = b[:max]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch {
		case c == '\n' || c == '\t':
			out = append(out, c)
		case c == '\r':
			// keep, paired \r\n handled by viewer
			out = append(out, c)
		case c >= 32 && c < 127:
			out = append(out, c)
		default:
			out = append(out, '.')
		}
	}
	return string(out) + note
}

// showTextWindow opens a simple read-only text window (for reassembled streams).
func showTextWindow(title, body string) {
	var w *walk.MainWindow
	_ = dec.MainWindow{
		AssignTo: &w,
		Title:    title,
		MinSize:  dec.Size{Width: 780, Height: 540},
		Layout:   dec.VBox{},
		Children: []dec.Widget{
			dec.TextEdit{Text: body, ReadOnly: true, VScroll: true, HScroll: true},
		},
	}.Create()
	if w != nil {
		w.Show()
	}
}
