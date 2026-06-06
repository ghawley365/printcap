//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	dec "github.com/lxn/walk/declarative"
)

// The GUI is a single settings window with a system-tray icon. Closing the
// window quits printcap (the engine stops and the process exits); background
// capture is done via the Windows service or -console. It
// edits the shared cfg, persists it to configFilePath, and drives the capture
// engine. "Smart" engine control: if the Windows service is installed, the
// Start/Stop and status reflect the service; otherwise the engine runs
// in-process inside the GUI.

// protoRow is one protocol's enable checkbox + port editor.
type protoRow struct {
	enable  *walk.CheckBox
	port    *walk.NumberEdit
	defPort int
}

var (
	mw         *walk.MainWindow
	notifyIcon *walk.NotifyIcon

	uiStatus    *walk.Label
	uiStartStop *walk.PushButton
	uiSvcStatus *walk.Label

	uiOut    *walk.LineEdit
	uiSave   *walk.ComboBox
	uiMaxJob *walk.NumberEdit
	uiBind   *walk.LineEdit

	rowRaw, rowLPR, rowIPP, rowIPPS, rowAuto, rowDash, rowSNMP protoRow

	uiName, uiModel, uiLoc, uiSerial *walk.LineEdit
	uiColor, uiEnforce               *walk.CheckBox

	uiSnmpEnabled                                              *walk.CheckBox
	uiCommunity, uiSysDescr, uiSysName, uiSysLoc, uiSysContact *walk.LineEdit
	uiSysObj                                                   *walk.LineEdit
	uiPageCount, uiToner                                       *walk.NumberEdit

	// RAW / LPR options
	uiRawParsePJL, uiRawSplitUEL *walk.CheckBox
	uiRawExtraPorts              *walk.LineEdit
	uiLpdAnyQueue, uiLpdPrivPort *walk.CheckBox
	uiLpdParsePJL                *walk.CheckBox
	uiLpdAllowed                 *walk.LineEdit

	// IPP / TLS options
	uiIppPaths, uiIppDefaultPath *walk.LineEdit
	uiCertFile, uiKeyFile        *walk.LineEdit

	// Logging
	uiLogLevel, uiLogFormat                    *walk.ComboBox
	uiLogFile, uiLogJSONFile                   *walk.LineEdit
	uiLogMaxSize, uiLogMaxBackups              *walk.NumberEdit
	uiLogConsole, uiLogProtocol, uiLogEventLog *walk.CheckBox

	// SIEM / syslog
	uiSyslogEnabled, uiSyslogRFC5424 *walk.CheckBox
	uiSyslogNet                      *walk.ComboBox
	uiSyslogAddr, uiSyslogApp        *walk.LineEdit
	uiSyslogFacility                 *walk.NumberEdit

	// Storage
	uiSpoolDir *walk.LineEdit

	// Dashboard
	uiDashEnabled *walk.CheckBox

	// General — capture notifications (cfg.Notifications)
	uiNotifications *walk.CheckBox

	// Service — start the tray GUI at login (registry-backed, not a cfg field)
	uiRunAtLogin *walk.CheckBox

	// Printer (extended)
	uiInfo, uiDocFormats, uiDefaultFormat *walk.LineEdit
	uiSides, uiResolutions, uiMedia       *walk.LineEdit

	// SNMPv3 / USM
	uiSnmpV3, uiSnmpAllowV12 *walk.CheckBox
	uiEngineID               *walk.LineEdit
	uiSnmpUsers              *walk.TextEdit

	// Discovery — mDNS + WSD
	uiMdnsEnabled, uiMdnsAirPrint  *walk.CheckBox
	uiMdnsInstance, uiMdnsHostname *walk.LineEdit
	uiWsdEnabled, uiWsdDiscovery   *walk.CheckBox
	uiWsdPort                      *walk.NumberEdit

	// SMB
	uiSmbEnabled, uiSmbRequireAuth, uiSmbSign, uiSmbEncrypt *walk.CheckBox
	uiSmbPort                                               *walk.NumberEdit
	uiSmbShare                                              *walk.LineEdit
	uiSmbUsers                                              *walk.TextEdit

	// Mainframe / EBCDIC
	uiEbcdicEnabled, uiEbcdicAuto, uiEbcdicSidecar *walk.CheckBox
	uiEbcdicCodePage, uiEbcdicCarriage             *walk.ComboBox
	uiLpdQueueDefaults                             *walk.TextEdit

	// Forward proxy
	uiFwdEnabled              *walk.CheckBox
	uiFwdCapture              *walk.ComboBox
	uiFwdMacros, uiFwdTargets *walk.TextEdit

	// Content / DLP
	uiDlpEnabled *walk.CheckBox
	uiDlpRules   *walk.TextEdit

	helpWin *walk.MainWindow
)

var saveModes = []string{"both", "raw", "meta"}
var logLevels = []string{"error", "warn", "info", "debug", "trace"}
var logFormats = []string{"text", "json"}
var syslogNets = []string{"udp", "tcp"}
var ebcdicCodePages = []string{"CP037", "CP500", "CP1047", "CP273", "CP285", "CP297"}
var carriageModes = []string{"none", "asa", "machine", "auto"}
var captureModes = []string{"both", "sent", "orig"}

// jsonBlock pretty-prints v as indented JSON for an in-GUI editor. On error it
// returns the empty string (the editor will simply start blank).
func jsonBlock(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func runGUI() {
	if err := buildWindow(); err != nil {
		// If the GUI can't be created (e.g. missing common controls), fall back
		// to running headless so the tool is never dead-on-arrival.
		attachConsole()
		runConsole()
		return
	}

	// System tray icon + menu.
	notifyIcon, _ = walk.NewNotifyIcon(mw)
	if notifyIcon != nil {
		if icon := loadAppIcon(); icon != nil {
			notifyIcon.SetIcon(icon)
			mw.SetIcon(icon)
		}
		notifyIcon.SetToolTip("printcap — print capture")
		_ = notifyIcon.SetVisible(true)
		notifyIcon.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
			if button == walk.LeftButton {
				showMain()
			}
		})
		addTrayAction("Open printcap", showMain)
		addTrayAction("Open Dashboard", openDashboard)
		addTrayAction("Open Capture Folder", openFolder)
		notifyIcon.ContextMenu().Actions().Add(walk.NewSeparatorAction())
		addTrayAction("Exit", func() { mw.Close() })

		// Show a tray balloon after each capture (gated by cfg.Notifications via
		// notifyCapture). Marshalled onto the GUI thread; guarded against a nil
		// icon in case it was disposed.
		onCapture = func(j *job) {
			title := "printcap — job captured"
			body := fmt.Sprintf("%s · %s · %d bytes",
				j.Protocol, firstNonEmpty(j.JobName, j.Source), j.Bytes)
			mw.Synchronize(func() {
				if notifyIcon != nil {
					_ = notifyIcon.ShowMessage(title, body)
				}
			})
		}
	}

	// Closing the window exits printcap. Stop the capture engine first (release
	// listener ports + capture/spool files, send mDNS/WSD goodbye, drain all
	// goroutines) and hide the tray icon, so the process fully terminates and no
	// longer locks the executable. To keep capturing in the background, use the
	// Windows service (Service tab) or run -console — closing the GUI is a quit.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if engineRunning() {
			_ = engineStop()
		}
		if notifyIcon != nil {
			_ = notifyIcon.SetVisible(false)
		}
	})

	refreshUIFromConfig()
	updateStatus()

	// Periodically refresh status (the service state can change externally).
	go statusTicker()

	mw.Run()
	if notifyIcon != nil {
		notifyIcon.Dispose()
	}
}

// loadAppIcon returns the application/tray icon. It first tries the icon
// embedded in the exe by goversioninfo (resource ID 2 — the first icon group
// goversioninfo writes when versioninfo.json sets IconPath). If no .ico was
// embedded, it falls back to a generic printer glyph from imageres.dll so the
// tray always has an icon. Returns nil only if both sources fail.
func loadAppIcon() *walk.Icon {
	if icon, err := walk.NewIconFromResourceId(2); err == nil && icon != nil {
		return icon
	}
	if icon, err := walk.NewIconFromSysDLL("imageres", 109); err == nil {
		return icon
	}
	return nil
}

func buildWindow() error {
	return dec.MainWindow{
		AssignTo: &mw,
		Title:    "printcap — Print Capture",
		MinSize:  dec.Size{Width: 560, Height: 640},
		Size:     dec.Size{Width: 600, Height: 680},
		Layout:   dec.VBox{},
		Children: []dec.Widget{
			// Status / control bar.
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.Label{AssignTo: &uiStatus, Text: "…"},
					dec.HSpacer{},
					dec.PushButton{AssignTo: &uiStartStop, Text: "Start", OnClicked: onStartStop},
					dec.PushButton{Text: "Open Dashboard", OnClicked: openDashboard},
					dec.PushButton{Text: "Open Folder", OnClicked: openFolder},
					dec.PushButton{Text: "Help", OnClicked: showHelp},
				},
			},
			dec.TabWidget{
				Pages: []dec.TabPage{
					generalTab(),
					protocolsTab(),
					rawLprTab(),
					ippTlsTab(),
					printerTab(),
					snmpTab(),
					discoveryTab(),
					smbTab(),
					ebcdicTab(),
					forwardTab(),
					dlpTab(),
					captureTab(),
					loggingTab(),
					serviceTab(),
				},
			},
			// Bottom action bar.
			dec.Composite{
				Layout: dec.HBox{},
				Children: []dec.Widget{
					dec.HSpacer{},
					dec.PushButton{Text: "Save Settings", OnClicked: onSave},
					dec.PushButton{Text: "Save && Restart", OnClicked: onSaveRestart},
				},
			},
		},
	}.Create()
}

func generalTab() dec.TabPage {
	return dec.TabPage{
		Title:  "General",
		Layout: dec.Grid{Columns: 3},
		Children: []dec.Widget{
			dec.Label{Text: "Capture directory:"},
			dec.LineEdit{AssignTo: &uiOut},
			dec.PushButton{Text: "Browse…", OnClicked: onBrowse},

			dec.Label{Text: "Spool/retry folder (blank = <exe>/spool):"},
			dec.LineEdit{AssignTo: &uiSpoolDir},
			dec.HSpacer{},

			dec.Label{Text: "Save mode:"},
			dec.ComboBox{AssignTo: &uiSave, Model: saveModes},
			dec.HSpacer{},

			dec.Label{Text: "Max job size (MB, 0 = unlimited):"},
			dec.NumberEdit{AssignTo: &uiMaxJob, MinValue: 0, MaxValue: 100000, Decimals: 0},
			dec.HSpacer{},

			dec.Label{Text: "Bind address:"},
			dec.LineEdit{AssignTo: &uiBind},
			dec.Label{Text: "(0.0.0.0 = all interfaces; 127.0.0.1 = local only)"},

			dec.Label{Text: ""},
			dec.CheckBox{AssignTo: &uiDashEnabled, Text: "Enable web dashboard"},
			dec.HSpacer{},

			dec.Label{Text: ""},
			dec.CheckBox{AssignTo: &uiNotifications, Text: "Show a tray notification after each captured job"},
			dec.HSpacer{},
		},
	}
}

func protocolsTab() dec.TabPage {
	row := func(label string, r *protoRow, def int) []dec.Widget {
		r.defPort = def
		return []dec.Widget{
			dec.CheckBox{AssignTo: &r.enable, Text: label},
			dec.NumberEdit{AssignTo: &r.port, MinValue: 0, MaxValue: 65535, Decimals: 0},
			dec.HSpacer{},
		}
	}
	var children []dec.Widget
	children = append(children, dec.Label{Text: "Enable a protocol and set its port. Ports < 1024 require running as Administrator."}, dec.HSpacer{}, dec.HSpacer{})
	children = append(children, row("Raw / JetDirect / AppSocket (TCP)", &rowRaw, 9100)...)
	children = append(children, row("LPR / LPD (TCP)", &rowLPR, 515)...)
	children = append(children, row("IPP (TCP)", &rowIPP, 631)...)
	children = append(children, row("IPPS / TLS (TCP)", &rowIPPS, 6310)...)
	children = append(children, row("IPP+IPPS auto-detect, one port (TCP)", &rowAuto, 631)...)
	children = append(children, row("SNMP agent (UDP)", &rowSNMP, 161)...)
	children = append(children, row("Web dashboard (TCP)", &rowDash, 8631)...)
	return dec.TabPage{
		Title:    "Protocols & Ports",
		Layout:   dec.Grid{Columns: 3},
		Children: children,
	}
}

func rawLprTab() dec.TabPage {
	return dec.TabPage{
		Title:  "RAW & LPR",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Raw / JetDirect / AppSocket (9100)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: "Extra raw ports (comma-separated, e.g. 9101,9102):"},
					dec.LineEdit{AssignTo: &uiRawExtraPorts},
					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiRawParsePJL, Text: "Parse PJL for job name / user"},
					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiRawSplitUEL, Text: "Split multiple jobs on one connection at UEL boundaries"},
				},
			},
			dec.GroupBox{
				Title:  "LPR / LPD (515) — enterprise (SAP, IBM AS/400, z/OS, Linux/CUPS)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLpdAnyQueue, Text: "Accept any queue name (recommended)"},
					dec.Label{Text: "Allowed queues (comma-separated; used only if above is off):"},
					dec.LineEdit{AssignTo: &uiLpdAllowed},
					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLpdPrivPort, Text: "Require privileged source port (RFC 1179 721–731) — usually OFF"},
					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLpdParsePJL, Text: "Also parse PJL inside the data file"},
				},
			},
			dec.VSpacer{},
		},
	}
}

func ippTlsTab() dec.TabPage {
	return dec.TabPage{
		Title:  "IPP & TLS",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "IPP / IPPS resource paths",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: "Advertised paths (comma-separated):"},
					dec.LineEdit{AssignTo: &uiIppPaths},
					dec.Label{Text: "Primary path (printer-uri):"},
					dec.LineEdit{AssignTo: &uiIppDefaultPath},
				},
			},
			dec.GroupBox{
				Title:  "IPPS / TLS certificate (blank = self-signed in memory)",
				Layout: dec.Grid{Columns: 3},
				Children: []dec.Widget{
					dec.Label{Text: "Certificate (PEM):"},
					dec.LineEdit{AssignTo: &uiCertFile},
					dec.PushButton{Text: "Browse…", OnClicked: func() { browseFile(uiCertFile) }},
					dec.Label{Text: "Private key (PEM):"},
					dec.LineEdit{AssignTo: &uiKeyFile},
					dec.PushButton{Text: "Browse…", OnClicked: func() { browseFile(uiKeyFile) }},
					dec.Label{Text: ""},
					dec.PushButton{Text: "Generate self-signed cert + key…", OnClicked: onGenerateCert},
					dec.HSpacer{},
				},
			},
			dec.VSpacer{},
		},
	}
}

func printerTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Printer Identity",
		Layout: dec.Grid{Columns: 2},
		Children: []dec.Widget{
			dec.Label{Text: "Name:"}, dec.LineEdit{AssignTo: &uiName},
			dec.Label{Text: "Info / description:"}, dec.LineEdit{AssignTo: &uiInfo},
			dec.Label{Text: "Make and model:"}, dec.LineEdit{AssignTo: &uiModel},
			dec.Label{Text: "Location:"}, dec.LineEdit{AssignTo: &uiLoc},
			dec.Label{Text: "Serial number:"}, dec.LineEdit{AssignTo: &uiSerial},
			dec.Label{Text: "Document formats (CSV MIME types):"}, dec.LineEdit{AssignTo: &uiDocFormats},
			dec.Label{Text: "Default format:"}, dec.LineEdit{AssignTo: &uiDefaultFormat},
			dec.Label{Text: "Sides (CSV, e.g. one-sided,two-sided-long-edge):"}, dec.LineEdit{AssignTo: &uiSides},
			dec.Label{Text: "Resolutions (CSV dpi, e.g. 300,600):"}, dec.LineEdit{AssignTo: &uiResolutions},
			dec.Label{Text: "Media (CSV, e.g. iso_a4_210x297mm):"}, dec.LineEdit{AssignTo: &uiMedia},
			dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiColor, Text: "Advertise color support"},
			dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiEnforce, Text: "Reject IPP jobs with unsupported document formats"},
		},
	}
}

func snmpTab() dec.TabPage {
	return dec.TabPage{
		Title:  "SNMP",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Agent identity (v1/v2c)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSnmpEnabled, Text: "Enable SNMP discovery agent"},
					dec.Label{Text: "Community string:"}, dec.LineEdit{AssignTo: &uiCommunity},
					dec.Label{Text: "System description:"}, dec.LineEdit{AssignTo: &uiSysDescr},
					dec.Label{Text: "System name:"}, dec.LineEdit{AssignTo: &uiSysName},
					dec.Label{Text: "System location:"}, dec.LineEdit{AssignTo: &uiSysLoc},
					dec.Label{Text: "System contact:"}, dec.LineEdit{AssignTo: &uiSysContact},
					dec.Label{Text: "sysObjectID (vendor OID):"}, dec.LineEdit{AssignTo: &uiSysObj},
					dec.Label{Text: "Reported page count:"}, dec.NumberEdit{AssignTo: &uiPageCount, MinValue: 0, MaxValue: 1e9, Decimals: 0},
					dec.Label{Text: "Reported toner level (%):"}, dec.NumberEdit{AssignTo: &uiToner, MinValue: 0, MaxValue: 100, Decimals: 0},
				},
			},
			dec.GroupBox{
				Title:  "SNMPv3 (USM)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSnmpV3, Text: "Enable SNMPv3 (USM)"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSnmpAllowV12, Text: "Also allow v1/v2c"},
					dec.Label{Text: "Engine ID (hex, blank=auto):"}, dec.LineEdit{AssignTo: &uiEngineID},
					dec.Label{Text: "USM users (JSON array):"},
					dec.Label{Text: "fields: user/level/auth_protocol/auth_pass/priv_protocol/priv_pass"},
					dec.TextEdit{AssignTo: &uiSnmpUsers, VScroll: true, ColumnSpan: 2, MinSize: dec.Size{Height: 120}},
				},
			},
			dec.VSpacer{},
		},
	}
}

func discoveryTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Discovery",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "mDNS / DNS-SD (Bonjour / AirPrint)",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiMdnsEnabled, Text: "Enable mDNS responder"},
					dec.Label{Text: "Instance name (blank = printer name):"}, dec.LineEdit{AssignTo: &uiMdnsInstance},
					dec.Label{Text: "Hostname (blank = sanitized name):"}, dec.LineEdit{AssignTo: &uiMdnsHostname},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiMdnsAirPrint, Text: "Advertise AirPrint"},
				},
			},
			dec.GroupBox{
				Title:  "WSD (Web Services for Devices) — experimental",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiWsdEnabled, Text: "Enable WSD print service"},
					dec.Label{Text: "WSD port:"}, dec.NumberEdit{AssignTo: &uiWsdPort, MinValue: 0, MaxValue: 65535, Decimals: 0},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiWsdDiscovery, Text: "Run WS-Discovery multicast responder"},
				},
			},
			dec.VSpacer{},
		},
	}
}

func smbTab() dec.TabPage {
	return dec.TabPage{
		Title:  "SMB Share",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Experimental SMB2/3 print share",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSmbEnabled, Text: "Enable experimental SMB print share"},
					dec.Label{Text: "Port:"}, dec.NumberEdit{AssignTo: &uiSmbPort, MinValue: 0, MaxValue: 65535, Decimals: 0},
					dec.Label{Text: "Share name:"}, dec.LineEdit{AssignTo: &uiSmbShare},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSmbRequireAuth, Text: "Require authentication"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSmbSign, Text: "Sign"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiSmbEncrypt, Text: "Encrypt"},
					dec.Label{Text: "Users (JSON array of user/password/domain):"},
					dec.Label{Text: "SMB capture is experimental."},
					dec.TextEdit{AssignTo: &uiSmbUsers, VScroll: true, ColumnSpan: 2, MinSize: dec.Size{Height: 120}},
				},
			},
			dec.VSpacer{},
		},
	}
}

func ebcdicTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Mainframe / EBCDIC",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "EBCDIC decoding",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiEbcdicEnabled, Text: "Enable EBCDIC decoding"},
					dec.Label{Text: "Default code page:"}, dec.ComboBox{AssignTo: &uiEbcdicCodePage, Model: ebcdicCodePages},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiEbcdicAuto, Text: "Auto-detect EBCDIC streams"},
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiEbcdicSidecar, Text: "Write decoded sidecar"},
					dec.Label{Text: "Carriage control:"}, dec.ComboBox{AssignTo: &uiEbcdicCarriage, Model: carriageModes},
				},
			},
			dec.GroupBox{
				Title:  "LPD per-queue defaults (JSON object: queue-glob → {code_page, carriage_control, ebcdic})",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.TextEdit{AssignTo: &uiLpdQueueDefaults, VScroll: true, MinSize: dec.Size{Height: 140}},
				},
			},
			dec.VSpacer{},
		},
	}
}

func forwardTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Forward Proxy",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Forwarding",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiFwdEnabled, Text: "Enable forwarding"},
					dec.Label{Text: "Capture mode:"}, dec.ComboBox{AssignTo: &uiFwdCapture, Model: captureModes},
				},
			},
			dec.GroupBox{
				Title:  "Macros (JSON object: name → value)",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.TextEdit{AssignTo: &uiFwdMacros, VScroll: true, MinSize: dec.Size{Height: 80}},
				},
			},
			dec.GroupBox{
				Title:  "Targets (JSON array)",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.Label{Text: "Each target is edited as JSON (transport, address, when, transforms, retry, failure)."},
					dec.TextEdit{AssignTo: &uiFwdTargets, VScroll: true, MinSize: dec.Size{Height: 180}},
				},
			},
			dec.VSpacer{},
		},
	}
}

func dlpTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Content / DLP",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Content inspection",
				Layout: dec.Grid{Columns: 2},
				Children: []dec.Widget{
					dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiDlpEnabled, Text: "Enable content inspection (DLP)"},
				},
			},
			dec.GroupBox{
				Title:  "Rules (JSON array of name/mode/pattern; mode = keyword|regex)",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.TextEdit{AssignTo: &uiDlpRules, VScroll: true, MinSize: dec.Size{Height: 180}},
				},
			},
			dec.VSpacer{},
		},
	}
}

func loggingTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Logging",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Log file & level",
				Layout: dec.Grid{Columns: 3},
				Children: []dec.Widget{
					dec.Label{Text: "Log level:"},
					dec.ComboBox{AssignTo: &uiLogLevel, Model: logLevels},
					dec.Label{Text: "(trace = per-connection / per-OID detail)"},

					dec.Label{Text: "File format:"},
					dec.ComboBox{AssignTo: &uiLogFormat, Model: logFormats},
					dec.Label{Text: "(json = machine-readable lines)"},

					dec.Label{Text: "Log file:"},
					dec.LineEdit{AssignTo: &uiLogFile},
					dec.PushButton{Text: "Browse…", OnClicked: func() { browseSaveFile(uiLogFile) }},

					dec.Label{Text: "Max file size (MB):"},
					dec.NumberEdit{AssignTo: &uiLogMaxSize, MinValue: 0, MaxValue: 100000, Decimals: 0},
					dec.HSpacer{},

					dec.Label{Text: "Rotated files to keep:"},
					dec.NumberEdit{AssignTo: &uiLogMaxBackups, MinValue: 0, MaxValue: 100, Decimals: 0},
					dec.HSpacer{},

					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLogConsole, Text: "Also log to console (-console mode)"},
					dec.HSpacer{},

					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLogProtocol, Text: "Verbose protocol logging (per connection / op) at INFO"},
					dec.HSpacer{},

					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiLogEventLog, Text: "Mirror warnings/errors to Windows Event Log (service)"},
					dec.HSpacer{},

					dec.Label{Text: ""},
					dec.Composite{
						Layout: dec.HBox{},
						Children: []dec.Widget{
							dec.PushButton{Text: "Open Log File", OnClicked: openLogFile},
							dec.PushButton{Text: "Open Folder", OnClicked: openFolder},
							dec.HSpacer{},
						},
					},
					dec.HSpacer{},
				},
			},
			dec.GroupBox{
				Title:  "SIEM export — JSON-lines file & remote syslog",
				Layout: dec.Grid{Columns: 3},
				Children: []dec.Widget{
					dec.Label{Text: "JSON-lines file (for Splunk/Filebeat):"},
					dec.LineEdit{AssignTo: &uiLogJSONFile},
					dec.PushButton{Text: "Browse…", OnClicked: func() { browseSaveFile(uiLogJSONFile) }},

					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiSyslogEnabled, Text: "Ship to remote syslog server"},
					dec.HSpacer{},

					dec.Label{Text: "Syslog server (host:port):"},
					dec.LineEdit{AssignTo: &uiSyslogAddr},
					dec.HSpacer{},

					dec.Label{Text: "Transport:"},
					dec.ComboBox{AssignTo: &uiSyslogNet, Model: syslogNets},
					dec.HSpacer{},

					dec.Label{Text: "Facility (0–23, 16 = local0):"},
					dec.NumberEdit{AssignTo: &uiSyslogFacility, MinValue: 0, MaxValue: 23, Decimals: 0},
					dec.HSpacer{},

					dec.Label{Text: "App name / tag:"},
					dec.LineEdit{AssignTo: &uiSyslogApp},
					dec.HSpacer{},

					dec.Label{Text: ""},
					dec.CheckBox{AssignTo: &uiSyslogRFC5424, Text: "Use RFC 5424 framing (off = RFC 3164 / BSD)"},
					dec.HSpacer{},
				},
			},
			dec.VSpacer{},
		},
	}
}

func serviceTab() dec.TabPage {
	return dec.TabPage{
		Title:  "Service & Firewall",
		Layout: dec.VBox{},
		Children: []dec.Widget{
			dec.GroupBox{
				Title:  "Windows service (runs unattended at boot)",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.Label{AssignTo: &uiSvcStatus, Text: "Service: …"},
					dec.Label{Text: "Install/Remove requires running printcap as Administrator."},
					dec.Composite{
						Layout: dec.HBox{},
						Children: []dec.Widget{
							dec.PushButton{Text: "Install Service", OnClicked: onInstall},
							dec.PushButton{Text: "Remove Service", OnClicked: onRemove},
							dec.PushButton{Text: "Start Service", OnClicked: onSvcStart},
							dec.PushButton{Text: "Stop Service", OnClicked: onSvcStop},
							dec.HSpacer{},
						},
					},
					dec.CheckBox{
						AssignTo: &uiRunAtLogin,
						Text:     "Start printcap automatically when I log in",
					},
				},
			},
			dec.GroupBox{
				Title:  "Windows Defender Firewall",
				Layout: dec.VBox{},
				Children: []dec.Widget{
					dec.Label{Text: "Add an inbound allow rule so other machines can reach the listeners.\nRequires Administrator."},
					dec.Composite{
						Layout: dec.HBox{},
						Children: []dec.Widget{
							dec.PushButton{Text: "Allow through Firewall", OnClicked: onFirewallAdd},
							dec.PushButton{Text: "Remove Firewall Rule", OnClicked: onFirewallRemove},
							dec.HSpacer{},
						},
					},
				},
			},
			dec.VSpacer{},
		},
	}
}

// --- config <-> UI ----------------------------------------------------------

func refreshUIFromConfig() {
	uiOut.SetText(cfg.OutDir)
	uiSpoolDir.SetText(cfg.Storage.SpoolDir)
	uiSave.SetCurrentIndex(saveIndex(cfg.Save))
	uiMaxJob.SetValue(float64(cfg.MaxJobMB))
	uiBind.SetText(cfg.Bind)
	uiDashEnabled.SetChecked(cfg.Dashboard.Enabled)
	uiNotifications.SetChecked(cfg.Notifications)
	uiRunAtLogin.SetChecked(runAtLogin()) // system state, not a cfg field

	setRow(rowRaw, cfg.Ports.Raw9100)
	setRow(rowLPR, cfg.Ports.LPR)
	setRow(rowIPP, cfg.Ports.IPP)
	setRow(rowIPPS, cfg.Ports.IPPS)
	setRow(rowAuto, cfg.Ports.AutoTLS)
	setRow(rowSNMP, cfg.Ports.SNMP)
	setRow(rowDash, cfg.Ports.Dashboard)

	uiName.SetText(cfg.Printer.Name)
	uiInfo.SetText(cfg.Printer.Info)
	uiModel.SetText(cfg.Printer.MakeAndModel)
	uiLoc.SetText(cfg.Printer.Location)
	uiSerial.SetText(cfg.Printer.Serial)
	uiDocFormats.SetText(strings.Join(cfg.Printer.DocumentFormats, ", "))
	uiDefaultFormat.SetText(cfg.Printer.DefaultFormat)
	uiSides.SetText(strings.Join(cfg.Printer.Sides, ", "))
	uiResolutions.SetText(joinIntList(cfg.Printer.Resolutions))
	uiMedia.SetText(strings.Join(cfg.Printer.Media, ", "))
	uiColor.SetChecked(cfg.Printer.Color)
	uiEnforce.SetChecked(cfg.Printer.EnforceFormats)

	uiSnmpEnabled.SetChecked(cfg.SNMP.Enabled)
	uiCommunity.SetText(cfg.SNMP.Community)
	uiSysDescr.SetText(cfg.SNMP.SysDescr)
	uiSysName.SetText(cfg.SNMP.SysName)
	uiSysLoc.SetText(cfg.SNMP.SysLocation)
	uiSysContact.SetText(cfg.SNMP.SysContact)
	uiSysObj.SetText(cfg.SNMP.SysObjectID)
	uiPageCount.SetValue(float64(cfg.SNMP.PageCount))
	uiToner.SetValue(float64(cfg.SNMP.TonerLevelPct))
	uiSnmpV3.SetChecked(cfg.SNMP.V3Enabled)
	uiSnmpAllowV12.SetChecked(cfg.SNMP.AllowV1V2c)
	uiEngineID.SetText(cfg.SNMP.EngineID)
	uiSnmpUsers.SetText(jsonBlock(cfg.SNMP.Users))

	uiMdnsEnabled.SetChecked(cfg.MDNS.Enabled)
	uiMdnsInstance.SetText(cfg.MDNS.Instance)
	uiMdnsHostname.SetText(cfg.MDNS.Hostname)
	uiMdnsAirPrint.SetChecked(cfg.MDNS.AirPrint)
	uiWsdEnabled.SetChecked(cfg.WSD.Enabled)
	uiWsdPort.SetValue(float64(cfg.WSD.Port))
	uiWsdDiscovery.SetChecked(cfg.WSD.Discovery)

	uiSmbEnabled.SetChecked(cfg.SMB.Enabled)
	uiSmbPort.SetValue(float64(cfg.SMB.Port))
	uiSmbShare.SetText(cfg.SMB.ShareName)
	uiSmbRequireAuth.SetChecked(cfg.SMB.RequireAuth)
	uiSmbSign.SetChecked(cfg.SMB.Sign)
	uiSmbEncrypt.SetChecked(cfg.SMB.Encrypt)
	uiSmbUsers.SetText(jsonBlock(cfg.SMB.Users))

	uiEbcdicEnabled.SetChecked(cfg.EBCDIC.Enabled)
	uiEbcdicCodePage.SetCurrentIndex(indexOf(ebcdicCodePages, cfg.EBCDIC.DefaultCodePage, 0))
	uiEbcdicAuto.SetChecked(cfg.EBCDIC.AutoDetect)
	uiEbcdicSidecar.SetChecked(cfg.EBCDIC.DecodedSidecar)
	uiEbcdicCarriage.SetCurrentIndex(indexOf(carriageModes, cfg.EBCDIC.CarriageControl, 3))
	uiLpdQueueDefaults.SetText(jsonBlock(cfg.LPD.QueueDefaults))

	uiFwdEnabled.SetChecked(cfg.Forward.Enabled)
	uiFwdCapture.SetCurrentIndex(indexOf(captureModes, cfg.Forward.Capture, 0))
	uiFwdMacros.SetText(jsonBlock(cfg.Forward.Macros))
	uiFwdTargets.SetText(jsonBlock(cfg.Forward.Targets))

	uiDlpEnabled.SetChecked(cfg.DLP.Enabled)
	uiDlpRules.SetText(jsonBlock(cfg.DLP.Rules))

	uiRawParsePJL.SetChecked(cfg.Raw.ParsePJL)
	uiRawSplitUEL.SetChecked(cfg.Raw.SplitOnUEL)
	uiRawExtraPorts.SetText(joinIntList(cfg.Raw.ExtraPorts))
	uiLpdAnyQueue.SetChecked(cfg.LPD.AcceptAnyQueue)
	uiLpdAllowed.SetText(strings.Join(cfg.LPD.AllowedQueues, ", "))
	uiLpdPrivPort.SetChecked(cfg.LPD.RequirePrivilegedSourcePort)
	uiLpdParsePJL.SetChecked(cfg.LPD.ParsePJL)
	uiIppPaths.SetText(strings.Join(cfg.IPPOpts.ResourcePaths, ", "))
	uiIppDefaultPath.SetText(cfg.IPPOpts.DefaultPath)
	uiCertFile.SetText(cfg.TLS.CertFile)
	uiKeyFile.SetText(cfg.TLS.KeyFile)

	uiLogLevel.SetCurrentIndex(levelIndex(cfg.Log.Level))
	uiLogFormat.SetCurrentIndex(indexOf(logFormats, cfg.Log.Format, 0))
	uiLogFile.SetText(cfg.Log.File)
	uiLogJSONFile.SetText(cfg.Log.JSONFile)
	uiLogMaxSize.SetValue(float64(cfg.Log.MaxSizeMB))
	uiLogMaxBackups.SetValue(float64(cfg.Log.MaxBackups))
	uiLogConsole.SetChecked(cfg.Log.Console)
	uiLogProtocol.SetChecked(cfg.Log.Protocol)
	uiLogEventLog.SetChecked(cfg.Log.EventLog)

	uiSyslogEnabled.SetChecked(cfg.Log.Syslog.Enabled)
	uiSyslogNet.SetCurrentIndex(indexOf(syslogNets, cfg.Log.Syslog.Network, 0))
	uiSyslogAddr.SetText(cfg.Log.Syslog.Address)
	uiSyslogFacility.SetValue(float64(cfg.Log.Syslog.Facility))
	uiSyslogApp.SetText(cfg.Log.Syslog.AppName)
	uiSyslogRFC5424.SetChecked(cfg.Log.Syslog.RFC5424)
	refreshInterceptUI()
}

// applyUIToConfig pulls every widget back into the live cfg. Nested list/map
// sub-blocks are edited as JSON; any that fail to parse are left at their
// previous value and reported back to the caller as a list of errors.
func applyUIToConfig() []string {
	var jsonErrs []string
	// applyJSON unmarshals the editor text into dst. On error the previous
	// value (already in dst) is kept and the failure is recorded.
	applyJSON := func(label, text string, dst interface{}) {
		if err := json.Unmarshal([]byte(text), dst); err != nil {
			jsonErrs = append(jsonErrs, fmt.Sprintf("%s: %v", label, err))
		}
	}

	cfg.OutDir = uiOut.Text()
	cfg.Storage.SpoolDir = strings.TrimSpace(uiSpoolDir.Text())
	cfg.Save = saveModes[clampIndex(uiSave.CurrentIndex(), len(saveModes))]
	cfg.MaxJobMB = int(uiMaxJob.Value())
	cfg.Bind = uiBind.Text()
	cfg.Dashboard.Enabled = uiDashEnabled.Checked()
	cfg.Notifications = uiNotifications.Checked()

	// Start-on-login is a system-state toggle (registry), not a cfg field, so
	// apply it directly here. A failure is non-fatal: record it as a soft error.
	if err := setRunAtLogin(uiRunAtLogin.Checked()); err != nil {
		jsonErrs = append(jsonErrs, fmt.Sprintf("start-at-login: %v", err))
	}

	cfg.Ports.Raw9100 = rowPort(rowRaw)
	cfg.Ports.LPR = rowPort(rowLPR)
	cfg.Ports.IPP = rowPort(rowIPP)
	cfg.Ports.IPPS = rowPort(rowIPPS)
	cfg.Ports.AutoTLS = rowPort(rowAuto)
	cfg.Ports.SNMP = rowPort(rowSNMP)
	cfg.Ports.Dashboard = rowPort(rowDash)

	cfg.Printer.Name = uiName.Text()
	cfg.Printer.Info = uiInfo.Text()
	cfg.Printer.MakeAndModel = uiModel.Text()
	cfg.Printer.Location = uiLoc.Text()
	cfg.Printer.Serial = uiSerial.Text()
	cfg.Printer.DocumentFormats = splitCSV(uiDocFormats.Text())
	cfg.Printer.DefaultFormat = strings.TrimSpace(uiDefaultFormat.Text())
	cfg.Printer.Sides = splitCSV(uiSides.Text())
	cfg.Printer.Resolutions = parseIntList(uiResolutions.Text())
	cfg.Printer.Media = splitCSV(uiMedia.Text())
	cfg.Printer.Color = uiColor.Checked()
	cfg.Printer.EnforceFormats = uiEnforce.Checked()

	cfg.SNMP.Enabled = uiSnmpEnabled.Checked()
	cfg.SNMP.Community = uiCommunity.Text()
	cfg.SNMP.SysDescr = uiSysDescr.Text()
	cfg.SNMP.SysName = uiSysName.Text()
	cfg.SNMP.SysLocation = uiSysLoc.Text()
	cfg.SNMP.SysContact = uiSysContact.Text()
	cfg.SNMP.SysObjectID = uiSysObj.Text()
	cfg.SNMP.PageCount = int(uiPageCount.Value())
	cfg.SNMP.TonerLevelPct = int(uiToner.Value())
	cfg.SNMP.V3Enabled = uiSnmpV3.Checked()
	cfg.SNMP.AllowV1V2c = uiSnmpAllowV12.Checked()
	cfg.SNMP.EngineID = strings.TrimSpace(uiEngineID.Text())
	applyJSON("SNMP USM users", uiSnmpUsers.Text(), &cfg.SNMP.Users)

	cfg.MDNS.Enabled = uiMdnsEnabled.Checked()
	cfg.MDNS.Instance = strings.TrimSpace(uiMdnsInstance.Text())
	cfg.MDNS.Hostname = strings.TrimSpace(uiMdnsHostname.Text())
	cfg.MDNS.AirPrint = uiMdnsAirPrint.Checked()
	cfg.WSD.Enabled = uiWsdEnabled.Checked()
	cfg.WSD.Port = int(uiWsdPort.Value())
	cfg.WSD.Discovery = uiWsdDiscovery.Checked()

	cfg.SMB.Enabled = uiSmbEnabled.Checked()
	cfg.SMB.Port = int(uiSmbPort.Value())
	cfg.SMB.ShareName = strings.TrimSpace(uiSmbShare.Text())
	cfg.SMB.RequireAuth = uiSmbRequireAuth.Checked()
	cfg.SMB.Sign = uiSmbSign.Checked()
	cfg.SMB.Encrypt = uiSmbEncrypt.Checked()
	applyJSON("SMB users", uiSmbUsers.Text(), &cfg.SMB.Users)

	cfg.EBCDIC.Enabled = uiEbcdicEnabled.Checked()
	cfg.EBCDIC.DefaultCodePage = ebcdicCodePages[clampIndex(uiEbcdicCodePage.CurrentIndex(), len(ebcdicCodePages))]
	cfg.EBCDIC.AutoDetect = uiEbcdicAuto.Checked()
	cfg.EBCDIC.DecodedSidecar = uiEbcdicSidecar.Checked()
	cfg.EBCDIC.CarriageControl = carriageModes[clampIndex(uiEbcdicCarriage.CurrentIndex(), len(carriageModes))]
	applyJSON("LPD queue defaults", uiLpdQueueDefaults.Text(), &cfg.LPD.QueueDefaults)

	cfg.Forward.Enabled = uiFwdEnabled.Checked()
	cfg.Forward.Capture = captureModes[clampIndex(uiFwdCapture.CurrentIndex(), len(captureModes))]
	applyJSON("Forward macros", uiFwdMacros.Text(), &cfg.Forward.Macros)
	applyJSON("Forward targets", uiFwdTargets.Text(), &cfg.Forward.Targets)

	cfg.DLP.Enabled = uiDlpEnabled.Checked()
	applyJSON("DLP rules", uiDlpRules.Text(), &cfg.DLP.Rules)

	cfg.Raw.ParsePJL = uiRawParsePJL.Checked()
	cfg.Raw.SplitOnUEL = uiRawSplitUEL.Checked()
	cfg.Raw.ExtraPorts = parseIntList(uiRawExtraPorts.Text())
	cfg.LPD.AcceptAnyQueue = uiLpdAnyQueue.Checked()
	cfg.LPD.AllowedQueues = splitCSV(uiLpdAllowed.Text())
	cfg.LPD.RequirePrivilegedSourcePort = uiLpdPrivPort.Checked()
	cfg.LPD.ParsePJL = uiLpdParsePJL.Checked()
	cfg.IPPOpts.ResourcePaths = splitCSV(uiIppPaths.Text())
	cfg.IPPOpts.DefaultPath = strings.TrimSpace(uiIppDefaultPath.Text())
	cfg.TLS.CertFile = strings.TrimSpace(uiCertFile.Text())
	cfg.TLS.KeyFile = strings.TrimSpace(uiKeyFile.Text())

	cfg.Log.Level = logLevels[clampIndex(uiLogLevel.CurrentIndex(), len(logLevels))]
	cfg.Log.Format = logFormats[clampIndex(uiLogFormat.CurrentIndex(), len(logFormats))]
	cfg.Log.File = strings.TrimSpace(uiLogFile.Text())
	cfg.Log.JSONFile = strings.TrimSpace(uiLogJSONFile.Text())
	cfg.Log.MaxSizeMB = int(uiLogMaxSize.Value())
	cfg.Log.MaxBackups = int(uiLogMaxBackups.Value())
	cfg.Log.Console = uiLogConsole.Checked()
	cfg.Log.Protocol = uiLogProtocol.Checked()
	cfg.Log.EventLog = uiLogEventLog.Checked()
	cfg.Log.Syslog.Enabled = uiSyslogEnabled.Checked()
	cfg.Log.Syslog.Network = syslogNets[clampIndex(uiSyslogNet.CurrentIndex(), len(syslogNets))]
	cfg.Log.Syslog.Address = strings.TrimSpace(uiSyslogAddr.Text())
	cfg.Log.Syslog.Facility = int(uiSyslogFacility.Value())
	cfg.Log.Syslog.AppName = strings.TrimSpace(uiSyslogApp.Text())
	cfg.Log.Syslog.RFC5424 = uiSyslogRFC5424.Checked()
	applyInterceptUI()
	configureLogging() // re-apply level, format, JSON-lines, and syslog live
	return jsonErrs
}

func indexOf(list []string, v string, def int) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return def
}

func setRow(r protoRow, port int) {
	r.enable.SetChecked(port > 0)
	if port > 0 {
		r.port.SetValue(float64(port))
	} else {
		r.port.SetValue(float64(r.defPort)) // pre-fill default so re-enabling has a value
	}
}

func rowPort(r protoRow) int {
	if !r.enable.Checked() {
		return 0
	}
	return int(r.port.Value())
}

// --- actions ----------------------------------------------------------------

func onBrowse() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select capture directory"
	if ok, err := dlg.ShowBrowseFolder(mw); err == nil && ok && dlg.FilePath != "" {
		uiOut.SetText(dlg.FilePath)
	}
}

// applyAndPersist applies the UI to the live config and writes it to disk,
// bouncing the engine if it is running so cfg is never mutated under live
// handlers. If restart is requested (or the engine was running), the engine is
// (re)started afterward.
// applyValidateAndPersist applies the UI, runs validation, and only persists
// (and optionally restarts) when there are no JSON parse errors and no
// hard validation errors. It returns a slice of human-readable blocking issues;
// an empty slice means the save proceeded. Warnings are returned separately so
// the caller can show them without blocking.
func applyValidateAndPersist(restart bool) (blocking []string, warnings []string, err error) {
	wasRunning := engineRunning()
	if wasRunning {
		if err = engineStop(); err != nil { // synchronous: drains all handlers
			return nil, nil, err
		}
	}

	jsonErrs := applyUIToConfig()
	blocking = append(blocking, jsonErrs...)

	for _, is := range validateConfig(cfg) {
		if is.Severity == sevError {
			blocking = append(blocking, is.String())
		} else {
			warnings = append(warnings, is.String())
		}
	}

	// On any blocking issue, do not persist or restart; restart the engine only
	// if it had been running so we don't leave the service stopped.
	if len(blocking) > 0 {
		if wasRunning {
			if e := engineStart(); e != nil {
				return blocking, warnings, e
			}
		}
		return blocking, warnings, nil
	}

	if err = dumpConfig(configFilePath); err != nil {
		return blocking, warnings, err
	}
	if restart || wasRunning {
		if err = engineStart(); err != nil {
			return blocking, warnings, err
		}
	}
	return blocking, warnings, nil
}

func onSave() { doSave(false) }

func onSaveRestart() { doSave(true) }

// doSave applies the UI, validates, and persists. Blocking issues (JSON parse
// errors or hard validation errors) are shown and the save is aborted so the
// user can fix them; warnings are shown but do not block.
func doSave(restart bool) {
	blocking, warnings, err := applyValidateAndPersist(restart)
	if err != nil {
		walk.MsgBox(mw, "Save failed", err.Error(), walk.MsgBoxIconError)
		updateStatus()
		return
	}
	if len(blocking) > 0 {
		msg := "Configuration was NOT saved. Fix these issues and try again:\n\n" + strings.Join(blocking, "\n")
		if len(warnings) > 0 {
			msg += "\n\nWarnings:\n" + strings.Join(warnings, "\n")
		}
		walk.MsgBox(mw, "Cannot save", msg, walk.MsgBoxIconError)
		updateStatus()
		return
	}
	msg := "Configuration saved to:\n" + configFilePath
	if len(warnings) > 0 {
		msg += "\n\nWarnings:\n" + strings.Join(warnings, "\n")
	}
	walk.MsgBox(mw, "Saved", msg, walk.MsgBoxIconInformation)
	reportBindFailures() // surface any listener that failed to bind on the restart
	updateStatus()
}

func onStartStop() {
	if engineRunning() {
		if err := engineStop(); err != nil {
			walk.MsgBox(mw, "Stop failed", err.Error(), walk.MsgBoxIconError)
		}
	} else {
		applyUIToConfig()
		if err := dumpConfig(configFilePath); err != nil {
			walk.MsgBox(mw, "Save failed", "Could not write the config file before starting:\n"+err.Error(), walk.MsgBoxIconError)
			return
		}
		if err := engineStart(); err != nil {
			walk.MsgBox(mw, "Start failed", err.Error(), walk.MsgBoxIconError)
		} else {
			reportBindFailures()
		}
	}
	updateStatus()
}

func onInstall() {
	applyUIToConfig()
	if err := dumpConfig(configFilePath); err != nil { // the service reads this file
		walk.MsgBox(mw, "Save failed", "Could not write the config file the service will read:\n"+err.Error(), walk.MsgBoxIconError)
		return
	}
	if err := installService(); err != nil {
		walk.MsgBox(mw, "Install failed", err.Error(), walk.MsgBoxIconError)
	} else {
		walk.MsgBox(mw, "Service installed", "printcap will now start automatically at boot.\nUse \"Start Service\" to start it now.", walk.MsgBoxIconInformation)
	}
	updateStatus()
}

func onRemove() {
	if err := removeService(); err != nil {
		walk.MsgBox(mw, "Remove failed", err.Error(), walk.MsgBoxIconError)
	}
	updateStatus()
}

func onSvcStart() {
	if err := startService(); err != nil {
		walk.MsgBox(mw, "Start failed", err.Error(), walk.MsgBoxIconError)
	}
	updateStatus()
}

func onSvcStop() {
	if err := stopService(); err != nil {
		walk.MsgBox(mw, "Stop failed", err.Error(), walk.MsgBoxIconError)
	}
	updateStatus()
}

// --- smart engine control (service if installed, else in-process) -----------

func engineRunning() bool {
	if serviceInstalled() {
		return serviceState() == "running"
	}
	return engine.Running()
}

func engineStart() error {
	if serviceInstalled() {
		return startService()
	}
	_, err := engine.Start()
	return err
}

func engineStop() error {
	if serviceInstalled() {
		return stopService()
	}
	engine.Stop()
	return nil
}

// --- helpers ----------------------------------------------------------------

// reportBindFailures pops a dialog listing any listeners that failed to bind on
// the last in-process engine start, with the actionable guidance the engine
// classified (port in use, privileged port, etc.). No-op when all listeners came
// up, or when running as a Windows service (the SCM owns that process, so there
// are no in-process failures to report here).
func reportBindFailures() {
	if mw == nil || serviceInstalled() {
		return
	}
	f := engine.Failures()
	if len(f) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("Some listeners did not start:\n\n")
	for name, reason := range f {
		fmt.Fprintf(&b, "• %s\n%s\n\n", name, reason)
	}
	walk.MsgBox(mw, "Listener problems", b.String(), walk.MsgBoxIconWarning)
}

func updateStatus() {
	if mw == nil {
		return
	}
	mode := "in-process"
	if serviceInstalled() {
		mode = "Windows service"
	}
	if engineRunning() {
		uiStatus.SetText("● Running  (" + mode + ")")
		uiStartStop.SetText("Stop")
	} else {
		uiStatus.SetText("○ Stopped  (" + mode + ")")
		uiStartStop.SetText("Start")
	}
	uiSvcStatus.SetText("Service: " + serviceState())
}

func statusTicker() {
	for range time.Tick(3 * time.Second) {
		if mw == nil {
			return
		}
		mw.Synchronize(updateStatus)
	}
}

func showMain() {
	if mw == nil {
		return
	}
	mw.Show()
	mw.SetVisible(true)
}

func openDashboard() {
	host := cfg.Bind
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = "localhost"
	}
	url := fmt.Sprintf("http://%s:%d/", host, cfg.Ports.Dashboard)
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

func openFolder() {
	// Use captureDir() so the tray "open captures folder" opens the SAME
	// (exe-relative) directory the engine actually writes to, even when the
	// process cwd differs from the exe dir (e.g. running as a service).
	_ = exec.Command("explorer", captureDir()).Start()
}

func addTrayAction(text string, fn func()) {
	a := walk.NewAction()
	_ = a.SetText(text)
	a.Triggered().Attach(fn)
	_ = notifyIcon.ContextMenu().Actions().Add(a)
}

func browseFile(target *walk.LineEdit) {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select file"
	dlg.Filter = "PEM/cert files (*.pem;*.crt;*.cer;*.key)|*.pem;*.crt;*.cer;*.key|All files (*.*)|*.*"
	if ok, err := dlg.ShowOpen(mw); err == nil && ok && dlg.FilePath != "" {
		target.SetText(dlg.FilePath)
	}
}

func onGenerateCert() {
	dir := strings.TrimSpace(uiOut.Text())
	if dir == "" {
		dir = captureDir()
	}
	absdir, err := filepath.Abs(dir)
	if err != nil {
		absdir = dir
	}
	_ = os.MkdirAll(absdir, 0o755)
	certPath := filepath.Join(absdir, "printcap-cert.pem")
	keyPath := filepath.Join(absdir, "printcap-key.pem")
	if err := writeSelfSignedCertFiles(certPath, keyPath); err != nil {
		walk.MsgBox(mw, "Generate failed", err.Error(), walk.MsgBoxIconError)
		return
	}
	uiCertFile.SetText(certPath)
	uiKeyFile.SetText(keyPath)
	walk.MsgBox(mw, "Certificate generated",
		"Self-signed certificate written:\n"+certPath+"\n"+keyPath+"\n\nClick Save Settings to use it for IPPS.",
		walk.MsgBoxIconInformation)
}

func onFirewallAdd() {
	n, err := addFirewallRules()
	if err != nil {
		walk.MsgBox(mw, "Firewall", "Failed (run printcap as Administrator?):\n\n"+err.Error(), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(mw, "Firewall", fmt.Sprintf("Added %d inbound port rule(s) for printcap.", n), walk.MsgBoxIconInformation)
}

func onFirewallRemove() {
	_ = removeFirewallRules()
	walk.MsgBox(mw, "Firewall", "printcap firewall rules removed.", walk.MsgBoxIconInformation)
}

func browseSaveFile(target *walk.LineEdit) {
	dlg := new(walk.FileDialog)
	dlg.Title = "Log file"
	dlg.Filter = "Log files (*.log)|*.log|All files (*.*)|*.*"
	if ok, err := dlg.ShowSave(mw); err == nil && ok && dlg.FilePath != "" {
		target.SetText(dlg.FilePath)
	}
}

func openLogFile() {
	p := strings.TrimSpace(uiLogFile.Text())
	if p == "" {
		p = defaultLogPath()
	}
	_ = exec.Command("cmd", "/c", "start", "", p).Start()
}

func levelIndex(name string) int {
	for i, n := range logLevels {
		if n == name {
			return i
		}
	}
	return 2 // info
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseIntList(s string) []int {
	var out []int
	for _, p := range splitCSV(s) {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	return out
}

func joinIntList(xs []int) string {
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, strconv.Itoa(x))
	}
	return strings.Join(parts, ", ")
}

func saveIndex(mode string) int {
	for i, m := range saveModes {
		if m == mode {
			return i
		}
	}
	return 0
}

func clampIndex(i, n int) int {
	if i < 0 || i >= n {
		return 0
	}
	return i
}
