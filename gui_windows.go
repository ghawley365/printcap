//go:build windows

package main

import (
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

// The GUI is a single settings window that minimizes to the system tray. It
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
	reallyExit bool

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

	helpWin *walk.MainWindow
)

var saveModes = []string{"both", "raw", "meta"}
var logLevels = []string{"error", "warn", "info", "debug", "trace"}
var logFormats = []string{"text", "json"}
var syslogNets = []string{"udp", "tcp"}

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
		if icon, err := walk.NewIconFromSysDLL("imageres", 109); err == nil {
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
		addTrayAction("Exit", func() { reallyExit = true; mw.Close() })
	}

	// Minimize/close to tray instead of exiting.
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if !reallyExit {
			*canceled = true
			mw.Hide()
			if notifyIcon != nil {
				_ = notifyIcon.SetVisible(true)
			}
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

			dec.Label{Text: "Save mode:"},
			dec.ComboBox{AssignTo: &uiSave, Model: saveModes},
			dec.HSpacer{},

			dec.Label{Text: "Max job size (MB, 0 = unlimited):"},
			dec.NumberEdit{AssignTo: &uiMaxJob, MinValue: 0, MaxValue: 100000, Decimals: 0},
			dec.HSpacer{},

			dec.Label{Text: "Bind address:"},
			dec.LineEdit{AssignTo: &uiBind},
			dec.Label{Text: "(0.0.0.0 = all interfaces; 127.0.0.1 = local only)"},
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
			dec.Label{Text: "Make and model:"}, dec.LineEdit{AssignTo: &uiModel},
			dec.Label{Text: "Location:"}, dec.LineEdit{AssignTo: &uiLoc},
			dec.Label{Text: "Serial number:"}, dec.LineEdit{AssignTo: &uiSerial},
			dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiColor, Text: "Advertise color support"},
			dec.Label{Text: ""}, dec.CheckBox{AssignTo: &uiEnforce, Text: "Reject IPP jobs with unsupported document formats"},
		},
	}
}

func snmpTab() dec.TabPage {
	return dec.TabPage{
		Title:  "SNMP",
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
	uiSave.SetCurrentIndex(saveIndex(cfg.Save))
	uiMaxJob.SetValue(float64(cfg.MaxJobMB))
	uiBind.SetText(cfg.Bind)

	setRow(rowRaw, cfg.Ports.Raw9100)
	setRow(rowLPR, cfg.Ports.LPR)
	setRow(rowIPP, cfg.Ports.IPP)
	setRow(rowIPPS, cfg.Ports.IPPS)
	setRow(rowAuto, cfg.Ports.AutoTLS)
	setRow(rowSNMP, cfg.Ports.SNMP)
	setRow(rowDash, cfg.Ports.Dashboard)

	uiName.SetText(cfg.Printer.Name)
	uiModel.SetText(cfg.Printer.MakeAndModel)
	uiLoc.SetText(cfg.Printer.Location)
	uiSerial.SetText(cfg.Printer.Serial)
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
}

func applyUIToConfig() {
	cfg.OutDir = uiOut.Text()
	cfg.Save = saveModes[clampIndex(uiSave.CurrentIndex(), len(saveModes))]
	cfg.MaxJobMB = int(uiMaxJob.Value())
	cfg.Bind = uiBind.Text()

	cfg.Ports.Raw9100 = rowPort(rowRaw)
	cfg.Ports.LPR = rowPort(rowLPR)
	cfg.Ports.IPP = rowPort(rowIPP)
	cfg.Ports.IPPS = rowPort(rowIPPS)
	cfg.Ports.AutoTLS = rowPort(rowAuto)
	cfg.Ports.SNMP = rowPort(rowSNMP)
	cfg.Ports.Dashboard = rowPort(rowDash)

	cfg.Printer.Name = uiName.Text()
	cfg.Printer.MakeAndModel = uiModel.Text()
	cfg.Printer.Location = uiLoc.Text()
	cfg.Printer.Serial = uiSerial.Text()
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
	configureLogging() // re-apply level, format, JSON-lines, and syslog live
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

func onSave() {
	applyUIToConfig()
	if err := dumpConfig(configFilePath); err != nil {
		walk.MsgBox(mw, "Save failed", err.Error(), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(mw, "Saved", "Configuration saved to:\n"+configFilePath, walk.MsgBoxIconInformation)
	updateStatus()
}

func onSaveRestart() {
	applyUIToConfig()
	if err := dumpConfig(configFilePath); err != nil {
		walk.MsgBox(mw, "Save failed", err.Error(), walk.MsgBoxIconError)
		return
	}
	if err := engineStop(); err != nil {
		walk.MsgBox(mw, "Stop failed", err.Error(), walk.MsgBoxIconError)
	}
	time.Sleep(300 * time.Millisecond)
	if err := engineStart(); err != nil {
		walk.MsgBox(mw, "Start failed", err.Error(), walk.MsgBoxIconError)
	}
	updateStatus()
}

func onStartStop() {
	if engineRunning() {
		if err := engineStop(); err != nil {
			walk.MsgBox(mw, "Stop failed", err.Error(), walk.MsgBoxIconError)
		}
	} else {
		applyUIToConfig()
		_ = dumpConfig(configFilePath)
		if err := engineStart(); err != nil {
			walk.MsgBox(mw, "Start failed", err.Error(), walk.MsgBoxIconError)
		}
	}
	updateStatus()
}

func onInstall() {
	applyUIToConfig()
	_ = dumpConfig(configFilePath) // ensure the service has a config to read
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
	dir, err := filepath.Abs(cfg.OutDir)
	if err != nil {
		dir = cfg.OutDir
	}
	_ = exec.Command("explorer", dir).Start()
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
		dir = cfg.OutDir
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
	if err := addFirewallRules(); err != nil {
		walk.MsgBox(mw, "Firewall", "Failed (run printcap as Administrator?):\n\n"+err.Error(), walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(mw, "Firewall", "Inbound allow rules added for printcap.", walk.MsgBoxIconInformation)
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
