package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// atoiDefault parses s as an int, returning def on failure.
func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

// saveMode controls what the capture sink persists per job.
type saveMode int

const (
	saveBoth saveMode = iota // raw spool file + .json metadata sidecar
	saveRaw                  // raw spool bytes only
	saveMeta                 // metadata only, document bytes discarded
)

// Config is the complete, JSON-serializable configuration for printcap. Every
// listener and behavior is driven from here. Defaults come from
// defaultConfig(); a -config file overlays onto them; explicit flags override
// last. Use -dump-config to write the effective config as a template to edit.
type Config struct {
	Bind      string      `json:"bind"`       // interface to bind all listeners to
	Ports     Ports       `json:"ports"`      // 0 disables a given listener
	Save      string      `json:"save"`       // both | raw | meta
	OutDir    string      `json:"out_dir"`    // capture output directory
	MaxJobMB  int         `json:"max_job_mb"` // per-job byte cap (0 = unlimited)
	TLS       TLSConf     `json:"tls"`
	Raw       RawOpts     `json:"raw"`
	LPD       LPDOpts     `json:"lpd"`
	IPPOpts   IPPOpts     `json:"ipp_options"`
	Printer   Printer     `json:"printer"`
	SNMP      SNMPConf    `json:"snmp"`
	Dashboard DashConf    `json:"dashboard"`
	MDNS      MDNSConf    `json:"mdns"`
	Log       LogConf     `json:"log"`
	Forward   ForwardConf `json:"forward"`
	EBCDIC    EBCDICConf  `json:"ebcdic"`
	SMB       SMBConf     `json:"smb"`
	WSD       WSDConf     `json:"wsd"`
	Storage   StorageConf `json:"storage"`
	DLP       DLPConf     `json:"dlp"`
	Service   ServiceConf `json:"service"`
}

// ServiceConf configures the installed Windows service. Blank Account = the
// default LocalSystem account.
type ServiceConf struct {
	Account  string `json:"account"`  // e.g. ".\\svc_printcap" or "DOMAIN\\user"; blank = LocalSystem
	Password string `json:"password"` // password for Account (if required)
}

// DLPConf scans captured documents for sensitive content and raises an alert
// (logged + tagged on the job). Inspection only — it never blocks capture.
type DLPConf struct {
	Enabled bool      `json:"enabled"`
	Rules   []DLPRule `json:"rules"`
}

// DLPRule matches captured content. Mode: "keyword" (case-insensitive substring)
// or "regex" (RE2). Name labels the match on the job and in the alert log.
type DLPRule struct {
	Name    string `json:"name"`
	Mode    string `json:"mode"` // keyword | regex
	Pattern string `json:"pattern"`
}

// EBCDICConf controls decoding of EBCDIC (mainframe) print streams into a
// readable sidecar, including code-page selection and carriage-control handling.
type EBCDICConf struct {
	Enabled         bool   `json:"enabled"`
	DefaultCodePage string `json:"default_code_page"` // e.g. "CP037"
	AutoDetect      bool   `json:"auto_detect"`
	DecodedSidecar  bool   `json:"decoded_sidecar"`
	CarriageControl string `json:"carriage_control"` // none|asa|machine|auto
}

// QueueDefault overrides EBCDIC/code-page/carriage-control settings for LPD
// queues whose name matches a glob key in LPDOpts.QueueDefaults.
type QueueDefault struct {
	CodePage        string `json:"code_page"`
	CarriageControl string `json:"carriage_control"`
	EBCDIC          bool   `json:"ebcdic"`
}

type ForwardConf struct {
	Enabled bool              `json:"enabled"`
	Capture string            `json:"capture"` // both | sent | orig
	Macros  map[string]string `json:"macros"`
	Targets []ForwardTarget   `json:"targets"`
}

type ForwardTarget struct {
	Name                 string          `json:"name"`
	Transport            string          `json:"transport"` // raw | lpr | ipp | ipps
	Address              string          `json:"address"`
	TimeoutMS            int             `json:"timeout_ms"`
	Queue                string          `json:"queue"`
	PrivilegedSourcePort bool            `json:"privileged_source_port"`
	TLSSkipVerify        bool            `json:"tls_skip_verify"`
	DocumentFormat       string          `json:"document_format"`
	When                 ForwardCond     `json:"when"`
	Failure              string          `json:"failure"` // best_effort | spool_retry | block
	Retry                ForwardRetry    `json:"retry"`
	Transforms           []TransformStep `json:"transforms"`
}

type TransformStep struct {
	Type  string      `json:"type"` // replace | inject_prefix | inject_suffix
	Mode  string      `json:"mode"` // replace: literal | regex | hex
	Match string      `json:"match"`
	With  string      `json:"with"`
	All   bool        `json:"all"`
	Data  string      `json:"data"` // inject_*: \xNN-escaped, supports macro:NAME
	When  ForwardCond `json:"when"`
}

// LogConf configures the logging subsystem.
type LogConf struct {
	Level      string     `json:"level"`       // error | warn | info | debug | trace
	File       string     `json:"file"`        // path; empty = printcap.log next to the exe
	Format     string     `json:"format"`      // text (default) | json — primary file/console rendering
	JSONFile   string     `json:"json_file"`   // optional separate JSON-lines file (SIEM shippers)
	MaxSizeMB  int        `json:"max_size_mb"` // rotate the file at this size (default 10)
	MaxBackups int        `json:"max_backups"` // rotated files to keep (default 5)
	Console    bool       `json:"console"`     // also write to the console
	Protocol   bool       `json:"protocol"`    // promote per-connection protocol detail to INFO
	EventLog   bool       `json:"event_log"`   // also write to the Windows Event Log (service)
	Syslog     SyslogConf `json:"syslog"`      // ship to a remote syslog server
}

// SyslogConf ships log records to a remote syslog collector (rsyslog, Graylog,
// Splunk, etc.).
type SyslogConf struct {
	Enabled  bool   `json:"enabled"`
	Network  string `json:"network"`  // udp | tcp
	Address  string `json:"address"`  // host:port, e.g. siem.example.com:514
	Facility int    `json:"facility"` // 0-23; 16 = local0 (default)
	RFC5424  bool   `json:"rfc5424"`  // true = RFC 5424; false = RFC 3164 (BSD)
	AppName  string `json:"app_name"` // syslog APP-NAME / tag (default "printcap")
}

// RawOpts configures the Raw/JetDirect/AppSocket listener.
type RawOpts struct {
	ExtraPorts []int `json:"extra_ports"`  // additional raw ports (multi-port servers, e.g. 9101, 9102)
	ParsePJL   bool  `json:"parse_pjl"`    // extract job name/user from a PJL preamble
	SplitOnUEL bool  `json:"split_on_uel"` // split multiple jobs on one connection at UEL boundaries
}

// LPDOpts configures the LPR/LPD listener for broad enterprise compatibility
// (SAP access-method U, IBM AS/400 RMTOUTQ, z/OS, Linux/CUPS, etc.).
type LPDOpts struct {
	AcceptAnyQueue              bool     `json:"accept_any_queue"`               // accept any queue name (default true)
	AllowedQueues               []string `json:"allowed_queues"`                 // if accept_any_queue is false, only these
	RequirePrivilegedSourcePort bool     `json:"require_privileged_source_port"` // RFC1179 721-731; default false (permissive)
	ParsePJL                    bool     `json:"parse_pjl"`                      // also parse PJL from the data file

	QueueDefaults map[string]QueueDefault `json:"queue_defaults"` // per-queue (glob) code page / carriage / ebcdic overrides
}

// IPPOpts configures IPP/IPPS resource paths.
type IPPOpts struct {
	ResourcePaths []string `json:"resource_paths"` // advertised printer-uri paths
	DefaultPath   string   `json:"default_path"`   // primary path in printer-uri-supported
}

type Ports struct {
	Raw9100   int `json:"raw9100"`
	LPR       int `json:"lpr"`
	IPP       int `json:"ipp"`
	IPPS      int `json:"ipps"`
	AutoTLS   int `json:"auto_tls"` // single port: auto-detect TLS vs plaintext IPP
	Dashboard int `json:"dashboard"`
	SNMP      int `json:"snmp"`
}

type TLSConf struct {
	CertFile string `json:"cert_file"` // empty = generate self-signed in memory
	KeyFile  string `json:"key_file"`
}

// Printer holds the identity and capabilities advertised over IPP (and used in
// SNMP descriptions). Tune these to impersonate a particular device.
type Printer struct {
	Name            string   `json:"name"`
	Info            string   `json:"info"`
	MakeAndModel    string   `json:"make_and_model"`
	Location        string   `json:"location"`
	Serial          string   `json:"serial"`
	DocumentFormats []string `json:"document_formats"` // MIME types advertised/accepted
	DefaultFormat   string   `json:"default_format"`
	EnforceFormats  bool     `json:"enforce_formats"` // reject IPP jobs with other formats
	Color           bool     `json:"color"`
	Sides           []string `json:"sides"`       // e.g. one-sided, two-sided-long-edge
	Resolutions     []int    `json:"resolutions"` // dpi, e.g. 300, 600
	Media           []string `json:"media"`       // e.g. iso_a4_210x297mm
}

// SNMPConf drives the built-in SNMP v1/v2c agent that makes the tool
// discoverable to fleet scanners as a printer.
type SNMPConf struct {
	Enabled       bool   `json:"enabled"`
	Community     string `json:"community"`
	SysDescr      string `json:"sys_descr"`
	SysName       string `json:"sys_name"`
	SysLocation   string `json:"sys_location"`
	SysContact    string `json:"sys_contact"`
	SysObjectID   string `json:"sys_object_id"` // dotted OID, vendor identity
	PageCount     int    `json:"page_count"`
	TonerLevelPct int    `json:"toner_level_pct"`

	V3Enabled  bool       `json:"v3_enabled"`
	AllowV1V2c bool       `json:"allow_v1v2c"`
	EngineID   string     `json:"engine_id"`
	Users      []SNMPUser `json:"users"`
}

// SNMPUser is a single SNMPv3 USM user definition.
type SNMPUser struct {
	Name         string `json:"name"`
	Level        string `json:"level"`         // noAuthNoPriv | authNoPriv | authPriv
	AuthProtocol string `json:"auth_protocol"` // MD5 | SHA-1 | SHA-256 | SHA-512
	AuthPass     string `json:"auth_pass"`
	PrivProtocol string `json:"priv_protocol"` // DES | AES-128 | AES-192 | AES-256
	PrivPass     string `json:"priv_pass"`
}

type DashConf struct {
	Enabled bool `json:"enabled"`
}

// MDNSConf drives the built-in mDNS/DNS-SD (Bonjour) responder that makes
// printcap auto-discoverable as a driverless printer.
type MDNSConf struct {
	Enabled  bool   `json:"enabled"`
	Instance string `json:"instance"` // blank = printer.name
	Hostname string `json:"hostname"` // blank = sanitized printer.name
	AirPrint bool   `json:"airprint"`
}

// WSDConf drives the experimental WSD (Web Services for Devices) print service
// that makes printcap discoverable/installable by Windows "Add a device".
type WSDConf struct {
	Enabled   bool `json:"enabled"`
	Port      int  `json:"port"`
	Discovery bool `json:"discovery"` // run the WS-Discovery multicast responder
}

// StorageConf configures where printcap writes generated files. Relative paths
// resolve relative to the executable's directory so the app is portable; absolute
// paths are used as-is. Nothing here is ever auto-deleted at shutdown.
type StorageConf struct {
	SpoolDir string `json:"spool_dir"` // forward retry queue + temp working files; blank = "<exe-dir>/spool"
}

// SMBUser is a credential the SMB share accepts (NTLMv2).
type SMBUser struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
}

// SMBConf drives the experimental SMB2/3 print-share capture listener. Default
// off; runs on a configurable non-445 port.
type SMBConf struct {
	Enabled     bool      `json:"enabled"`
	Port        int       `json:"port"`
	ShareName   string    `json:"share_name"`
	RequireAuth bool      `json:"require_auth"`
	Sign        bool      `json:"sign"`
	Encrypt     bool      `json:"encrypt"`
	Users       []SMBUser `json:"users"`
}

func (c *Config) mode() saveMode {
	switch strings.ToLower(c.Save) {
	case "raw":
		return saveRaw
	case "meta", "metadata":
		return saveMeta
	default:
		return saveBoth
	}
}

// defaultConfig returns a sensible, fully-populated configuration: a generic
// driverless-capable mono printer listening on all standard print ports plus
// dashboard and SNMP.
func defaultConfig() *Config {
	return &Config{
		Bind: "0.0.0.0",
		Ports: Ports{
			Raw9100:   9100,
			LPR:       515,
			IPP:       631,
			IPPS:      6310,
			AutoTLS:   0,
			Dashboard: 8631,
			SNMP:      161,
		},
		Save:     "both",
		OutDir:   "captures",
		MaxJobMB: 0,
		Raw: RawOpts{
			ExtraPorts: []int{},
			ParsePJL:   true,
			SplitOnUEL: false,
		},
		LPD: LPDOpts{
			AcceptAnyQueue:              true,
			AllowedQueues:               []string{},
			RequirePrivilegedSourcePort: false,
			ParsePJL:                    true,
			QueueDefaults:               map[string]QueueDefault{},
		},
		IPPOpts: IPPOpts{
			ResourcePaths: []string{"/ipp/print", "/ipp", "/printers/printcap", "/printer"},
			DefaultPath:   "/ipp/print",
		},
		Printer: Printer{
			Name:         "printcap",
			Info:         "printcap capture printer",
			MakeAndModel: "printcap Virtual MFP",
			Location:     "lab",
			Serial:       "PC-0000-0001",
			DocumentFormats: []string{
				"application/octet-stream", "application/pdf", "application/postscript",
				"application/vnd.hp-PCL", "application/vnd.hp-PCLXL", "image/pwg-raster",
				"image/urf", "image/jpeg", "image/tiff", "application/PCLm",
				"application/vnd.ms-xpsdocument", "text/plain",
			},
			DefaultFormat:  "application/octet-stream",
			EnforceFormats: false,
			Color:          true,
			Sides:          []string{"one-sided", "two-sided-long-edge", "two-sided-short-edge"},
			Resolutions:    []int{300, 600},
			Media:          []string{"iso_a4_210x297mm", "na_letter_8.5x11in", "iso_a3_297x420mm"},
		},
		SNMP: SNMPConf{
			Enabled:       true,
			Community:     "public",
			SysDescr:      "printcap Virtual MFP; SNMP capture agent",
			SysName:       "printcap",
			SysLocation:   "lab",
			SysContact:    "admin",
			SysObjectID:   "1.3.6.1.4.1.11.2.3.9.1", // generic; override per vendor
			PageCount:     0,
			TonerLevelPct: 100,
			V3Enabled:     false,
			AllowV1V2c:    true,
			Users:         []SNMPUser{},
		},
		Dashboard: DashConf{Enabled: true},
		MDNS: MDNSConf{
			Enabled:  true,
			Instance: "",
			Hostname: "",
			AirPrint: true,
		},
		EBCDIC: EBCDICConf{
			Enabled:         true,
			DefaultCodePage: "CP037",
			AutoDetect:      true,
			DecodedSidecar:  true,
			CarriageControl: "auto",
		},
		SMB: SMBConf{
			Enabled:     false,
			Port:        4445,
			ShareName:   "PRINTER",
			RequireAuth: false,
			Sign:        true,
			Encrypt:     true,
			Users:       []SMBUser{},
		},
		WSD: WSDConf{
			Enabled:   false,
			Port:      3911,
			Discovery: true,
		},
		Storage: StorageConf{SpoolDir: ""}, // empty = <exe-dir>/spool
		Service: ServiceConf{},
		DLP: DLPConf{
			Enabled: false,
			Rules:   []DLPRule{},
		},
		Forward: ForwardConf{
			Enabled: false,
			Capture: "both",
			Macros:  map[string]string{},
			Targets: []ForwardTarget{},
		},
		Log: LogConf{
			Level:      "info",
			File:       "",
			Format:     "text",
			JSONFile:   "",
			MaxSizeMB:  10,
			MaxBackups: 5,
			Console:    true,
			Protocol:   false,
			EventLog:   true,
			Syslog: SyslogConf{
				Enabled:  false,
				Network:  "udp",
				Address:  "",
				Facility: 16, // local0
				RFC5424:  false,
				AppName:  "printcap",
			},
		},
	}
}

// loadConfig overlays a JSON config file onto the current cfg. Only keys
// present in the file are changed; everything else keeps its default.
func loadConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, cfg)
}

// dumpConfig writes the effective config as pretty JSON to path (or stdout when
// path is "-").
func dumpConfig(path string) error {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	b = append(b, '\n')
	if path == "-" || path == "" {
		_, err := os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
