// printcap — a self-contained, configurable network print server / capture tool.
//
// It impersonates a network printer across the common print transports so any
// host can send it a job and have the raw spool data captured to disk, while
// also being discoverable (SNMP) and observable (web dashboard):
//
//   - Raw / JetDirect / AppSocket  (TCP 9100)   — straight byte stream
//   - LPR / LPD                    (TCP 515)    — RFC 1179 line protocol
//   - IPP                          (TCP 631)    — IPP-over-HTTP (configurable attrs)
//   - IPPS                         (TCP 6310)   — IPP-over-HTTPS (TLS)
//   - SNMP v1/v2c agent            (UDP 161)    — printer discovery (RFC 1213/2790/3805)
//   - Web dashboard                (TCP 8631)   — live jobs, stats, config
//
// On Windows it launches a native settings GUI by default, can install itself
// as a Windows service, or run headless in a console with -console. On other
// platforms it always runs in the console.
//
// Build a single static .exe with:
//
//	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o printcap.exe
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
)

// job is one captured print job plus the metadata we could glean about it.
type job struct {
	ID        int    `json:"id"`
	Protocol  string `json:"protocol"`
	Source    string `json:"source"` // remote ip:port
	Received  string `json:"received"`
	JobName   string `json:"job_name,omitempty"`
	User      string `json:"user,omitempty"`
	Host      string `json:"host,omitempty"`
	Queue     string `json:"queue,omitempty"`           // LPD queue / IPP resource path
	DocFormat string `json:"document_format,omitempty"` // advertised MIME type (IPP)
	PDL       string `json:"pdl,omitempty"`             // detected page-description language
	Class     string `json:"class,omitempty"`
	Title     string `json:"title,omitempty"`
	CodePage  string `json:"code_page,omitempty"`
	DecodedAs string `json:"decoded_as,omitempty"`
	Bytes     int    `json:"bytes"`
	SavedAs   string `json:"saved_as,omitempty"`
	data      []byte // not serialized; written to the raw file instead

	Forwards     []forwardResult `json:"forwards,omitempty"`
	captureBase  string          // set by sink.save (Task 8); base name for -sent files
	captureExt   string          // set by sink.save (Task 8); chosen extension
	carriageHint string          // control-file carriage-control hint ("asa" or "")
}

var (
	cfg    *Config
	sink   *captureSink
	store  *jobStore
	seqNum int64

	// Resolved launch options, set in main() and read by the platform dispatch.
	configFilePath string
	optServiceCmd  string
	optFirewall    string
	optConsole     bool
	optVerbose     int    // -v = debug (1), -vv = trace (2)
	optLogLevel    string // -loglevel explicit override
)

func main() {
	configPath := flag.String("config", "", "path to a JSON config file to load (default: printcap.json next to the exe)")
	dumpPath := flag.String("dump-config", "", "write effective config to this path ('-' for stdout) and exit")
	svcCmd := flag.String("service", "", "Windows service control: install | remove | start | stop | status")
	fwCmd := flag.String("firewall", "", "Windows firewall: add | remove inbound allow rules for this exe")
	console := flag.Bool("console", false, "run headless in the console instead of launching the GUI")
	verbose := flag.Bool("v", false, "verbose: debug-level logging")
	vverbose := flag.Bool("vv", false, "very verbose: trace-level logging (per-connection, per-OID)")
	logLevel := flag.String("loglevel", "", "log level: error | warn | info | debug | trace")
	logFile := flag.String("logfile", "", "log file path (default printcap.log next to the exe)")
	flag.String("bind", "", "interface address to bind listeners to")
	flag.Int("raw", 0, "raw/JetDirect TCP port (0 disables)")
	flag.Int("lpr", 0, "LPR/LPD TCP port (0 disables)")
	flag.Int("ipp", 0, "IPP (HTTP) TCP port (0 disables)")
	flag.Int("ipps", 0, "IPPS (TLS) TCP port (0 disables)")
	flag.Int("auto-tls", 0, "single port that auto-detects TLS vs plaintext IPP")
	flag.Int("dash", 0, "web dashboard TCP port (0 disables)")
	flag.Int("snmp", 0, "SNMP agent UDP port (0 disables)")
	flag.String("out", "", "capture output directory")
	flag.String("save", "", "what to keep per job: both | raw | meta")
	flag.String("cert", "", "TLS certificate PEM (self-signed if empty)")
	flag.String("key", "", "TLS private key PEM (self-signed if empty)")
	flag.String("community", "", "SNMP community string")
	flag.String("model", "", "printer make-and-model advertised over IPP/SNMP")
	flag.Bool("forward", false, "enable the transform & forward proxy")
	flag.Bool("mdns", true, "advertise the printer over mDNS/DNS-SD (Bonjour)")
	flag.Bool("smb", false, "enable the experimental SMB print share")
	flag.Bool("wsd", false, "enable the experimental WSD print service")
	flag.Parse()

	// Resolve the config file path (explicit flag, else next to the exe).
	configFilePath = *configPath
	if configFilePath == "" {
		configFilePath = defaultConfigPath()
	}

	cfg = defaultConfig()
	if err := loadConfig(configFilePath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("cannot load config %q: %v", configFilePath, err)
	}
	applyFlagOverrides()

	optServiceCmd = *svcCmd
	optFirewall = *fwCmd
	optConsole = *console
	optLogLevel = *logLevel
	if *vverbose {
		optVerbose = 2
	} else if *verbose {
		optVerbose = 1
	}
	if *logFile != "" {
		cfg.Log.File = *logFile
	}

	if *dumpPath != "" {
		if err := dumpConfig(*dumpPath); err != nil {
			log.Fatalf("dump-config failed: %v", err)
		}
		return
	}

	// Bring up logging before anything else writes a line; route the standard
	// library logger into our sinks so nothing is lost.
	configureLogging()
	log.SetFlags(0)
	log.SetOutput(stdLogWriter{})
	logInfo("app", "printcap starting (config %q, level %s)", configFilePath, logger.Level())
	dispatch() // platform-specific: GUI/service on Windows, console elsewhere
}

// runConsole starts the engine and runs until interrupted (Ctrl+C). Used on
// non-Windows platforms and on Windows with -console.
func runConsole() {
	n, err := engine.Start()
	if err != nil {
		log.Fatalf("failed to start: %v", err)
	}
	printBanner(n)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Println("\nstopping…")
	engine.Stop()
}

func printBanner(n int) {
	abs := captureDir()
	fmt.Println("printcap — network print server & spool capture")
	fmt.Printf("  printer    : %q (%s)\n", cfg.Printer.Name, cfg.Printer.MakeAndModel)
	fmt.Printf("  output dir : %s  (mode=%s)\n", abs, cfg.Save)
	for _, a := range engine.Active() {
		fmt.Printf("  listen     : %-14s on %s\n", a, cfg.Bind)
	}
	if cfg.Dashboard.Enabled && cfg.Ports.Dashboard > 0 {
		fmt.Printf("  dashboard  : http://%s:%d/\n", dashHost(), cfg.Ports.Dashboard)
	}
	if n == 0 {
		fmt.Println("  WARNING: no listeners started (check ports/permissions)")
	}
	fmt.Println("  (Ctrl+C to stop)")
}

// defaultConfigPath returns printcap.json next to the executable, falling back
// to the working directory.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "printcap.json"
	}
	return filepath.Join(filepath.Dir(exe), "printcap.json")
}

// applyFlagOverrides copies any explicitly-set flags over the loaded config.
func applyFlagOverrides() {
	flag.Visit(func(f *flag.Flag) {
		get := func() string { return f.Value.String() }
		switch f.Name {
		case "bind":
			cfg.Bind = get()
		case "raw":
			cfg.Ports.Raw9100 = atoiDefault(get(), cfg.Ports.Raw9100)
		case "lpr":
			cfg.Ports.LPR = atoiDefault(get(), cfg.Ports.LPR)
		case "ipp":
			cfg.Ports.IPP = atoiDefault(get(), cfg.Ports.IPP)
		case "ipps":
			cfg.Ports.IPPS = atoiDefault(get(), cfg.Ports.IPPS)
		case "auto-tls":
			cfg.Ports.AutoTLS = atoiDefault(get(), cfg.Ports.AutoTLS)
		case "dash":
			cfg.Ports.Dashboard = atoiDefault(get(), cfg.Ports.Dashboard)
		case "snmp":
			cfg.Ports.SNMP = atoiDefault(get(), cfg.Ports.SNMP)
		case "out":
			cfg.OutDir = get()
		case "save":
			cfg.Save = get()
		case "cert":
			cfg.TLS.CertFile = get()
		case "key":
			cfg.TLS.KeyFile = get()
		case "community":
			cfg.SNMP.Community = get()
		case "model":
			cfg.Printer.MakeAndModel = get()
		case "forward":
			cfg.Forward.Enabled = get() == "true"
		case "mdns":
			cfg.MDNS.Enabled = get() == "true"
		case "smb":
			cfg.SMB.Enabled = true
		case "wsd":
			cfg.WSD.Enabled = true
		}
	})
}

// nextSeq returns a monotonically increasing per-run sequence number used as a
// job ID and to keep capture filenames unique and ordered.
func nextSeq() int { return int(atomic.AddInt64(&seqNum, 1)) }
