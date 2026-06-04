package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// validationSeverity classifies a configIssue as a hard error or a warning.
type validationSeverity string

const (
	sevError   validationSeverity = "error"
	sevWarning validationSeverity = "warning"
)

// configIssue is one validation finding with an actionable recommendation.
type configIssue struct {
	Severity validationSeverity
	Field    string // e.g. "ports.ipp"
	Message  string // what's wrong
	Fix      string // recommended fix
}

func (i configIssue) String() string {
	return fmt.Sprintf("[%s] %s: %s — fix: %s", i.Severity, i.Field, i.Message, i.Fix)
}

// hasErrors reports whether any issue is an error (vs warning).
func hasErrors(issues []configIssue) bool {
	for _, is := range issues {
		if is.Severity == sevError {
			return true
		}
	}
	return false
}

// validateConfig checks c for problems and returns issues (errors + warnings).
// It performs read-only checks plus a best-effort writability probe of the
// storage directories. It never mutates c.
func validateConfig(c *Config) []configIssue {
	var issues []configIssue
	issues = append(issues, validatePorts(c)...)
	issues = append(issues, validateEnums(c)...)
	issues = append(issues, validateTLS(c)...)
	issues = append(issues, validateForward(c)...)
	issues = append(issues, validateSyslog(c)...)
	issues = append(issues, validateStorage(c)...)
	issues = append(issues, validateBind(c)...)
	return issues
}

// portEntry pairs a listener's human-readable name with its configured port.
type portEntry struct {
	field string
	port  int
}

// validatePorts checks port ranges, privileged ports, and duplicate listeners.
func validatePorts(c *Config) []configIssue {
	var issues []configIssue

	// Every individually-named port field, for range + privileged checks.
	all := []portEntry{
		{"ports.raw9100", c.Ports.Raw9100},
		{"ports.lpr", c.Ports.LPR},
		{"ports.ipp", c.Ports.IPP},
		{"ports.ipps", c.Ports.IPPS},
		{"ports.auto_tls", c.Ports.AutoTLS},
		{"ports.dashboard", c.Ports.Dashboard},
		{"ports.snmp", c.Ports.SNMP},
		{"smb.port", c.SMB.Port},
		{"wsd.port", c.WSD.Port},
	}
	for i, p := range c.Raw.ExtraPorts {
		all = append(all, portEntry{fmt.Sprintf("raw.extra_ports[%d]", i), p})
	}

	for _, e := range all {
		if e.port < 0 || e.port > 65535 {
			issues = append(issues, configIssue{
				Severity: sevError,
				Field:    e.field,
				Message:  fmt.Sprintf("port %d is out of range", e.port),
				Fix:      "set to a value between 1 and 65535, or 0 to disable",
			})
			continue
		}
		if e.port > 0 && e.port < 1024 {
			issues = append(issues, configIssue{
				Severity: sevWarning,
				Field:    e.field,
				Message:  fmt.Sprintf("port %d is privileged (<1024)", e.port),
				Fix:      "ports below 1024 need root (Linux/macOS) or Administrator (Windows); run elevated or pick a high port",
			})
		}
	}

	// Duplicate-port detection. Mirror engine.go Start(): when AutoTLS>0 it
	// serves IPP+IPPS on the one port and zeroes whichever of IPP/IPPS equals
	// it, so that overlap is the documented merge, not a clash.
	ipp, ipps := c.Ports.IPP, c.Ports.IPPS
	if c.Ports.AutoTLS > 0 {
		if ipp == c.Ports.AutoTLS {
			ipp = 0
		}
		if ipps == c.Ports.AutoTLS {
			ipps = 0
		}
	}

	listeners := []portEntry{
		{"ports.raw9100", c.Ports.Raw9100},
		{"ports.lpr", c.Ports.LPR},
		{"ports.ipp", ipp},
		{"ports.ipps", ipps},
		{"ports.auto_tls", c.Ports.AutoTLS},
		{"ports.dashboard", c.Ports.Dashboard},
		{"ports.snmp", c.Ports.SNMP},
		{"smb.port", c.SMB.Port},
		{"wsd.port", c.WSD.Port},
	}
	for i, p := range c.Raw.ExtraPorts {
		listeners = append(listeners, portEntry{fmt.Sprintf("raw.extra_ports[%d]", i), p})
	}

	seen := map[int]string{}
	for _, e := range listeners {
		if e.port <= 0 || e.port > 65535 {
			continue // disabled or already flagged out-of-range
		}
		if first, ok := seen[e.port]; ok {
			issues = append(issues, configIssue{
				Severity: sevError,
				Field:    e.field,
				Message:  fmt.Sprintf("port %d already used by %s", e.port, first),
				Fix:      fmt.Sprintf("assign distinct ports; e.g. move %s to %d", e.field, e.port+1),
			})
			continue
		}
		seen[e.port] = e.field
	}

	return issues
}

// enumOK reports whether val (lowercased) is in allowed; blank is always OK
// (treated as "use the default"). allowed entries must be lowercase.
func enumOK(val string, allowed ...string) bool {
	if val == "" {
		return true
	}
	v := strings.ToLower(val)
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

// validateEnums checks every enum-valued field against its allowed set.
func validateEnums(c *Config) []configIssue {
	var issues []configIssue
	check := func(field, val string, allowed ...string) {
		if !enumOK(val, allowed...) {
			issues = append(issues, configIssue{
				Severity: sevError,
				Field:    field,
				Message:  fmt.Sprintf("invalid value %q", val),
				Fix:      "use one of: " + strings.Join(allowed, " | "),
			})
		}
	}

	check("save", c.Save, "both", "raw", "meta", "metadata")
	check("log.level", c.Log.Level, "error", "warn", "info", "debug", "trace")
	check("log.format", c.Log.Format, "text", "json")
	check("ebcdic.carriage_control", c.EBCDIC.CarriageControl, "none", "asa", "machine", "auto")
	check("ebcdic.default_code_page", c.EBCDIC.DefaultCodePage, "cp037", "cp500", "cp1047", "cp273", "cp285", "cp297")

	for name, qd := range c.LPD.QueueDefaults {
		check(fmt.Sprintf("lpd.queue_defaults[%s].code_page", name), qd.CodePage,
			"cp037", "cp500", "cp1047", "cp273", "cp285", "cp297")
		check(fmt.Sprintf("lpd.queue_defaults[%s].carriage_control", name), qd.CarriageControl,
			"none", "asa", "machine", "auto")
	}

	check("forward.capture", c.Forward.Capture, "both", "sent", "orig")
	for i, t := range c.Forward.Targets {
		check(fmt.Sprintf("forward.targets[%d].transport", i), t.Transport, "raw", "lpr", "ipp", "ipps")
		check(fmt.Sprintf("forward.targets[%d].failure", i), t.Failure, "best_effort", "spool_retry", "block")
	}

	check("log.syslog.network", c.Log.Syslog.Network, "udp", "tcp")

	return issues
}

// validateTLS checks the configured certificate/key files.
func validateTLS(c *Config) []configIssue {
	var issues []configIssue
	cert, key := c.TLS.CertFile, c.TLS.KeyFile

	if cert == "" && key == "" {
		return nil // self-signed in memory
	}
	if cert != "" && key == "" {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "tls.key_file",
			Message: "cert_file is set but key_file is blank",
			Fix:     "set key_file to the matching private key, or blank both to use an in-memory self-signed certificate",
		})
	}
	if key != "" && cert == "" {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "tls.cert_file",
			Message: "key_file is set but cert_file is blank",
			Fix:     "set cert_file to the matching certificate, or blank both to use an in-memory self-signed certificate",
		})
	}
	if cert != "" {
		if _, err := os.Stat(cert); err != nil {
			issues = append(issues, configIssue{
				Severity: sevError, Field: "tls.cert_file",
				Message: fmt.Sprintf("certificate file not found: %s", cert),
				Fix:     "create the file or leave blank to use an in-memory self-signed certificate",
			})
		}
	}
	if key != "" {
		if _, err := os.Stat(key); err != nil {
			issues = append(issues, configIssue{
				Severity: sevError, Field: "tls.key_file",
				Message: fmt.Sprintf("key file not found: %s", key),
				Fix:     "create the file or leave blank to use an in-memory self-signed certificate",
			})
		}
	}
	return issues
}

// validateForward checks forward-proxy targets for completeness and plausible
// address formats.
func validateForward(c *Config) []configIssue {
	var issues []configIssue
	if !c.Forward.Enabled {
		return nil
	}
	if len(c.Forward.Targets) == 0 {
		issues = append(issues, configIssue{
			Severity: sevWarning, Field: "forward.targets",
			Message: "forwarding is enabled but no targets are defined",
			Fix:     "add at least one target, or set forward.enabled to false",
		})
		return issues
	}
	for i, t := range c.Forward.Targets {
		field := fmt.Sprintf("forward.targets[%d].address", i)
		if strings.TrimSpace(t.Address) == "" {
			issues = append(issues, configIssue{
				Severity: sevError, Field: field,
				Message: "target address is blank",
				Fix:     "set address to a host:port (raw/lpr) or a URI (ipp/ipps)",
			})
			continue
		}
		switch strings.ToLower(t.Transport) {
		case "ipp", "ipps":
			if !strings.Contains(t.Address, "://") {
				issues = append(issues, configIssue{
					Severity: sevWarning, Field: field,
					Message: fmt.Sprintf("%s transport expects a URI but got %q", t.Transport, t.Address),
					Fix:     "use a URI like ipp://host:631/ipp/print",
				})
			}
		case "raw", "lpr", "":
			if _, _, err := net.SplitHostPort(t.Address); err != nil {
				issues = append(issues, configIssue{
					Severity: sevWarning, Field: field,
					Message: fmt.Sprintf("%s transport expects host:port but got %q", t.Transport, t.Address),
					Fix:     "use a host:port like printer.example.com:9100",
				})
			}
		}
	}
	return issues
}

// validateSyslog checks the remote-syslog shipper configuration.
func validateSyslog(c *Config) []configIssue {
	var issues []configIssue
	s := c.Log.Syslog
	if !s.Enabled {
		return nil
	}
	if strings.TrimSpace(s.Address) == "" {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "log.syslog.address",
			Message: "syslog is enabled but address is blank",
			Fix:     "set address to a host:port, e.g. siem.example.com:514",
		})
	} else if _, _, err := net.SplitHostPort(s.Address); err != nil {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "log.syslog.address",
			Message: fmt.Sprintf("address %q is not host:port", s.Address),
			Fix:     "use a host:port, e.g. siem.example.com:514",
		})
	}
	if s.Facility < 0 || s.Facility > 23 {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "log.syslog.facility",
			Message: fmt.Sprintf("facility %d is out of range", s.Facility),
			Fix:     "set facility to 0..23 (16 = local0)",
		})
	}
	return issues
}

// validateStorage probes the capture and spool directories for writability.
// Directories are resolved from c (not the global cfg) so validation reflects
// the config actually being checked.
func validateStorage(c *Config) []configIssue {
	var issues []configIssue
	dirs := []string{
		resolveStorageDir(c.OutDir, "captures"),
		resolveStorageDir(c.Storage.SpoolDir, "spool"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			issues = append(issues, configIssue{
				Severity: sevError, Field: "storage",
				Message: fmt.Sprintf("cannot create directory %s: %v", dir, err),
				Fix:     fmt.Sprintf("ensure the directory exists and the account has write permission (currently: %s)", dir),
			})
			continue
		}
		probe := filepath.Join(dir, ".printcap-write-test")
		f, err := os.Create(probe)
		if err != nil {
			issues = append(issues, configIssue{
				Severity: sevError, Field: "storage",
				Message: fmt.Sprintf("cannot write to directory %s: %v", dir, err),
				Fix:     fmt.Sprintf("ensure the directory exists and the account has write permission (currently: %s)", dir),
			})
			continue
		}
		_ = f.Close()
		_ = os.Remove(probe)
	}
	return issues
}

// validateBind checks the listener bind address resolves to something usable.
func validateBind(c *Config) []configIssue {
	b := strings.TrimSpace(c.Bind)
	if b == "" || b == "0.0.0.0" || b == "::" {
		return nil
	}
	if net.ParseIP(b) != nil {
		return nil
	}
	if addrs, err := net.LookupHost(b); err == nil && len(addrs) > 0 {
		return nil
	}
	return []configIssue{{
		Severity: sevWarning, Field: "bind",
		Message: fmt.Sprintf("bind address %q is not a valid IP and did not resolve", b),
		Fix:     "use a local interface IP, 0.0.0.0 (all), or leave blank",
	}}
}
