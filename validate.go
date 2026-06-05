package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
	issues = append(issues, validateDLP(c)...)
	issues = append(issues, validateIntercept(c)...)
	return issues
}

// parseAuthExpiry parses an authorization expiry stamp. It accepts RFC3339
// ("2026-12-31T23:59:59Z") or a plain calendar date ("2026-12-31", interpreted as
// end-of-day UTC so a same-day capture is still permitted). A blank string means
// "no expiry" and returns the zero time with ok=true.
func parseAuthExpiry(s string) (t time.Time, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if d, err := time.Parse("2006-01-02", s); err == nil {
		return d.Add(24*time.Hour - time.Second), true // end of that day, UTC
	}
	return time.Time{}, false
}

// validateIntercept enforces the authorization preconditions for the network
// interception mode. Capture of all traffic — and especially active ARP poisoning
// — is gated behind an explicit operator attestation so "authorized use only" is a
// checked precondition, not just documentation. Disabled intercept config is not
// scrutinized (you can carry an unused block in the file).
func validateIntercept(c *Config) []configIssue {
	if !c.Intercept.Enabled {
		return nil
	}
	var issues []configIssue
	a := c.Intercept.Authorization

	if !a.Acknowledged {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.authorization.acknowledged",
			Message: "intercept mode is enabled but authorization is not acknowledged",
			Fix:     "only on networks you are authorized to capture: set intercept.authorization.acknowledged=true (or pass -authorize) and record operator + engagement",
		})
	}
	if strings.TrimSpace(a.Operator) == "" {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.authorization.operator",
			Message: "operator is blank",
			Fix:     "set intercept.authorization.operator (or -operator) to the person/handle running the capture, for the audit record",
		})
	}
	if strings.TrimSpace(a.Engagement) == "" {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.authorization.engagement",
			Message: "engagement reference is blank",
			Fix:     "set intercept.authorization.engagement (or -engagement) to the ticket/SOW reference that grants capture authority",
		})
	}
	if exp, ok := parseAuthExpiry(a.Expiry); !ok {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.authorization.expiry",
			Message: fmt.Sprintf("expiry %q is not a valid date", a.Expiry),
			Fix:     "use RFC3339 (2026-12-31T23:59:59Z) or YYYY-MM-DD, or leave blank for no expiry",
		})
	} else if !exp.IsZero() && time.Now().After(exp) {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.authorization.expiry",
			Message: fmt.Sprintf("authorization expired at %s", exp.Format(time.RFC3339)),
			Fix:     "renew the engagement window and update intercept.authorization.expiry before capturing",
		})
	}

	// Carve enabled but with no ports reconstructs nothing — likely a mistake.
	if c.Intercept.Carve.Enabled && len(c.Intercept.Carve.Ports) == 0 {
		issues = append(issues, configIssue{
			Severity: sevWarning, Field: "intercept.carve.ports",
			Message: "stream carving is enabled but no ports are listed",
			Fix:     "list the print ports to reconstruct (e.g. 9100, 515, 631), or set intercept.carve.enabled=false",
		})
	}

	// Carve port values get the same range check named listeners get, so a typo
	// (negative/0/>65535) is caught at -check rather than silently carving nothing.
	for i, p := range c.Intercept.Carve.Ports {
		if p < 1 || p > 65535 {
			issues = append(issues, configIssue{
				Severity: sevError, Field: fmt.Sprintf("intercept.carve.ports[%d]", i),
				Message: fmt.Sprintf("port %d is out of range", p),
				Fix:     "use a value between 1 and 65535",
			})
		}
	}
	// Non-negative numeric fields.
	for _, n := range []struct {
		field string
		val   int
	}{
		{"intercept.carve.max_stream_mb", c.Intercept.Carve.MaxStreamMB},
		{"intercept.carve.idle_flush_sec", c.Intercept.Carve.IdleFlushSec},
		{"intercept.arp.interval_ms", c.Intercept.ARP.IntervalMS},
		{"intercept.snaplen", c.Intercept.SnapLen},
	} {
		if n.val < 0 {
			issues = append(issues, configIssue{
				Severity: sevError, Field: n.field,
				Message: fmt.Sprintf("%d is negative", n.val),
				Fix:     "use a non-negative value (0 = default/unlimited)",
			})
		}
	}

	// Surface the runtime fail-closed behavior at check time too: ARP enabled with
	// an empty allow-list captures nothing actively (no whole-subnet mode).
	if c.Intercept.ARP.Enabled && len(c.Intercept.ARP.Targets) == 0 {
		issues = append(issues, configIssue{
			Severity: sevWarning, Field: "intercept.arp.targets",
			Message: "arp.enabled is true but the target allow-list is empty",
			Fix:     "list the specific victim IPs in intercept.arp.targets; with none, active poisoning stays OFF (capture-only)",
		})
	}
	// Parse ARP target/gateway IPs at -check so a typo is caught before start
	// (runtime validation is fail-closed but only fires when intercept actually runs).
	for i, raw := range c.Intercept.ARP.Targets {
		if net.ParseIP(strings.TrimSpace(raw)) == nil {
			issues = append(issues, configIssue{
				Severity: sevError, Field: fmt.Sprintf("intercept.arp.targets[%d]", i),
				Message: fmt.Sprintf("%q is not a valid IP", raw),
				Fix:     "use a literal IPv4/IPv6 address",
			})
		}
	}
	if g := strings.TrimSpace(c.Intercept.ARP.Gateway); g != "" && net.ParseIP(g) == nil {
		issues = append(issues, configIssue{
			Severity: sevError, Field: "intercept.arp.gateway",
			Message: fmt.Sprintf("%q is not a valid IP", g),
			Fix:     "use a literal gateway IP, or leave blank to auto-detect",
		})
	}
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

// validateDLP checks DLP rule definitions for completeness and compilability.
func validateDLP(c *Config) []configIssue {
	if !c.DLP.Enabled {
		return nil
	}
	var issues []configIssue
	for i, r := range c.DLP.Rules {
		field := fmt.Sprintf("dlp.rules[%d]", i)
		if strings.TrimSpace(r.Name) == "" {
			issues = append(issues, configIssue{
				Severity: sevWarning,
				Field:    field + ".name",
				Message:  "rule name is blank",
				Fix:      "give the rule a descriptive name so matches can be identified in logs and job metadata",
			})
		}
		mode := strings.ToLower(r.Mode)
		if mode != "keyword" && mode != "regex" {
			issues = append(issues, configIssue{
				Severity: sevError,
				Field:    field + ".mode",
				Message:  fmt.Sprintf("invalid mode %q", r.Mode),
				Fix:      "use one of: keyword | regex",
			})
			continue // no point checking the pattern if the mode is unknown
		}
		if strings.TrimSpace(r.Pattern) == "" {
			issues = append(issues, configIssue{
				Severity: sevError,
				Field:    field + ".pattern",
				Message:  "pattern is blank",
				Fix:      "set pattern to the keyword substring or regular expression to match",
			})
			continue
		}
		if mode == "regex" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				issues = append(issues, configIssue{
					Severity: sevError,
					Field:    field + ".pattern",
					Message:  fmt.Sprintf("regex does not compile: %v", err),
					Fix:      "fix the regular expression",
				})
			}
		}
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
