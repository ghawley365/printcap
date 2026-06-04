package main

import (
	"net"
	"regexp"
	"strings"
)

type svcAddrs struct {
	host string
	v4   []net.IP
	v6   []net.IP
}

type service struct {
	instance string
	svcType  string
	port     uint16
	txt      []string
	subtypes []string
}

func (s service) instanceName() string { return s.instance + "." + s.svcType + ".local" }
func (s service) browseName() string   { return s.svcType + ".local" }

// boundListeners is the snapshot of which listeners actually bound, with their
// effective ports. 0 means "not advertised". The Engine fills this in.
type boundListeners struct {
	IPP     int
	IPPS    int
	Raw9100 int
	LPR     int
	Dash    int
}

func boolTF(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

// urfSupported is the single source of truth for the printer's URF capability
// set; ipp.go's urf-supported attribute derives from it so the two transports
// never drift.
func urfSupported() []string {
	return []string{"V1.4", "W8", "SRGB24", "RS300-600"}
}

func urfTxt() string {
	return strings.Join(urfSupported(), ",")
}

var hostUnsafe = regexp.MustCompile(`[^A-Za-z0-9-]+`)

func resolveInstance() string {
	if cfg.MDNS.Instance != "" {
		return cfg.MDNS.Instance
	}
	return cfg.Printer.Name
}

// resolveHost returns the advertised "<host>.local" label, sanitized to the
// DNS host-label charset (letters, digits, hyphen).
func resolveHost() string {
	h := cfg.MDNS.Hostname
	if h != "" {
		return strings.TrimSuffix(h, ".local") + ".local"
	}
	base := hostUnsafe.ReplaceAllString(cfg.Printer.Name, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "printcap"
	}
	return base + ".local"
}

// buildServices turns the live config plus the set of bound listeners into the
// DNS-SD services to advertise. instance is the (already collision-resolved)
// service instance name.
func buildServices(bl boundListeners, airprint bool, instance string) []service {
	p := cfg.Printer
	var svcs []service

	rp := strings.TrimPrefix(orElse(cfg.IPPOpts.DefaultPath, "/ipp/print"), "/")
	pdl := strings.Join(p.DocumentFormats, ",")
	duplex := boolTF(containsAnyTwoSided(p.Sides))
	uuid := "00000000-0000-1000-8000-000000000001"
	adminurl := ""
	if bl.Dash > 0 {
		adminurl = "http://" + resolveHost() + ":" + itoa(bl.Dash) + "/"
	}

	ippTxt := func(tls bool) []string {
		txt := []string{
			"txtvers=1", "qtotal=1",
			"rp=" + rp,
			"ty=" + p.MakeAndModel,
			"product=(" + p.MakeAndModel + ")",
			"note=" + p.Location,
			"pdl=" + pdl,
			"UUID=" + uuid,
			"Color=" + boolTF(p.Color),
			"Duplex=" + duplex,
			"URF=" + urfTxt(),
			"kind=document",
		}
		if adminurl != "" {
			txt = append(txt, "adminurl="+adminurl)
		}
		if tls {
			txt = append(txt, "TLS=1.2")
		}
		return txt
	}

	subs := []string{}
	if airprint {
		subs = []string{"_universal", "_cups"}
	}

	if bl.IPP > 0 {
		svcs = append(svcs, service{instance, "_ipp._tcp", uint16(bl.IPP), ippTxt(false), subs})
	}
	if bl.IPPS > 0 {
		svcs = append(svcs, service{instance, "_ipps._tcp", uint16(bl.IPPS), ippTxt(true), subs})
	}
	if bl.Raw9100 > 0 {
		txt := []string{"txtvers=1", "qtotal=1", "ty=" + p.MakeAndModel,
			"product=(" + p.MakeAndModel + ")", "note=" + p.Location,
			"pdl=" + pdl, "Transparent=T", "Binary=T"}
		svcs = append(svcs, service{instance, "_pdl-datastream._tcp", uint16(bl.Raw9100), txt, nil})
	}
	if bl.LPR > 0 {
		txt := []string{"txtvers=1", "qtotal=1", "rp=auto", "ty=" + p.MakeAndModel, "note=" + p.Location}
		svcs = append(svcs, service{instance, "_printer._tcp", uint16(bl.LPR), txt, nil})
	}
	return svcs
}

func containsAnyTwoSided(sides []string) bool {
	for _, s := range sides {
		if strings.HasPrefix(s, "two-sided") {
			return true
		}
	}
	return false
}
