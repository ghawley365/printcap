package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// captureSink is the single point where every listener hands off a finished
// job. Centralizing it keeps save-mode, naming, size-capping, logging, and the
// dashboard feed identical no matter which protocol produced the bytes.
type captureSink struct {
	dir string
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// extForFormat detects the page-description language of the job (recording it on
// j.PDL) and returns the matching file extension. The advertised IPP
// document-format is preferred when it clearly implies a type; otherwise the
// spool bytes are sniffed (seeing through any PJL preamble).
func extForFormat(j *job) string {
	name, ext, _ := detectPDL(j.data)
	j.PDL = name
	// If IPP told us the format and detection was inconclusive, honor the hint.
	if name == "Unknown" || name == "Text" {
		f := strings.ToLower(j.DocFormat)
		switch {
		case strings.Contains(f, "pdf"):
			j.PDL, ext = "PDF", ".pdf"
		case strings.Contains(f, "postscript"):
			j.PDL, ext = "PostScript", ".ps"
		case strings.Contains(f, "pwg-raster"):
			j.PDL, ext = "PWG Raster", ".pwg"
		case strings.Contains(f, "urf"):
			j.PDL, ext = "Apple Raster (URF)", ".urf"
		case strings.Contains(f, "pclxl"):
			j.PDL, ext = "PCL-XL (PCL6)", ".pclxl"
		case strings.Contains(f, "pcl"):
			j.PDL, ext = "PCL", ".pcl"
		case strings.Contains(f, "jpeg"):
			j.PDL, ext = "JPEG", ".jpg"
		}
	}
	return ext
}

// save persists the job per the configured save mode, records it for the
// dashboard, and logs a one-line summary.
func (s *captureSink) save(j *job) error {
	// Enforce per-job byte cap (0 = unlimited) before touching disk/memory.
	if cfg.MaxJobMB > 0 {
		if cap := cfg.MaxJobMB * 1024 * 1024; len(j.data) > cap {
			j.data = j.data[:cap]
			j.Bytes = cap
		}
	}

	j.ID = nextSeq()
	if j.Received == "" {
		j.Received = time.Now().Format(time.RFC3339)
	}

	// Detect the PDL and pick an extension up front so it's recorded even in
	// metadata-only mode (where no spool file is written).
	ext := extForFormat(j)

	stamp := time.Now().Format("20060102-150405")
	base := fmt.Sprintf("%s-%04d-%s", stamp, j.ID, j.Protocol)
	if j.JobName != "" {
		base += "-" + unsafeName.ReplaceAllString(j.JobName, "_")
	}
	if len(base) > 120 {
		base = base[:120]
	}
	j.captureBase, j.captureExt = base, ext

	mode := cfg.mode()
	if mode != saveMeta && len(j.data) > 0 {
		name := base + ext
		if err := os.WriteFile(filepath.Join(s.dir, name), j.data, 0o600); err != nil {
			logErr(j.Protocol, "failed to write spool data: %v", err)
		} else {
			j.SavedAs = name
			logDebug(j.Protocol, "wrote spool file %s (%d bytes)", name, j.Bytes)
		}
	}

	// Tee to the forwarder before writing the JSON metadata so j.Forwards is
	// captured in the .json. The original spool bytes are passed untouched.
	var fwdErr error
	if forward != nil {
		original := append([]byte{}, j.data...)
		fwdErr = forward.forward(j, original)
	}

	// dlpDecoded captures the EBCDIC-decoded text (if any) for DLP scanning
	// below. It stays "" when EBCDIC decode didn't run or failed.
	var dlpDecoded string

	if page, carriage, on := resolveEBCDIC(j, j.data); on {
		// Machine (FCFC) carriage-control is raw EBCDIC control bytes that decode
		// would map away, so it MUST run on the raw bytes BEFORE decode. ASA/none/
		// auto operate on the decoded text, AFTER decode.
		raw := j.data
		if carriage == "machine" {
			raw = convertMachineRaw(raw)
		}
		if decoded := decodeEBCDIC(raw, page); decoded != "" {
			if carriage != "machine" {
				decoded = applyCarriageControl(decoded, carriage)
			}
			dlpDecoded = decoded // make available to DLP scan
			j.CodePage = page
			if cfg.EBCDIC.DecodedSidecar && cfg.mode() != saveMeta {
				name := base + "-decoded.txt"
				if err := os.WriteFile(filepath.Join(s.dir, name), []byte(decoded), 0o600); err != nil {
					logErr(j.Protocol, "failed to write decoded sidecar: %v", err)
				} else {
					j.DecodedAs = name
					logInfo(j.Protocol, "decoded %d bytes as %s (%s) -> %s", j.Bytes, page, carriage, name)
				}
			}
		} else {
			logWarn(j.Protocol, "EBCDIC decode skipped: unknown code page %q", page)
		}
	}

	if cfg.DLP.Enabled {
		if matches := scanDLP(j.data, dlpDecoded); len(matches) > 0 {
			j.DLPMatches = matches
			logWarn("DLP", "job %q from %s matched rule(s): %s", j.JobName, j.Source, strings.Join(matches, ", "))
		}
	}

	if mode != saveRaw {
		b, _ := json.MarshalIndent(j, "", "  ")
		if err := os.WriteFile(filepath.Join(s.dir, base+".json"), b, 0o600); err != nil {
			logErr(j.Protocol, "failed to write metadata: %v", err)
		}
	}

	store.add(j)
	logInfo(j.Protocol, "captured %d bytes from %s user=%s job=%q queue=%s pdl=%s -> %s",
		j.Bytes, j.Source, orQ(j.User), j.JobName, orQ(j.Queue), orQ(j.PDL), orElse(j.SavedAs, "(meta only)"))
	return fwdErr
}

func orQ(s string) string { return orElse(s, "?") }
func orElse(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// newJob builds a job stamped with the current time, consistent across every
// protocol path.
func newJob(proto, source string) *job {
	return &job{Protocol: proto, Source: source, Received: time.Now().Format(time.RFC3339)}
}
