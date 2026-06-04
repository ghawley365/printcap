package main

import (
	"bytes"
	"regexp"
	"strings"
)

// compiledDLPRule is a pre-compiled form of a DLPRule ready for fast matching.
type compiledDLPRule struct {
	name    string
	re      *regexp.Regexp // set for regex mode
	keyword []byte         // lower-cased, set for keyword mode
}

// dlpRules holds the global compiled rule set built once at engine Start.
var dlpRules []compiledDLPRule

// compileDLPRules compiles cfg.DLP.Rules into a set of compiledDLPRule values.
// It returns the compiled set and one error per rule that failed to compile
// (bad regex pattern, unknown mode, blank pattern) so callers can warn.
func compileDLPRules(rules []DLPRule) ([]compiledDLPRule, []error) {
	var compiled []compiledDLPRule
	var errs []error
	for _, r := range rules {
		switch strings.ToLower(r.Mode) {
		case "keyword":
			compiled = append(compiled, compiledDLPRule{
				name:    r.Name,
				keyword: bytes.ToLower([]byte(r.Pattern)),
			})
		case "regex":
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			compiled = append(compiled, compiledDLPRule{name: r.Name, re: re})
		default:
			// Unknown mode: skip silently here; validate.go catches it at startup.
		}
	}
	return compiled, errs
}

// rebuildDLP recompiles the global rule set from the current cfg.
// Called at engine Start so the compiled set always matches the active config.
// Any rule that fails to compile is logged as a warning and skipped.
func rebuildDLP() {
	if !cfg.DLP.Enabled {
		dlpRules = nil
		return
	}
	compiled, errs := compileDLPRules(cfg.DLP.Rules)
	for _, e := range errs {
		logWarn("DLP", "rule compile error (skipped): %v", e)
	}
	dlpRules = compiled
}

// scanDLP returns the names of compiled DLP rules that match the raw job bytes
// or the decoded text string. Returns nil when DLP is disabled or nothing
// matches. Results are deduplicated and ordered by rule position.
//
// Keyword rules perform a case-insensitive substring search.
// Regex rules are RE2 and match against raw bytes and, when non-empty, the
// decoded text.
//
// NOTE: compressed or binary PDLs (e.g. PDF with embedded streams, PCL, ZPL)
// will not match plain-text patterns unless the document is decoded first;
// only the decoded sidecar text (EBCDIC decode output) enables plain-text
// matches for mainframe streams.
func scanDLP(data []byte, decoded string) []string {
	if !cfg.DLP.Enabled || len(dlpRules) == 0 {
		return nil
	}

	// Lower-case the raw bytes once for all keyword rules.
	lowerData := bytes.ToLower(data)
	lowerDecoded := strings.ToLower(decoded)

	var matches []string
	seen := make(map[string]bool, len(dlpRules))

	for _, rule := range dlpRules {
		if seen[rule.name] {
			continue
		}
		var hit bool
		if rule.re != nil {
			// Regex: try raw bytes then decoded text.
			hit = rule.re.Match(data)
			if !hit && decoded != "" {
				hit = rule.re.MatchString(decoded)
			}
		} else {
			// Keyword: case-insensitive substring in raw bytes or decoded text.
			hit = bytes.Contains(lowerData, rule.keyword)
			if !hit && decoded != "" {
				hit = strings.Contains(lowerDecoded, string(rule.keyword))
			}
		}
		if hit {
			matches = append(matches, rule.name)
			seen[rule.name] = true
		}
	}
	return matches
}
