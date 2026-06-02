# Code Audit Report

> Automated analysis of **29** files | **4,777** lines of code | 6.3s baseline
> Enhanced 2026-06-02 with **gosec**, **govulncheck**, **semgrep (auto)**, **gitleaks**, **trufflehog**, and **trivy**, plus manual source review of all network-facing code paths.

---

## Enhanced Security Synthesis (read this first)

### What printcap is — and why context changes the findings

printcap is a **network print-server / spool-capture tool** (a printer emulator / honeypot). It deliberately listens on every common print transport — Raw/JetDirect (9100), LPR/LPD (515), IPP (631), IPPS (6310), an SNMP v1/v2c agent (161) — accepts jobs from anyone, and writes the captured spool data to disk. It also serves a live web **dashboard** (8631). By default it binds **all of these to `0.0.0.0`** (every interface).

This matters for the audit: **unauthenticated print listeners are the product, not a vulnerability.** The right lens is *"who can reach the captured data, and how is sensitive material handled?"* Most findings below are graded through that lens.

### Overall health: **GOOD**

This is a well-engineered, security-conscious codebase. Evidence:
- **No secrets** found (gitleaks, trufflehog, trivy all clean).
- **No known-CVE dependencies** (govulncheck clean for both darwin and windows builds; trivy clean). Minimal dependency surface (`lxn/walk`, `golang.org/x/sys`, `govaluate`).
- Defensive engineering is visible throughout: request body caps (`io.LimitReader`), LPD `readChunk` that *never* pre-allocates from an attacker-supplied count (anti-OOM), idle/read-header timeouts to prevent goroutine pinning, secret redaction in the dashboard config API, path-traversal defense-in-depth (`filepath.Base` + join), filename sanitization via an allow-list regex, and a private key written `0600`.

The findings that remain are mostly **deployment-posture** issues (what's exposed by default) and **robustness/quality gaps** (no tests for hand-rolled binary protocol parsers), not classic injectable vulnerabilities.

### Priority findings

| # | Severity | Finding | Where |
|---|----------|---------|-------|
| H1 | 🟠 High | **Unauthenticated dashboard serves captured documents + full log over the network**, bound to `0.0.0.0` by default. Anyone who can reach :8631 can list jobs and download raw spool data (`/api/job?id=`) and the entire log file (`/api/logfile`). | `dashboard.go`, `engine.go:40` |
| H2 | 🟠 High | **No tests at all** (0 test files for 4 hand-rolled binary parsers: SNMP BER/TLV, IPP, LPD, PDL). High regression/robustness risk for untrusted-input parsers. | whole repo |
| M1 | 🟡 Medium | **Captured spool files + metadata written `0644`** (world-readable). Captured print jobs may contain sensitive documents; on a multi-user host any local user can read them. | `sink.go:84,93` |
| M2 | 🟡 Medium | **Insecure-by-default posture**: bind `0.0.0.0`, SNMP community `"public"`, dashboard enabled, no auth. Reasonable for a lab tool; risky if deployed unaware. | `config.go:160,209,218` |
| M3 | 🟡 Medium | **SNMP agent is an unauthenticated UDP reflector** on `0.0.0.0:161`. Responses are larger than requests → minor DDoS-reflection/amplification potential. Bounded by the small fixed MIB, so amplification factor is low. | `snmp.go`, `engine.go:121` |
| L1 | 🔵 Low | **`G115` integer-overflow conversions** in the IPP/SNMP encoders (`uint16(len(name))`, etc.). Inputs are config-/MIB-derived, not attacker-controlled, so low real risk — but a >64 KB attribute name/value would wrap the length field. | `ipp.go`, `snmp.go` |
| L2 | 🔵 Low | **~24–77 unhandled errors (`G104`)** — mostly ignored `w.Write` / `conn.Write` / `Encode` return values on network paths. Benign individually; worth a lint gate. | many files |
| L3 | 🔵 Low | **`G204` subprocess launches** (`netsh`, `rundll32`, `explorer`, `cmd /c start`). All use fixed binaries with operator/config-derived args and no shell string — **not** network-tainted. Effectively false positives. | `firewall_windows.go`, `gui_windows.go` |
| L4 | 🔵 Low | **God file** `gui_windows.go` (902 lines) and several 300–480-line files; deep nesting in a few spots. Maintainability only. | `gui_windows.go` et al. |

### Notes on findings the scanners flagged but that are actually mitigated

- **`G703` path traversal in `sink.go`** (capture filename built from job name): mitigated — job names are run through `unsafeName = [^A-Za-z0-9._-]+ → "_"` and the base is length-capped, so no `..`/separators survive.
- **`G304` file inclusion in `dashboard.go:131` (`/api/job`)**: mitigated — `filepath.Join(cfg.OutDir, filepath.Base(j.SavedAs))` strips any directory component (explicit defense-in-depth comment in code).
- **semgrep `no-direct-write-to-responsewriter` (XSS)** on `dashboard.go:148` / `ipp.go:101`: false positives — those writes emit a static HTML constant and a binary IPP response, not reflected user input. The dashboard's *dynamic* rendering is done client-side with a consistent `esc()` HTML-escaper.

### Recommended actions (highest leverage first)

1. **Protect the dashboard** (H1): bind it to `127.0.0.1` by default (separate from the print listeners' bind), and/or add a token/basic-auth gate, and/or make it read-only without the document-download endpoints. At minimum, document loudly that :8631 exposes captured documents.
2. **Tighten capture-file permissions** (M1): write spool/metadata files `0600` and the capture dir `0700` — captured documents are the tool's most sensitive output.
3. **Add tests** (H2): table-driven unit tests + fuzz tests (`go test -fuzz`) for `parseIPP`, `readTLV`/`decodeOID`/`decodeInt` (SNMP), LPD `parseControlFile`/`readChunk`, and `detectPDL`. These parse untrusted network bytes and have zero coverage today.
4. **Document the security posture** (M2/M3): ship a "secure deployment" note — change the SNMP community, restrict `bind`, disable SNMP/dashboard when not needed.
5. **Add a CI lint gate**: `govulncheck ./...`, `gosec ./...`, and `go vet`. Address `G115` with explicit bounds checks or `//nosec` with justification, and `errcheck` the network writes.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Summary](#summary)
- [Tools Used](#tools-used)
- [Secrets & Credentials](#secrets-credentials)
- [Security](#security)
- [Dependencies](#dependencies)
- [Code Structure](#code-structure)
- [Testing](#testing)
- [Import Graph & Coupling](#import-graph-coupling)
- [AI-Generated Code Patterns](#ai-generated-code-patterns)
- [What This Audit Doesn't Cover](#what-this-audit-doesnt-cover)

## Project Overview

| Metric | Value |
|--------|-------|
| Primary Language | Go |
| Frameworks | Go |
| Package Manager | go |
| Lockfile Present | Yes |
| Total Files Scanned | 29 |
| Code Files | 21 |
| Total Lines of Code | 4,777 |
| Avg File Size | 227 lines |

### Language Breakdown

| Language | Files |
|----------|-------|
| Go | 21 |
| Markdown | 2 |
| JSON | 1 |

### Largest Files

| File | Lines |
|------|-------|
| `gui_windows.go` | 902 |
| `snmp.go` | 478 |
| `logging.go` | 451 |
| `ipp.go` | 377 |
| `help_windows.go` | 309 |

## Summary

**Total findings: 12**

| Severity | Count |
|----------|-------|
| 🟠 High | 1 |
| 🟡 Medium | 2 |
| 🔵 Low | 9 |

### Findings by Category

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Testing | - | 1 | 1 | - | - |
| Code Structure | - | - | 1 | 8 | - |
| Security | - | - | - | 1 | - |

## Tools Used

### External Tools

| Tool | Version | Findings | Time |
|------|---------|----------|------|
| Semgrep | 1.154.0 | 0 | 1.4s |
| Gitleaks | 8.30.0 | 0 | 0.0s |
| Semgrep | 1.154.0 | 0 | 2.4s |
| Trivy | 0.69.3 | 0 | 0.2s |

**Tool issues:** TruffleHog (no-output), ESLint (no-output)

All analyzers also run built-in regex/heuristic analysis as a baseline. When external tools are available, their findings take priority and regex duplicates are removed.

### Install for Better Results

The following tools would enhance this audit:

| Tool | Enhances | Install | Benefit |
|------|----------|---------|--------|
| OSV-Scanner | dependencies | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` | Google-backed vulnerability database. Cross-ecosystem coverage using OSV.dev. |

## Secrets & Credentials

Scan for hardcoded secrets, API keys, tokens, and credentials. Any finding here should be treated as urgent — rotate exposed credentials immediately.

> No issues found. ✅

## Security

Detection of security anti-patterns including injection risks, XSS vectors, weak cryptography, and misconfigured security controls.

#### 1. HTTP (not HTTPS) URL in gui_windows.go

**Severity:** 🔵 Low

HTTP URL found. Data sent over HTTP is not encrypted.

**File:** `gui_windows.go` (line 770)

```
url := fmt.Sprintf("http://%s:%d/", host, cfg.Ports.Dashboard)
```

**Remediation:** Use HTTPS for all external URLs.

## Dependencies

Evaluation of dependency health, including version pinning, known vulnerabilities, lockfile presence, and problematic packages.

> No issues found. ✅

## Code Structure

Analysis of file sizes, nesting depth, import counts, and function length. Identifies complexity hotspots that increase maintenance cost.

#### 1. God file: gui_windows.go (902 lines)

**Severity:** 🟡 Medium

This file has 902 lines, well above the 500-line threshold. Large files are harder to test, review, and maintain. Consider splitting into focused modules.

**File:** `gui_windows.go`

**Remediation:** Break this file into smaller, focused modules with single responsibilities.

---

#### 2. Deep nesting in gui_windows.go (7 levels)

**Severity:** 🔵 Low

Code is nested 7 levels deep. Deep nesting reduces readability. Consider early returns, guard clauses, or extracting functions.

**File:** `gui_windows.go`

**Remediation:** Use early returns, guard clauses, or extract nested logic into helper functions.

---

#### 3. Large file: help_windows.go (309 lines)

**Severity:** 🔵 Low

This file has 309 lines. Not critical, but worth watching as it grows.

**File:** `help_windows.go`

**Remediation:** Consider splitting if this file continues to grow.

---

#### 4. Deep nesting in help_windows.go (5 levels)

**Severity:** 🔵 Low

Code is nested 5 levels deep. Deep nesting reduces readability. Consider early returns, guard clauses, or extracting functions.

**File:** `help_windows.go`

**Remediation:** Use early returns, guard clauses, or extract nested logic into helper functions.

---

#### 5. Large file: ipp.go (377 lines)

**Severity:** 🔵 Low

This file has 377 lines. Not critical, but worth watching as it grows.

**File:** `ipp.go`

**Remediation:** Consider splitting if this file continues to grow.

---

#### 6. Large file: logging.go (451 lines)

**Severity:** 🔵 Low

This file has 451 lines. Not critical, but worth watching as it grows.

**File:** `logging.go`

**Remediation:** Consider splitting if this file continues to grow.

---

#### 7. Deep nesting in lpd.go (5 levels)

**Severity:** 🔵 Low

Code is nested 5 levels deep. Deep nesting reduces readability. Consider early returns, guard clauses, or extracting functions.

**File:** `lpd.go`

**Remediation:** Use early returns, guard clauses, or extract nested logic into helper functions.

---

#### 8. Large file: snmp.go (478 lines)

**Severity:** 🔵 Low

This file has 478 lines. Not critical, but worth watching as it grows.

**File:** `snmp.go`

**Remediation:** Consider splitting if this file continues to grow.

---

#### 9. Deep nesting in snmp.go (5 levels)

**Severity:** 🔵 Low

Code is nested 5 levels deep. Deep nesting reduces readability. Consider early returns, guard clauses, or extracting functions.

**File:** `snmp.go`

**Remediation:** Use early returns, guard clauses, or extract nested logic into helper functions.

## Testing

Assessment of test coverage, framework configuration, assertion quality, and CI integration.

#### 1. No test files found

**Severity:** 🟠 High

The project has 21 source files but no test files were detected. Tests are essential for catching regressions and enabling safe refactoring.

**Remediation:** Start with integration tests for critical paths, then add unit tests for complex logic.

---

#### 2. No test framework configured

**Severity:** 🟡 Medium

No test framework was detected in project dependencies or configuration files.

**Remediation:** Add a test framework. For JS/TS: Vitest or Jest. For Python: pytest. For Elixir: ExUnit (built-in).

### Test Coverage Summary

| Metric | Value |
|--------|-------|
| Source Files | 21 |
| Test Files | 0 |
| Test Ratio | 0% |

## Import Graph & Coupling

Analysis of the dependency graph between source files. Identifies circular imports, hub files, and coupling hotspots.

> No issues found. ✅

### Dependency Graph Summary

| Metric | Value |
|--------|-------|
| Files Analyzed | 0 |
| Total Import Edges | 0 |
| Avg Imports/File | 0 |
| Circular Dependencies | 0 |

## AI-Generated Code Patterns

Detection of patterns commonly associated with AI-generated code, including tool fingerprints, silent error handling, and structural inconsistencies.

> No issues found. ✅

## What This Audit Doesn't Cover

Automated analysis catches patterns and known anti-patterns. The following areas require human judgment — understanding your business, your team, and your trajectory.

### Architecture Fitness

Whether your architecture fits your growth trajectory requires business context that no automated tool can assess. Questions like "should we break this monolith into services?" or "will this database choice scale to 10x users?" depend on your roadmap, team size, and funding stage.

**What a senior engineer would evaluate:**
- Alignment between technical architecture and business goals
- Scaling bottlenecks relative to your growth projections
- Build vs. buy decisions for your specific context
- Technical debt prioritization based on your roadmap

### Business-Context Prioritization

This audit assigns severity by *technical risk*. But technical risk and *business risk* aren't the same thing. A "medium" security finding in your payment flow is more urgent than a "high" complexity issue in an internal tool. Prioritization requires understanding what matters most to *your* business right now.

### Remediation Cost Estimates

Converting findings into engineering-weeks requires understanding your team's velocity, familiarity with the codebase, and current sprint commitments. A finding that takes a senior engineer 2 hours might take a junior engineer 2 days. Accurate estimates need context about *your* team.

### Executive Summary

Translating technical findings into language for founders, investors, or non-technical stakeholders requires understanding both the technology and the business conversation. What does this audit mean for your next fundraise? Your hiring plan? Your launch timeline?

---

**Need the full picture?** [Variant Systems](https://variantsystems.io/get-audit) provides comprehensive code audits that combine automated analysis with senior engineering judgment. We've reviewed codebases for startups from pre-seed to Series B — and we'll tell you honestly what needs fixing now, what can wait, and what's actually fine.

---

*Generated on 2026-06-02 by [code-audit](https://github.com/variant-systems/skills) — an open-source automated code audit tool by [Variant Systems](https://variantsystems.io).*

*This report covers automated analysis only. For architecture review, business-context prioritization, and remediation planning, [get a full audit](https://variantsystems.io/get-audit).*
