# Design — Transform & Forward proxy for printcap

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Relationship to other specs:** Independent feature; not part of the 4-spec
  legacy-protocol track. Sits alongside the mDNS spec.
- **Approach:** A — hook the tee/transform/forward engine into `sink.save`, the
  existing single capture chokepoint.

## 1. Problem & goal

printcap captures spool data to disk but forwards nothing. This feature turns it
into an optional **transparent print proxy (tee)**: every captured job is also
passed through an ordered **transform pipeline** (find/replace + PCL/command
injection) and **forwarded to one or more real downstream printers**, while the
original is still captured. The driving use case: rewrite spool content
(find/replace, inject PCL command sequences) and verify the result on an actual
printer.

**In scope (phase 1):**
- Tee: capture **both** the original and the transformed bytes; forward the
  transformed bytes downstream.
- **Multiple forward targets with routing**: each target has a match condition,
  an ordered transform pipeline, a transport + address, and a failure policy. A
  job tees to every target whose condition matches.
- **Transforms**: `replace` (literal / regex / hex), `inject_prefix`,
  `inject_suffix`, a reusable named **macro** library; every step may carry its
  own condition.
- **Conditions**: job metadata, detected PDL, stream content, size, always.
- **Transports (all fully implemented)**: `raw`/9100, `lpr` (RFC 1179 client),
  `ipp`/`ipps` (IPP client).
- **Failure policy** (per target): `best_effort` | `spool_retry` | `block`.

**Out of scope (YAGNI):** IPP `Create-Job`+`Send-Document` multi-document flow
(single `Print-Job` covers phase 1); IPP post-submit job-status polling; a GUI
tab (deferred to the "modern UI" track); automatic length-fixups for
length-indexed formats (documented caveat + PDL-gated rules instead).

## 2. Architecture

Hooks into `sink.save` — the single point every protocol handler funnels into —
so all inbound protocols (raw/9100, LPR, IPP/IPPS) gain forwarding uniformly.

### New files

- **`forward.go`** — the `forwarder` (built from config at engine start, like
  `sink`/`store`), the target model, `forward(j *job, original []byte) error`
  orchestration, failure-policy handling, the `transport` interface, and the
  spool-retry worker.
- **`transform.go`** — the ordered transform pipeline:
  `applyTransforms(steps []transformStep, data []byte, j *job) []byte`.
- **`match.go`** — `(condition).matches(j *job, data []byte) bool`, shared by
  target routing and per-step conditions.
- **`fwd_raw.go`** — raw/9100 transport.
- **`fwd_lpr.go`** — RFC 1179 LPD client transport.
- **`fwd_ipp.go`** — IPP/IPPS client transport (reuses the attribute encoders in
  `ipp.go`).

### Modified files

- **`sink.go`** — after capturing the original, call `forwarder.forward`; capture
  transformed bytes per target; **return `error`** so a `block` target can signal
  failure upstream.
- **`raw9100.go`, `lpd.go`, `ipp.go`** — propagate the `sink.save` error: raw
  closes the connection; LPD withholds the final ACK; IPP returns
  `server-error-job-canceled` (`0x0508`).
- **`config.go`** — `ForwardConf` + nested structs; default `enabled:false`.
- **`main.go`** — `-forward` bool flag + override.
- **`engine.go`** — build the `forwarder` in `Start()`; stop its retry workers in
  `Stop()` via a closer.

### Data flow inside `sink.save` (tee)

1. Capture the **original** exactly as today (PDL detect, write spool + `.json`,
   `store.add`).
2. `forwarder.forward(j, original)`:
   - For each target whose `when` matches → run that target's transform pipeline
     over a **copy** of the original (never mutate `j.data` or other targets'
     input).
   - When `capture` ∈ {both, sent}, write the transformed bytes as
     `<base>-sent-<target><ext>`.
   - Deliver via the target's transport under its failure policy.
   - Append a `forwardResult{target, transport, address, status, bytes, error}`
     to the job (serialized in the `.json` and shown in the dashboard feed).
3. If any matched `block` target failed, return that error.

## 3. Configuration

New top-level `forward` section; `enabled:false` by default (existing
deployments unchanged). A `-forward` flag toggles it.

```jsonc
"forward": {
  "enabled": false,                 // master switch (also -forward)
  "capture": "both",                // both | sent | orig

  "macros": {                       // reusable named byte blocks (\xNN-escapable)
    "pcl_reset":   "\\x1bE",
    "duplex_long": "\\x1b&l1S",
    "tray2":       "\\x1b&l4H"
  },

  "targets": [
    {
      "name": "lab-printer",        // logs, dashboard, -sent-<name> filenames
      "transport": "raw",           // raw | lpr | ipp | ipps
      "address": "10.0.0.20:9100",  // transport-specific (see below)
      "timeout_ms": 30000,

      // --- lpr-only ---
      "queue": "auto",              // LPD queue; "auto"/blank = job's queue or "lp"
      "privileged_source_port": false,
      // --- ipp/ipps-only ---
      "tls_skip_verify": true,      // accept self-signed downstream (ipps)
      "document_format": "",        // blank = detected/forwarded format

      "when": {                     // routing condition; empty = always
        "protocols":    ["IPP","9100"],        // 9100|LPR|IPP|IPPS
        "source_cidrs": ["10.0.0.0/24"],
        "users":        [], "hosts": [],
        "job_name":     "*invoice*",           // glob, or /regex/
        "queues":       [], "doc_formats": [],
        "pdls":         ["PCL","PostScript"],
        "contains":     "@PJL",                // literal | /regex/ | hex:1b45
        "min_bytes":    0, "max_bytes": 0
      },

      "failure": "best_effort",     // best_effort | spool_retry | block
      "retry": { "max_attempts": 5, "backoff_ms": 2000, "ttl_min": 60 },

      "transforms": [               // ordered; each step may carry its own "when"
        { "type": "inject_prefix", "data": "macro:pcl_reset" },
        { "type": "replace", "mode": "literal", "match": "ACME Corp", "with": "Globex",
          "all": true, "when": { "pdls": ["PCL","PostScript","Text"] } },
        { "type": "replace", "mode": "regex",  "match": "Draft\\s+\\d+", "with": "FINAL" },
        { "type": "replace", "mode": "hex",    "match": "1b266c3153",   "with": "1b266c3044" },
        { "type": "inject_suffix", "data": "macro:duplex_long" }
      ]
    }
  ]
}
```

### Transport-specific `address`

- **raw:** `host:port` (e.g. `10.0.0.20:9100`).
- **lpr:** `host:port` (e.g. `10.0.0.21:515`) plus `queue` / `privileged_source_port`.
- **ipp / ipps:** a full URI (`ipp://host:631/ipp/print`, `ipps://host:6310/...`)
  plus `tls_skip_verify` / `document_format`.

### Notation conventions (anywhere a value can be bytes)

- **Byte blocks** (`inject.data`, `macros.*`, `replace.with`, `replace.match`
  when `mode:"hex"`): `\xNN` hex escapes; `inject.data` also accepts `macro:NAME`.
- **`replace.match`**: interpreted by `mode` = `literal` | `regex` | `hex`.
- **`when.contains`**: plain = literal, `/.../` = regex, `hex:...` = hex bytes.
- **`when.job_name`** and similar: glob by default, `/.../` for regex.

### Validation at load (non-fatal, logged — "one bad thing never stops the rest")

- Malformed `address`/URI, bad regex, bad hex, or bad CIDR disables just that
  target or rule, logged at `warn`/`error`. The engine and other targets continue.

## 4. Transform pipeline (`transform.go`)

Steps run in array order on a per-target copy of the original:

- **`inject_prefix` / `inject_suffix`** — decode `data` (`\xNN` + `macro:NAME`
  expansion); prepend/append the bytes.
- **`replace`** — `literal` (`bytes.ReplaceAll`, or first-only when `all:false`),
  `regex` (Go `regexp` over the byte stream; `with` supports `$1` and `\xNN`),
  `hex` (decode both sides, byte replace).
- **Per-step `when`** — evaluated against the **current** (partially transformed)
  bytes + job; non-match skips the step.

**Length safety:** injection and replace may change total length (expected for
command wrapping). The pipeline logs the net byte delta per step at `debug`. Docs
warn that `replace` targets text/PCL/PostScript and can corrupt length-indexed
formats (PDF xref, PCL transparent-data/raster); `when.pdls` is the tool to gate a
rule to safe PDLs.

## 5. Conditions (`match.go`)

One evaluator for both routing and step-`when`. **All present fields must match
(AND); list fields match if any element matches (OR within the field).** Empty /
absent condition = always.

Fields: `protocols`, `source_cidrs`, `users`, `hosts`, `job_name` (glob/regex),
`queues`, `doc_formats`, `pdls` (printcap's detected PDL names), `contains`
(literal/regex/hex over bytes), `min_bytes`, `max_bytes`.

## 6. Transports

Interface in `forward.go`:

```go
type transport interface {
    send(t *target, data []byte, j *job) error
}
```

- **`fwd_raw.go` (raw/9100):** `net.DialTimeout("tcp", addr, …)`, set a write
  deadline from `timeout_ms`, stream all bytes, close.
- **`fwd_lpr.go` (RFC 1179 client):** connect (optionally from a privileged source
  port 721–731); send `\x02<queue>\n` (receive-job), read ACK; build a control
  file from job metadata (`H`=host, `P`=user, `J`=job-name, `f<dfname>`) and a
  data file; send each as `\x02<len> <cfname>\n` / `\x03<len> <dfname>\n` + bytes +
  `\x00`, reading the single ACK byte after each. Non-zero ACK or short read →
  error.
- **`fwd_ipp.go` (IPP/IPPS client):** build a **Print-Job** request — version 2.0,
  operation `0x0002`, operation attributes (`attributes-charset`,
  `attributes-natural-language`, `printer-uri` from `address`,
  `requesting-user-name` from the job, `job-name`, `document-format`) using the
  attribute encoders already in `ipp.go` — append the document bytes; `POST` to
  the URI over HTTP, or HTTPS for `ipps://` (TLS with `InsecureSkipVerify` when
  `tls_skip_verify`). Parse the IPP status code; `≥0x0400` → error.

## 7. Failure policies (per target)

- **`best_effort`** — deliver synchronously with a bounded timeout; on error log
  `warn` and record `failed`, never propagate.
- **`spool_retry`** — enqueue the transformed payload on an **in-memory** retry
  queue (best-effort, bounded by `max_attempts` and `ttl_min`; **not** persisted
  across restart); a per-target background worker retries with `backoff_ms` up to
  those limits; success/exhaustion logged + recorded. Worker stopped via the engine
  closer on `Stop()`. *(YAGNI: disk persistence of the retry queue is deferred.)*
- **`block`** — deliver synchronously; on failure `sink.save` returns the error and
  the handler signals upstream (raw closes; LPD withholds final ACK; IPP returns
  `server-error-job-canceled` `0x0508`).
- A job matching multiple targets runs `block` targets synchronously (first error
  wins) and async ones in the background.

## 8. Capture (tee)

- Original captured as today.
- Transformed captured per matching target as `<base>-sent-<name><ext>` when
  `capture` ∈ {both, sent}; `orig` skips it.
- Job `.json` gains `forwards: [{target, transport, address, status, bytes,
  error}]`, also surfaced in the dashboard job feed.

## 9. Logging

Component tag `[fwd]`:
- `info`: delivered N bytes to `<target>`.
- `warn`: forward failures; disabled targets/rules.
- `debug`: condition match/skip; per-step byte deltas.
- `trace`: per-rule detail.

## 10. Testing

- **transform:** literal/regex/hex replace, `all` vs first, prefix/suffix, macro +
  `\xNN` decoding, ordering, conditional-skip — table tests on bytes.
- **match:** every field incl. CIDR, glob vs regex, `contains` literal/regex/hex,
  size bounds, always.
- **forward orchestration:** routing selection, capture-both filenames + `forwards`
  metadata, each failure policy via a **fake transport** (block → error from
  `sink.save`; best_effort swallows; spool_retry enqueues + retries).
- **raw transport:** loopback `net.Listen` echo server asserts received bytes;
  dead-address timeout.
- **LPR client:** point the forwarder at **printcap's own LPD server** on a random
  port and assert the job is captured there with correct `H`/`P`/`J`; test a NAK →
  error.
- **IPP client:** point the forwarder at **printcap's own IPP handler** on a random
  port and assert capture with the right `job-name`/`document-format`; test an
  `ipps://` target against an in-test TLS server with `tls_skip_verify`; test a
  `≥0x0400` status → error.
- **integration:** `sink.save` with a configured target + local listener yields
  `-orig` + `-sent` files and correct `forwards` metadata.

## 11. Acceptance criteria

1. With `forward.enabled:true` and a `raw` target, a captured job is delivered
   byte-for-byte (post-transform) to a downstream 9100 listener; original + `-sent`
   files both exist; `forwards` metadata shows `ok`.
2. A `replace` rule (literal, regex, and hex each) changes the forwarded bytes as
   configured and is visible in the `-sent` capture; `inject_prefix`/`suffix` and a
   `macro:` reference wrap the job.
3. Routing: a job matching two targets tees to both; a non-matching job is captured
   only (not forwarded).
4. LPR and IPP/IPPS targets each deliver to printcap's own server in tests and to a
   real printer in manual acceptance.
5. Failure policies behave: `block` surfaces an error to the sender; `best_effort`
   delivers synchronously with a bounded timeout, records `failed` on error, and
   never propagates; `spool_retry` records `queued`, then retries on an in-memory
   queue (not persisted across restart) and gives up per `max_attempts`/`ttl_min`.
6. `forward.enabled:false` (default) leaves current behavior byte-identical.
7. No regression in existing capture; `go vet` clean; no new module dependency
   beyond the standard library.
```
