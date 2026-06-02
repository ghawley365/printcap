# Design — Mainframe EBCDIC + richer LPD metadata

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Track:** Legacy/ERP/Linux protocol expansion — **spec #2 of 4**
- **Approach:** Hand-rolled, pure-stdlib EBCDIC decoding + carriage-control
  conversion, applied centrally in `sink.save`; richer LPD control-file parsing.

## 1. Problem & goal

IBM mainframes (z/OS) and midrange (IBM i / AS-400) print to printers via
LPR/LPD to a Remote Output Queue, and frequently send **EBCDIC/SCS** data with
**ASA or machine carriage-control** rather than ASCII. printcap currently records
those bytes verbatim (unreadable) and parses only the `H`/`P`/`J` control-file
fields.

**Goal:** capture mainframe jobs *readably* — transcode EBCDIC → UTF-8 using
operator-controlled code pages, convert carriage-control to normal line breaks,
and capture richer LPD metadata — while keeping the original raw bytes and
staying a single zero-dependency exe.

**Non-goals (YAGNI):** EBCDIC *encoding* (we only decode inbound); SCS/3270
field-level rendering; AFP/IPDS structured-field interpretation; code pages
beyond the hand-rolled common set (extend later if needed).

## 2. Decisions (from brainstorming)

- **EBCDIC trigger:** per-LPD-queue mapping **+** a global default **+** a
  heuristic auto-detect fallback.
- **Code pages (hand-rolled, zero-dep):** CP037 (US/Canada), CP500
  (International), CP1047 (Open/Latin-1), CP273 (Germany), CP285 (UK), CP297
  (France).
- **Output:** keep the raw spool **and** write a UTF-8 `<base>-decoded.txt`
  sidecar.
- **Richer LPD:** capture more control-file fields (C class, T title) and use the
  FORTRAN `r` format letter as a carriage-control hint; convert ASA/machine
  carriage-control; support per-queue defaults.

## 3. Architecture

Decoding happens **centrally in `sink.save`** so it covers every protocol that
produces a job, using settings resolved from the job's queue + global config +
auto-detect.

### New files

- **`ebcdic.go`** — the six code-page tables (`[256]rune` each), `decodeEBCDIC(data
  []byte, page string) string`, `looksEBCDIC(data []byte) bool`, and the
  code-page registry/lookup.
- **`carriage.go`** — `applyCarriageControl(text string, mode string) string` for
  `asa` and `machine` (FCFC) modes (`none` returns input unchanged).

### Modified files

- **`config.go`** — add `EBCDICConf`; extend `LPDOpts` with `QueueDefaults`.
- **`lpd.go`** — parse additional control-file letters; attach per-queue defaults
  to the job.
- **`sink.go`** — after capturing raw, resolve the effective code page; if
  applicable, decode + carriage-control and write the `-decoded.txt` sidecar;
  record `CodePage`/`DecodedAs` on the job.
- **`main.go`** — `job` gains `Class`, `Title`, `CodePage`, `DecodedAs` fields.

## 4. Configuration

```jsonc
"ebcdic": {
  "enabled": true,
  "default_code_page": "CP037",   // used when a job is EBCDIC but no queue match
  "auto_detect": true,            // heuristic fallback when no explicit mapping
  "decoded_sidecar": true,        // write <base>-decoded.txt
  "carriage_control": "auto"      // none | asa | machine | auto (global default)
},

"lpd": {
  // ...existing fields...
  "queue_defaults": {             // keyed by queue name; glob patterns allowed
    "mvs*":  { "code_page": "CP037", "carriage_control": "asa",     "ebcdic": true },
    "as400": { "code_page": "CP037", "carriage_control": "machine", "ebcdic": true }
  }
}
```

`queue_defaults` value type:

```go
type QueueDefault struct {
    CodePage        string `json:"code_page"`
    CarriageControl string `json:"carriage_control"` // none|asa|machine|auto
    EBCDIC          bool   `json:"ebcdic"`           // force-treat as EBCDIC
}
```

**Resolution order for a job (in `sink.save`):**
1. If a `queue_defaults` entry's key glob-matches `j.Queue`: use its
   `code_page`/`carriage_control`; treat as EBCDIC when `ebcdic:true` (or when its
   `code_page` is set).
2. Else if `ebcdic.auto_detect` and `looksEBCDIC(raw)`: treat as EBCDIC with
   `ebcdic.default_code_page` and `ebcdic.carriage_control`.
3. Else: no decode (capture raw only, as today).

Unknown code-page names or carriage modes are logged at `warn` and skip decoding
(non-fatal).

## 5. EBCDIC decoding (`ebcdic.go`)

- Each code page is a `[256]rune` table built from the authoritative **Unicode
  Consortium IBM mapping files** (e.g. `MAPPINGS/VENDORS/MICSFT/EBCDIC/CP037.TXT`
  and the matching CDRA pages). `decodeEBCDIC` maps each byte through the table
  and returns UTF-8.
- `looksEBCDIC(data)` heuristic: sample the first ~4 KiB; treat as EBCDIC when the
  EBCDIC space `0x40` is the dominant byte **and** the fraction of bytes in
  EBCDIC-printable ranges is high while ASCII printable/control distribution is
  inconsistent with text. Conservative — favors false-negative (leave raw) over
  corrupting ASCII.
- Table correctness is locked by tests asserting known anchors per page (e.g.
  CP037: `0x40`→space, `0xC1`→'A', `0x81`→'a', `0x4B`→'.', `0x5B`→'$'; CP500/1047
  differ at the cent/bracket positions — each asserted).

## 6. Carriage control (`carriage.go`)

`applyCarriageControl(text, mode)`:
- **`asa`**: the first character of each record is the control: space → newline
  before the line (single space), `0` → blank line + line (double space), `-` →
  two blank lines (triple), `1` → form feed (`\f`) then line, `+` → overprint
  (no advance, emitted as carriage return). The control character is stripped from
  the output.
- **`machine` (FCFC)**: the first byte is a machine carriage-control code; map the
  common print-and-space / skip-to-channel-1 codes to newline/form-feed and strip
  it.
- **`none`**: return input unchanged. **`auto`**: if every record begins with a
  valid ASA control character, treat as `asa`; else if bytes look like machine
  codes, `machine`; else `none`.

Carriage control runs **after** EBCDIC decode (it operates on decoded text).

## 7. Richer LPD control-file parsing (`lpd.go`)

`parseControlFile` extends to capture, in addition to `H`/`P`/`J`:

- `C` → `job.Class` and `T` → `job.Title`, plus the FORTRAN carriage-control format
  letter `r`, recorded as a hint used to default the carriage-control mode
  (`r` ⇒ ASA) when the queue doesn't specify one.

**Out of scope (phase 1):** the `N` data-file-name field and the other format/print
letters (`f` formatted, `l` leave-control, `o` PostScript, `p` pr-format) are not
captured. Only `r` is interpreted, and only as a carriage-control hint.

Per-queue defaults are looked up by `j.Queue` at job completion and stored on the
job so `sink.save` can resolve them without re-reading config.

## 8. Capture output

- Raw spool unchanged (`<base><ext>`).
- When decoded: `<base>-decoded.txt` (UTF-8), and `job.CodePage` +
  `job.DecodedAs` set (serialized in the `.json` and shown in the dashboard).
- `save: meta` still records `CodePage`/decoded status without writing files;
  `decoded_sidecar:false` suppresses the `.txt` while keeping the metadata.

## 9. Logging

Component tags reuse `[LPR]`/protocol for capture; decoding logs under the job's
protocol tag: `info` "decoded N bytes as CP037 (asa) -> <file>"; `warn` unknown
code page / mode; `debug` auto-detect decision; `trace` per-record carriage
control.

## 10. Testing

- **Code pages:** anchor-point assertions per page (above); a full round-trip
  sample ("HELLO WORLD" in EBCDIC bytes → ASCII) for CP037 and CP500.
- **Detection:** `looksEBCDIC` true for an EBCDIC sample, false for ASCII text and
  for a PDF/PCL binary.
- **Carriage control:** ASA single/double/triple/formfeed/overprint; machine
  codes; `auto` selection; `none` passthrough.
- **Control file:** parsing `C`/`T`; the `r` format letter → ASA carriage hint
  (`f` and other letters yield no hint).
- **Resolution:** queue glob match wins over auto-detect; unknown code page →
  skip + warn.
- **Sink integration:** an EBCDIC job on a mapped queue yields raw + `-decoded.txt`
  with readable text and correct `CodePage`/`DecodedAs` metadata; an ASCII job is
  untouched.

## 11. Acceptance criteria

1. An EBCDIC job sent via LPR to a queue mapped to CP037 is captured raw **and**
   as readable `-decoded.txt`; metadata shows the code page.
2. ASA/machine carriage-control produces correct line breaks/form feeds in the
   decoded text.
3. Auto-detect decodes an unmapped EBCDIC job with the default page and leaves
   ASCII/binary jobs byte-identical to today.
4. `C`/`T` control-file fields appear in job metadata.
5. `ebcdic.enabled:false` (or no match) reproduces current behavior exactly.
6. No new module dependency; build stays a single static exe; `go vet` clean.
```
