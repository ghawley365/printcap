# Design — SNMPv3 (USM auth/priv) agent

- **Date:** 2026-06-02
- **Status:** Approved (pending written-spec review)
- **Track:** Legacy/ERP/Linux protocol expansion — **spec #3 of 4**
- **Approach:** Extend the existing hand-rolled SNMP agent (`snmp.go`) with a
  User-based Security Model (USM) v3 path, pure stdlib crypto.

## 1. Problem & goal

printcap's SNMP agent answers v1/v2c only, with the community string in clear
text. Secured environments require **SNMPv3 USM** (authentication + encryption).

**Goal:** add a standards-compliant SNMPv3 agent (engine discovery, USM auth and
priv, the time-window replay check) serving the *same read-only MIB*, coexisting
with v1/v2c, using only Go's standard-library crypto — no new dependency.

**Non-goals (YAGNI):** SET operations (agent stays read-only); the View-based
Access Control Model (VACM) beyond "an authenticated user may read the whole
MIB"; SNMP notifications/traps; persistence of engineBoots across restarts
(boots = 1 per process run, which is RFC-valid).

## 2. Decisions (from brainstorming)

- **Security levels:** per-user — `noAuthNoPriv`, `authNoPriv`, `authPriv`.
- **Auth protocols:** MD5, SHA-1 (RFC 3414), SHA-256, SHA-512 (RFC 7860).
- **Priv protocols:** DES (RFC 3414), AES-128 (RFC 3826), AES-192/256 (Blumenthal
  key-extension).
- **Coexistence:** configurable; default v1/v2c **and** v3 both answer on UDP 161;
  a flag can disable v1/v2c for a v3-only posture.

## 3. Architecture

The engine still binds one UDP 161. `handleSNMP` inspects the message version
(the first INTEGER inside the outer SEQUENCE) and dispatches: `0`/`1` → the
existing v1/v2c path (when `allow_v1v2c`), `3` → the new v3 path (when
`v3_enabled`). The MIB and its lookup (`exactEntry`/`nextEntry`) are shared
unchanged.

### New files

- **`snmpv3.go`** — v3 message parse/build (`msgGlobalData`,
  `msgSecurityParameters`, scoped PDU), version dispatch, engine discovery
  (Report PDU), and the time-window check.
- **`usm.go`** — USM crypto: password→key localization (RFC 3414 §2.6), the auth
  HMAC (per protocol, with correct truncation), and priv encrypt/decrypt
  (DES-CBC, AES-CFB 128/192/256).

### Modified files

- **`snmp.go`** — version dispatch in `handleSNMP`; reuse its BER primitives
  (`tlv`, `readTLV`, `berInteger`, …), exporting/sharing as needed.
- **`config.go`** — `SNMPConf` gains v3 fields and a `users` list.
- **`dashboard.go`** — redact v3 user passphrases in `/api/config` (as community is
  already redacted).
- **`engine.go`** — generate/resolve the engineID at SNMP start.

## 4. Configuration

```jsonc
"snmp": {
  // ...existing v1/v2c fields...
  "v3_enabled": true,
  "allow_v1v2c": true,            // false = v3-only while v3_enabled
  "engine_id": "",                // hex string; blank = auto-generate (RFC 3411)
  "users": [
    {
      "name": "admin",
      "level": "authPriv",        // noAuthNoPriv | authNoPriv | authPriv
      "auth_protocol": "SHA-256", // MD5 | SHA-1 | SHA-256 | SHA-512
      "auth_pass": "secretauth",
      "priv_protocol": "AES-128", // DES | AES-128 | AES-192 | AES-256
      "priv_pass": "secretpriv"
    }
  ]
}
```

User struct:

```go
type SNMPUser struct {
    Name         string `json:"name"`
    Level        string `json:"level"`
    AuthProtocol string `json:"auth_protocol"`
    AuthPass     string `json:"auth_pass"`
    PrivProtocol string `json:"priv_protocol"`
    PrivPass     string `json:"priv_pass"`
}
```

**Validation at load (non-fatal):** unknown level/protocol or a `authPriv` user
missing a passphrase logs a `warn` and disables that user. `auth_pass`/`priv_pass`
are **secrets** — redacted from `/api/config`.

## 5. Engine identity & discovery

- **engineID:** if `engine_id` is blank, generate an RFC 3411 conformant ID:
  `0x80000000` | enterprise-number, format byte `0x05` (text) or an octet variant,
  followed by a per-host value (hash of hostname + a random nibble). Stored for the
  process lifetime.
- **engineBoots = 1** per process run; **engineTime** = seconds since SNMP start.
- **Discovery:** a request with an empty `msgAuthoritativeEngineID` (the standard
  discovery probe) is answered with a **Report PDU** carrying
  `usmStatsUnknownEngineIDs.0` and the agent's engineID/boots/time, so managers
  learn the engine before sending an authed request.
- **Time window:** reject authed messages whose engineTime differs by more than
  ±150 s (replay protection), responding with `usmStatsNotInTimeWindows` when
  authenticated.

## 6. USM crypto (`usm.go`)

- **Key localization (RFC 3414 §2.6):** expand the passphrase to a 1 MiB stream,
  hash it (`Ku`), then localize: `Kul = H(Ku || engineID || Ku)`. Implemented per
  hash (MD5/SHA-1/SHA-256/SHA-512) using `crypto/*`.
- **Auth (HMAC, truncated):** HMAC over the whole message with the auth-parameters
  field zeroed, truncated to the protocol's length — **12 bytes** for MD5 & SHA-1,
  **24 bytes** for SHA-256 (usmHMAC192SHA256), **48 bytes** for SHA-512
  (usmHMAC384SHA512). On a request, recompute and compare in constant time
  (`hmac.Equal`); on a response, insert the computed value.
- **Priv:**
  - **DES-CBC (RFC 3414):** DES key = first 8 bytes of the localized key; pre-IV =
    next 8; salt = 8-byte msgPrivacyParameters; IV = pre-IV XOR salt.
  - **AES-CFB-128 (RFC 3826):** key = first 16 bytes of the localized key; IV =
    engineBoots(4) ‖ engineTime(4) ‖ 8-byte salt.
  - **AES-192/256 (Blumenthal):** extend the localized key by repeated
    localization to 24/32 bytes; same CFB IV construction.
  - The scoped PDU is the encrypted payload; decrypt on request, encrypt the
    response with a fresh salt (a per-message counter).

## 7. Message flow

1. Parse outer SEQUENCE → version. v3 → continue.
2. Parse `msgGlobalData` (msgID, maxSize, flags = `reportable|priv|auth`,
   securityModel = 3) and `msgSecurityParameters` (engineID, boots, time, userName,
   authParams, privParams).
3. **Discovery** (empty engineID or unknown user) → Report PDU.
4. Look up the user; enforce the requested security level ≤ the user's configured
   level. If `auth` flag: verify HMAC; reject → `usmStatsWrongDigests` report.
   Check time window.
5. If `priv` flag: decrypt the scoped PDU.
6. Parse the scoped PDU's PDU (Get/GetNext/GetBulk) and serve it from the **shared
   MIB** exactly as v1/v2c does.
7. Build the response scoped PDU; encrypt (if priv) with a fresh salt; compute auth
   (if auth) over the assembled message; send.

## 8. Logging

Component `[SNMP]` (reuse): `info` v3 user authenticated + level; `warn` auth
failure, time-window rejection, unknown user, disabled user at load; `debug`
discovery responses; `trace` per-OID (shared with v1/v2c). Never log passphrases
or keys.

## 9. Testing

- **Key localization (RFC 3414 Appendix A.3 vectors):** password `"maplesyrup"`,
  engineID `0x000000000000000000000002`, assert the exact localized MD5 key
  (`52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b`) and SHA-1 key
  (`66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f`).
- **HMAC truncation lengths** per protocol (12/12/24/48) verified.
- **Priv round-trip:** DES-CBC and AES-CFB-128/192/256 encrypt→decrypt returns the
  original scoped PDU; IV construction matches the spec for a known salt.
- **Message parse/build round-trip:** build a v3 authPriv message, parse it back,
  fields intact.
- **Dispatch:** a v1/v2c packet still works; a v3 discovery probe returns a Report
  with the engineID; with `allow_v1v2c:false`, v2c is dropped.
- **Self integration:** craft an authPriv Get for `sysDescr.0` against the handler
  with a configured user; assert the response decrypts and carries the value.
- **Redaction:** `/api/config` shows `auth_pass`/`priv_pass` as `***`.

## 10. Acceptance criteria

1. `snmpget -v3 -l authPriv -u admin -a SHA-256 -A secretauth -x AES -X secretpriv
   <host> 1.3.6.1.2.1.1.1.0` (net-snmp) returns `sysDescr` over an encrypted,
   authenticated exchange (manual acceptance), including the discovery round trip.
2. `authNoPriv` and `noAuthNoPriv` users work at their levels; a user may not
   exceed its configured level.
3. Wrong passphrase → request rejected (no MIB data leaked); a replayed/old message
   is rejected by the time window.
4. v1/v2c still works with `allow_v1v2c:true`; v3-only with `false`.
5. `/api/config` never exposes v3 passphrases.
6. No new module dependency (stdlib `crypto/*` only); `go vet` clean.
```
