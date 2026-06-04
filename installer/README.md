# Building the printcap Windows installer

`printcap.iss` is an [Inno Setup](https://jrsoftware.org/isinfo.php) script that
packages the single self-contained `printcap.exe` into a standard Windows
installer (`printcap-<version>-setup.exe`). No Windows is required to *author*
the script; you do need a Windows build machine to *compile* it.

## Prerequisites

1. **Build `printcap.exe` first.** From the repository root, on Windows:

   ```bat
   set VERSION=1.0.0
   build.bat
   ```

   This produces `printcap.exe` in the repo root. The installer script references
   it as `..\printcap.exe`.

2. **Install Inno Setup 6+** (https://jrsoftware.org/isdl.php). The compiler
   `iscc.exe` is installed under `C:\Program Files (x86)\Inno Setup 6\`.

## Build the installer

```bat
cd installer
set "VERSION=1.0.0"
iscc printcap.iss
```

Update the version in **two** places so they match:

- `versioninfo.json` / `build.bat` `VERSION` — embeds the PE FileVersion and
  `main.version` into the exe.
- `#define MyVersion "1.0.0"` near the top of `printcap.iss` — the installer's
  display version and output filename.

The compiled installer is written to `installer\Output\printcap-<version>-setup.exe`
(Inno's default `Output` subfolder).

## What the installer does

- Installs `printcap.exe` (plus the sample config and docs, if present) into
  `C:\Program Files\printcap` (`{autopf}\printcap`).
- Creates a Start Menu shortcut, and an **optional** Desktop shortcut (task).
- Offers two **optional** Windows-integration tasks (both unchecked by default):
  - **Install and start the Windows service** — runs
    `printcap.exe -service install` then `-service start`.
  - **Add Windows Firewall rules** — runs `printcap.exe -firewall add`, which
    adds one inbound allow rule per configured listener port.
- Optionally launches the tray GUI when setup finishes.
- Requests Administrator privileges (`PrivilegesRequired=admin`) — required for
  Program Files, the service, the Event Log source, and firewall rules.

### Uninstall

The uninstaller runs **before** removing files so the exe can clean up after
itself:

- `printcap.exe -service stop`
- `printcap.exe -service remove` (also deregisters the Event Log source)
- `printcap.exe -firewall remove` (deletes the per-port + legacy firewall rules)

The uninstaller **does not** delete captured documents, the spool/retry queue, or
`printcap.json`. That is the operator's data and is intentionally left in place;
remove it manually if you want a clean wipe.

## Code signing (recommended for distribution)

Sign **both** the application exe and the finished installer with your
organization's Authenticode certificate so Windows SmartScreen and Defender
trust them. These commands are gated on the cert being available — skip them if
you do not have a signing cert.

Sign the exe **before** compiling the installer (so the bundled exe is signed),
then sign the installer afterward:

```bat
REM 1. Sign printcap.exe (after build.bat, before iscc)
signtool sign /fd SHA256 /f "%SIGN_PFX%" /p "%SIGN_PFX_PASSWORD%" ^
  /tr http://timestamp.digicert.com /td SHA256 ^
  /d "printcap — network print capture" ..\printcap.exe

REM 2. Compile the installer
iscc printcap.iss

REM 3. Sign the installer
signtool sign /fd SHA256 /f "%SIGN_PFX%" /p "%SIGN_PFX_PASSWORD%" ^
  /tr http://timestamp.digicert.com /td SHA256 ^
  /d "printcap setup" Output\printcap-1.0.0-setup.exe
```

If your cert lives in the Windows certificate store instead of a `.pfx`, use
`/n "Your Org, Inc."` (subject name) or `/sha1 <thumbprint>` in place of
`/f ... /p ...`.

Inno Setup can also sign automatically via a configured **Sign Tool** (Tools →
Configure Sign Tools) referenced by a `SignTool=` directive — see the Inno Setup
docs if you prefer to sign as part of `iscc`.
