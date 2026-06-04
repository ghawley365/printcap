@echo off
REM Build the self-contained printcap.exe (GUI + service + capture) for 64-bit
REM Windows. Requires Go (https://go.dev/dl/). No other runtime dependencies.
REM
REM Usage:
REM   build.bat                 build with the default version below
REM   set VERSION=1.2.3 ^& build.bat   build and stamp that version
setlocal

REM ---------------------------------------------------------------------------
REM Version. Override by setting VERSION before calling, e.g.:
REM   set VERSION=1.2.3
REM Keep this in sync with versioninfo.json (PE FileVersion/ProductVersion) and
REM installer\printcap.iss (#define MyVersion).
REM ---------------------------------------------------------------------------
if "%VERSION%"=="" set VERSION=1.0.0

set GOOS=windows
set GOARCH=amd64

REM ---------------------------------------------------------------------------
REM Embedded Windows resource (rsrc_windows_amd64.syso): application manifest +
REM PE VersionInfo + optional icon. The committed .syso is built from
REM printcap.manifest with the akavel/rsrc tool. To ALSO embed PE version info
REM and an app icon (assets\printcap.ico), regenerate it with goversioninfo —
REM which reads versioninfo.json (it references printcap.manifest and the icon):
REM
REM   go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest ^
REM     -manifest printcap.manifest -o rsrc_windows_amd64.syso
REM
REM That command REPLACES the current rsrc-generated .syso. goversioninfo is a
REM build-time external tool only; it is NOT a Go module dependency of printcap.
REM (If you only changed printcap.manifest and don't need version info/icon:
REM   go run github.com/akavel/rsrc@latest -manifest printcap.manifest -arch amd64 -o rsrc_windows_amd64.syso )
REM ---------------------------------------------------------------------------

REM -H windowsgui : no console window when the GUI launches
REM -s -w         : strip debug info to shrink the binary
REM -X main.version : stamp the build version reported by -version and the GUI
go build -ldflags="-s -w -H windowsgui -X main.version=%VERSION%" -o printcap.exe .
if %ERRORLEVEL% NEQ 0 (
  echo Build failed.
  exit /b %ERRORLEVEL%
)
echo Built printcap.exe (version %VERSION%)

REM ---------------------------------------------------------------------------
REM Optional Authenticode signing. Enabled only when a signing cert is provided
REM via either SIGN_PFX (path to a .pfx, plus SIGN_PFX_PASSWORD) or SIGN_CERT
REM (subject name of a cert in the Windows store). Skipped otherwise.
REM ---------------------------------------------------------------------------
if not "%SIGN_PFX%"=="" (
  echo Signing printcap.exe with %SIGN_PFX% ...
  signtool sign /fd SHA256 /f "%SIGN_PFX%" /p "%SIGN_PFX_PASSWORD%" ^
    /tr http://timestamp.digicert.com /td SHA256 ^
    /d "printcap - network print capture" printcap.exe
  if %ERRORLEVEL% NEQ 0 ( echo Signing failed. & exit /b %ERRORLEVEL% )
) else if not "%SIGN_CERT%"=="" (
  echo Signing printcap.exe with store cert "%SIGN_CERT%" ...
  signtool sign /fd SHA256 /n "%SIGN_CERT%" ^
    /tr http://timestamp.digicert.com /td SHA256 ^
    /d "printcap - network print capture" printcap.exe
  if %ERRORLEVEL% NEQ 0 ( echo Signing failed. & exit /b %ERRORLEVEL% )
)
