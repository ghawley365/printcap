@echo off
REM Build the self-contained printcap.exe (GUI + service + capture) for 64-bit
REM Windows. Requires Go (https://go.dev/dl/). No other runtime dependencies.
REM
REM The embedded application manifest (rsrc_windows_amd64.syso) is committed to
REM the repo; regenerate it only if you change printcap.manifest:
REM   go run github.com/akavel/rsrc@latest -manifest printcap.manifest -arch amd64 -o rsrc_windows_amd64.syso
setlocal
set GOOS=windows
set GOARCH=amd64

REM -H windowsgui : no console window when the GUI launches
REM -s -w         : strip debug info to shrink the binary
go build -ldflags="-s -w -H windowsgui" -o printcap.exe .
if %ERRORLEVEL% NEQ 0 (
  echo Build failed.
  exit /b %ERRORLEVEL%
)
echo Built printcap.exe
