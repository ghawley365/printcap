# assets

Optional build assets for the Windows resource (`.syso`) embedded into
`printcap.exe`.

## printcap.ico

Drop a real Windows `.ico` here named **`printcap.ico`** and regenerate the
resource (see below) to embed it as the application + tray icon. The GUI loads
the embedded icon first (`walk.NewIconFromResourceId(2)`); if no `.ico` is
embedded it falls back to a generic printer glyph from `imageres.dll`, so the
icon is entirely optional.

A good `printcap.ico` contains multiple sizes (16, 32, 48, 256 px) for crisp
rendering in the tray, taskbar, and Add/Remove Programs.

## Regenerating the resource

`versioninfo.json` (in the repo root) references `assets/printcap.ico` via
`IconPath`. To embed the icon + PE version info + the existing manifest:

```bat
go run github.com/josephspurrier/goversioninfo/cmd/goversioninfo@latest ^
  -manifest printcap.manifest -o rsrc_windows_amd64.syso
```

This replaces the committed `rsrc_windows_amd64.syso`. See `build.bat` for the
full build flow. `goversioninfo` is a build-time external tool only — it is NOT
a Go module dependency of printcap.
