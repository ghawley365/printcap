; printcap — Inno Setup installer script
; -----------------------------------------------------------------------------
; Build with Inno Setup 6+ on a Windows machine:
;     iscc printcap.iss
; See installer/README.md for the full build + code-signing instructions.
;
; Update MyVersion to match the build (it should equal the value passed to
; build.bat as VERSION / -X main.version). The installer expects a freshly
; built ..\printcap.exe to exist (run build.bat first).

#define MyAppName "printcap"
#define MyAppPublisher "printcap"
#define MyVersion "1.0.0"
#define MyAppExeName "printcap.exe"

[Setup]
AppId={{8F3B7A2E-5C1D-4E9A-9B6F-printcap0001}
AppName={#MyAppName}
AppVersion={#MyVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#MyAppName} {#MyVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputBaseFilename=printcap-{#MyVersion}-setup
Compression=lzma2/max
SolidCompression=yes
; printcap installs into Program Files, manages a Windows service, writes to the
; Event Log, and adds firewall rules — all of which require Administrator.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "installservice"; Description: "Install and start the Windows service (runs unattended at boot)"; GroupDescription: "Windows integration:"; Flags: unchecked
Name: "firewall"; Description: "Add Windows Firewall rules for the configured listener ports"; GroupDescription: "Windows integration:"; Flags: unchecked

[Files]
; The build produces ..\printcap.exe (relative to this script). Run build.bat first.
Source: "..\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Ship the sample config and docs alongside the exe (optional but helpful).
Source: "..\printcap.sample.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\ADMIN_GUIDE.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Install + start the Windows service if the operator opted in.
Filename: "{app}\{#MyAppExeName}"; Parameters: "-service install"; Flags: runascurrentuser runhidden waituntilterminated; Tasks: installservice; StatusMsg: "Installing the printcap service..."
Filename: "{app}\{#MyAppExeName}"; Parameters: "-service start"; Flags: runascurrentuser runhidden waituntilterminated; Tasks: installservice; StatusMsg: "Starting the printcap service..."
; Add per-port firewall rules if opted in.
Filename: "{app}\{#MyAppExeName}"; Parameters: "-firewall add"; Flags: runascurrentuser runhidden waituntilterminated; Tasks: firewall; StatusMsg: "Adding Windows Firewall rules..."
; Optional: launch the tray GUI at the end of setup.
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Run BEFORE files are removed so the exe is still present to clean up after
; itself: stop + remove the service (which also deregisters the Event Log
; source) and delete the firewall rules. Best-effort — failures are ignored so
; uninstall always proceeds.
Filename: "{app}\{#MyAppExeName}"; Parameters: "-service stop"; Flags: runhidden waituntilterminated runascurrentuser; RunOnceId: "StopSvc"
Filename: "{app}\{#MyAppExeName}"; Parameters: "-service remove"; Flags: runhidden waituntilterminated runascurrentuser; RunOnceId: "RemoveSvc"
Filename: "{app}\{#MyAppExeName}"; Parameters: "-firewall remove"; Flags: runhidden waituntilterminated runascurrentuser; RunOnceId: "RemoveFw"

; NOTE: We deliberately do NOT remove captured documents, the spool/retry queue,
; or printcap.json on uninstall — that is the operator's data. Those live next to
; the exe (or wherever OutDir/SpoolDir point) and are left in place.
