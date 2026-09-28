; Stemma installer. Build with scripts/package-windows.ps1.
#ifndef AppVersion
  #error AppVersion must be supplied by scripts/package-windows.ps1
#endif
#define Root ".."
#define Bin Root + "\target\release"
#define Dependencies Root + "\target\installer-dependencies"

[Setup]
AppId={{773C5C77-A7AE-402D-AC63-19F8574CC2F3}
AppName=Stemma
AppVersion={#AppVersion}
AppPublisher=Stemma contributors
DefaultDirName={autopf}\Stemma
DefaultGroupName=Stemma
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
PrivilegesRequired=admin
OutputDir={#Root}\target\installer
OutputBaseFilename=stemma-{#AppVersion}-windows-x64-setup
SetupIconFile={#Root}\apps\stemma-gui\src-tauri\icons\icon.ico
UninstallDisplayIcon={app}\stemma.exe
LicenseFile={#Root}\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimp"; MessagesFile: "ChineseSimplified.isl"

[CustomMessages]
english.PrerequisiteError=Could not install %1 (error %2). Check your Internet connection and retry.
chinesesimp.PrerequisiteError=无法安装 %1（错误 %2）。请检查网络连接后重试。
english.ImportConfig=Import rules and proxy groups from a detected compatible configuration
chinesesimp.ImportConfig=从检测到的兼容配置中导入规则与代理组
english.RedirectorRunning=Another traffic redirector is running. Exit it before using Stemma to avoid conflicts.
chinesesimp.RedirectorRunning=另一个流量代理程序正在运行。请先退出该程序再使用 Stemma，以免发生冲突。
english.EngineFailed=The Stemma Engine service could not be set up (error %1).
chinesesimp.EngineFailed=无法安装 Stemma Engine 服务（错误 %1）。
english.RecoveryFailed=Stemma could not stop safely or restore DNS (error %1). Recovery files have been kept. Resolve the error and retry.
chinesesimp.RecoveryFailed=Stemma 无法安全停止或恢复 DNS（错误 %1）。恢复文件已保留，请解决错误后重试。

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "importclew"; Description: "{cm:ImportConfig}"; Check: CanImportClew

[Files]
Source: "{#Bin}\stemma.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Bin}\stemma-engine.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\third_party\windivert\WinDivert.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\third_party\windivert\WinDivert64.sys"; DestDir: "{app}"; Flags: ignoreversion restartreplace uninsrestartdelete
Source: "{#Root}\third_party\windivert\LICENSE"; DestDir: "{app}\licenses"; DestName: "WinDivert.txt"; Flags: ignoreversion
Source: "{#Root}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Root}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#Dependencies}\DEPENDENCY_LICENSES.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "{#Dependencies}\MicrosoftEdgeWebview2Setup.exe"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\Stemma"; Filename: "{app}\stemma.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\Stemma"; Filename: "{app}\stemma.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\stemma.exe"; Description: "{cm:LaunchProgram,Stemma}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\Stemma\logs"
Type: filesandordirs; Name: "{commonappdata}\Stemma\state"
Type: filesandordirs; Name: "{localappdata}\Stemma"

[Code]
const
  ClewUninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{B4030D7C-ED32-4DA1-936E-944411E77496}_is1';

function ClewConfigPath: String;
var Location: String;
begin
  Result := '';
  if RegQueryStringValue(HKLM64, ClewUninstallKey, 'InstallLocation', Location) or
     RegQueryStringValue(HKLM32, ClewUninstallKey, 'InstallLocation', Location) then
    if FileExists(AddBackslash(Location) + 'clew.json') then
      Result := AddBackslash(Location) + 'clew.json';
end;

// Offered on first installation only; an upgrade keeps Stemma's own settings.
function CanImportClew: Boolean;
begin
  Result := (ClewConfigPath <> '') and not FileExists(ExpandConstant('{commonappdata}\Stemma\config.json'));
end;

function HasWebView2: Boolean;
var Version: String;
begin
  Result := RegQueryStringValue(HKLM32, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
  Result := Result and (Version <> '') and (Version <> '0.0.0.0');
  if not Result then begin
    Result := RegQueryStringValue(HKCU, 'Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
    Result := Result and (Version <> '') and (Version <> '0.0.0.0');
  end;
end;

function RunHidden(FileName, Parameters: String): Integer;
begin
  if not Exec(FileName, Parameters, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var Code: Integer; Engine: String;
begin
  Result := '';
  // Use our bundled binary, not an executable planted in a custom directory.
  ExtractTemporaryFile('stemma-engine.exe');
  Engine := ExpandConstant('{tmp}\stemma-engine.exe');
  Code := RunHidden(Engine, 'secure-install-dir --path "' + ExpandConstant('{app}') + '"');
  if Code <> 0 then begin
    Result := FmtMessage(CustomMessage('EngineFailed'), [IntToStr(Code)]);
    Exit;
  end;
  Code := RunHidden(Engine, 'stop');
  if Code <> 0 then begin
    Result := FmtMessage(CustomMessage('RecoveryFailed'), [IntToStr(Code)]);
    Exit;
  end;
  if not HasWebView2 then begin
    ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
    Code := RunHidden(ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe'), '/silent /install');
    if Code <> 0 then
      Result := FmtMessage(CustomMessage('PrerequisiteError'), ['WebView2', IntToStr(Code)]);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var Engine: String; Code: Integer;
begin
  if CurStep = ssPostInstall then begin
    Engine := ExpandConstant('{app}\stemma-engine.exe');
    Code := RunHidden(Engine, 'install');
    if Code <> 0 then
      RaiseException(FmtMessage(CustomMessage('EngineFailed'), [IntToStr(Code)]));
    if WizardIsTaskSelected('importclew') then begin
      Code := RunHidden(Engine, 'import-config --from "' + ClewConfigPath + '"');
      if Code <> 0 then
        RaiseException(FmtMessage(CustomMessage('EngineFailed'), [IntToStr(Code)]));
    end;
    Code := RunHidden(Engine, 'start');
    if Code <> 0 then
      RaiseException(FmtMessage(CustomMessage('EngineFailed'), [IntToStr(Code)]));
    if CheckForMutexes('Global\Clew_SingleInstance') then
      SuppressibleMsgBox(CustomMessage('RedirectorRunning'), mbInformation, MB_OK, IDOK);
  end;
end;

function InitializeUninstall: Boolean;
var Code, Attempts: Integer;
begin
  Code := RunHidden(ExpandConstant('{app}\stemma-engine.exe'), 'uninstall');
  Result := Code = 0;
  if not Result then begin
    SuppressibleMsgBox(FmtMessage(CustomMessage('RecoveryFailed'), [IntToStr(Code)]), mbError, MB_OK, IDOK);
    Exit;
  end;
  // Only our own GUI is asked to quit; never kill by global image name.
  if CheckForMutexes('io.github.leooochen.stemma-sim') and
     FileExists(ExpandConstant('{app}\stemma.exe')) then begin
    RunHidden(ExpandConstant('{app}\stemma.exe'), '--quit');
    Attempts := 0;
    while CheckForMutexes('io.github.leooochen.stemma-sim') and (Attempts < 100) do begin
      Sleep(100);
      Attempts := Attempts + 1;
    end;
    Result := not CheckForMutexes('io.github.leooochen.stemma-sim');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Command: String;
begin
  // Remove the logon entry only when it belongs to this installation.
  if (CurUninstallStep = usUninstall) and
     RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Stemma', Command) and
     (Pos(Lowercase(ExpandConstant('{app}\stemma.exe')), Lowercase(Command)) > 0) then
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Stemma');
end;
