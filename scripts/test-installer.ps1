param([string]$Installer, [switch]$Elevated)
# Installer acceptance: silent install into a Chinese path, upgrade over it,
# uninstall. Checks the service, the preserved configuration and cleanup.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Installer) {
    $Installer = Get-ChildItem (Join-Path $root 'target/installer/stemma-*-setup.exe') |
        Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
}
$out = Join-Path $root 'target/installer-test'
New-Item -ItemType Directory -Force $out | Out-Null
$log = Join-Path $out 'test.log'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) { throw 'Elevation did not provide administrator rights' }
    Remove-Item -LiteralPath $log -ErrorAction SilentlyContinue
    $child = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Installer', "`"$Installer`"", '-Elevated')
    Get-Content -LiteralPath $log -Encoding utf8
    exit $child.ExitCode
}

function Say([string]$Text) { $Text | Out-File -LiteralPath $log -Append -Encoding utf8 }
function Setup([string[]]$Arguments) {
    $p = Start-Process -FilePath $Installer -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "setup $Arguments exited with $($p.ExitCode)" }
}
function Service { Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'" }

$dir = Join-Path $env:ProgramFiles 'Stemma 安装测试'
$data = Join-Path $env:ProgramData 'Stemma'
$code = 1
$config = Join-Path $data 'config.json'
$originalConfig = $null
$originalBackup = $null
$injectedJournal = $false
try {
    if (Service) { throw 'A Stemma service is already installed; not replacing it' }
    if (Test-Path -LiteralPath (Join-Path $data 'state\dns-journal.json')) { throw 'An existing DNS recovery journal needs attention; not replacing it' }
    if (Test-Path -LiteralPath $config) { $originalConfig = [IO.File]::ReadAllBytes($config) }
    if (Test-Path -LiteralPath ($config + '.bak')) { $originalBackup = [IO.File]::ReadAllBytes($config + '.bak') }
    Setup -Arguments @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$dir`"", "/LOG=`"$out\install.log`"", '/TASKS=')
    $service = Service
    if (-not $service -or $service.State -ne 'Running') { throw 'service is not running after install' }
    if (-not $service.PathName.StartsWith("`"$dir\stemma-engine.exe`"")) { throw "service path is $($service.PathName)" }
    foreach ($file in 'stemma.exe', 'stemma-engine.exe', 'WinDivert.dll', 'WinDivert64.sys', 'licenses\WinDivert.txt', 'licenses\DEPENDENCY_LICENSES.txt') {
        if (-not (Test-Path -LiteralPath (Join-Path $dir $file))) { throw "missing $file" }
    }
    $status = & (Join-Path $dir 'stemma-engine.exe') status | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'status command failed' }
    if ($status.data.engaged) { throw 'service must start idle' }
    Say 'PASS install into a Chinese path; service running and idle'

    $config = Join-Path $data 'config.json'
    $json = Get-Content -Raw $config | ConvertFrom-Json
    $json.proxy_groups[0].port = 17999
    $edited = Join-Path $out 'edited.json'
    [IO.File]::WriteAllText($edited, ($json | ConvertTo-Json -Depth 20))
    & (Join-Path $dir 'stemma-engine.exe') set-config --config $edited | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'set-config command failed' }
    Setup -Arguments @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$dir`"", "/LOG=`"$out\upgrade.log`"", '/TASKS=')
    if ((Service).State -ne 'Running') { throw 'service is not running after upgrade' }
    if ((Get-Content -Raw $config | ConvertFrom-Json).proxy_groups[0].port -ne 17999) { throw 'upgrade lost the configuration' }
    Say 'PASS upgrade kept the configuration and restarted the service'

    $uninstaller = Join-Path $dir 'unins000.exe'
    & (Join-Path $dir 'stemma-engine.exe') stop
    if ($LASTEXITCODE -ne 0) { throw 'cannot stop before recovery test' }
    $stateDir = Join-Path $data 'state'
    New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
    $journal = Join-Path $stateDir 'dns-journal.json'
    [IO.File]::WriteAllText($journal, 'intentionally invalid recovery test')
    $injectedJournal = $true
    $rejected = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$out\rejected-uninstall.log`"") -Wait -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2
    if (-not (Service) -or -not (Test-Path -LiteralPath $journal) -or -not (Test-Path -LiteralPath (Join-Path $dir 'stemma-engine.exe'))) {
        throw 'failed DNS recovery did not preserve service and recovery files'
    }
    Say 'PASS corrupt recovery journal blocks uninstall and preserves service and files'
    Remove-Item -LiteralPath $journal
    $injectedJournal = $false
    $p = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$out\uninstall.log`"") -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "uninstall exited with $($p.ExitCode)" }
    # The uninstaller copies itself and returns before it finishes.
    $deadline = (Get-Date).AddSeconds(60)
    while ((Test-Path -LiteralPath $uninstaller) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Service) { throw 'service still exists after uninstall' }
    if (Test-Path (Join-Path $data 'state\dns-journal.json')) { throw 'DNS journal left behind' }
    if (Test-Path (Join-Path $data 'logs')) { throw 'engine logs left behind' }
    $left = Get-ChildItem -LiteralPath $dir -Recurse -ErrorAction SilentlyContinue | Where-Object Name -ne 'WinDivert64.sys'
    if ($left) { throw "left in the install directory: $($left.Name -join ', ')" }
    if (-not (Test-Path $config)) { throw 'uninstall removed the configuration' }
    if (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Stemma -ErrorAction SilentlyContinue) { throw 'logon entry left behind' }
    Say 'PASS uninstall removed the service and program files and kept the configuration'
    $code = 0
} catch {
    Say "FAIL $_"
} finally {
    if ($injectedJournal -and (Test-Path -LiteralPath $journal)) {
        if ([IO.File]::ReadAllText($journal) -eq 'intentionally invalid recovery test') {
            Remove-Item -LiteralPath $journal
        }
    }
    if (-not (Service)) {
        if ($null -ne $originalConfig) { [IO.File]::WriteAllBytes($config, $originalConfig) }
        if ($null -ne $originalBackup) { [IO.File]::WriteAllBytes($config + '.bak', $originalBackup) }
    }
}
exit $code
