param(
    [ValidateSet('Run', 'Setup', 'Crash', 'Cleanup')]
    [string]$Phase = 'Run',
    [string]$TestDirectory,
    [string]$DataDirectory
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $TestDirectory) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $TestDirectory = Join-Path $root "target\service-test-$stamp"
    $DataDirectory = Join-Path $env:ProgramData "Stemma-test-$stamp"
}
$exe = Join-Path $TestDirectory 'stemma-engine.exe'
$log = Join-Path $TestDirectory "$Phase.log"
New-Item -ItemType Directory -Path $TestDirectory -Force | Out-Null

function Invoke-AdminPhase([string]$Action) {
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-Phase', $Action, '-TestDirectory', "`"$TestDirectory`"",
        '-DataDirectory', "`"$DataDirectory`""
    )
    $process = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden `
        -ArgumentList $arguments -Wait -PassThru
    $phaseLog = Join-Path $TestDirectory "$Action.log"
    if (Test-Path -LiteralPath $phaseLog) { Get-Content -LiteralPath $phaseLog }
    if ($process.ExitCode -ne 0) { throw "$Action failed ($($process.ExitCode))" }
}

function Invoke-Client([string[]]$Arguments) {
    $output = & $exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Client command failed: $Arguments" }
    return ($output | ConvertFrom-Json)
}

if ($Phase -ne 'Run') {
    try {
        switch ($Phase) {
            'Setup' {
                if (Get-Service -Name StemmaEngine -ErrorAction SilentlyContinue) {
                    throw 'A Stemma service already exists; this test will not replace it.'
                }
                Copy-Item -LiteralPath (Join-Path $root 'target\debug\stemma-engine.exe') -Destination $exe
                & $exe install --data-dir $DataDirectory --windivert-dir (Join-Path $root 'third_party\windivert') >> $log 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'Service installation failed' }
                & $exe start >> $log 2>&1
                if ($LASTEXITCODE -ne 0) { throw 'Service startup failed' }
                'Setup passed' | Out-File -LiteralPath $log -Append
            }
            'Crash' {
                $service = Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'"
                $process = Get-Process -Id $service.ProcessId
                if ($process.Path -ne $exe) { throw 'Refusing to kill an unrelated service process' }
                $oldId = $process.Id
                Stop-Process -Id $oldId -Force
                $deadline = (Get-Date).AddSeconds(25)
                do {
                    Start-Sleep -Milliseconds 250
                    $service = Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'"
                } while (($service.State -ne 'Running' -or $service.ProcessId -eq $oldId) -and (Get-Date) -lt $deadline)
                if ($service.State -ne 'Running' -or $service.ProcessId -eq $oldId) {
                    throw 'SCM did not restart the crashed service'
                }
                'Crash recovery passed' | Out-File -LiteralPath $log -Append
            }
            'Cleanup' {
                $service = Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'"
                if ($service -and ($service.PathName.StartsWith('"' + $exe + '"') -or $service.PathName.StartsWith($exe + ' '))) {
                    & $exe uninstall >> $log 2>&1
                    if ($LASTEXITCODE -ne 0) { throw 'Service uninstall failed' }
                    'Cleanup passed; test configuration and logs were retained.' | Out-File -LiteralPath $log -Append
                }
            }
        }
        exit 0
    } catch {
        $_ | Out-File -LiteralPath $log -Append
        exit 1
    }
}

Push-Location $root
try {
    & cargo build -p stemma-engine
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    Invoke-AdminPhase 'Setup'
    Start-Sleep -Milliseconds 500
    $state = Invoke-Client -Arguments @('status')
    if ($state.data.engaged) { throw 'Service must start idle' }
    Write-Host 'PASS authenticated IPC from the calling user without elevation'
    $config = (Invoke-Client -Arguments @('get-config')).data
    $config.proxy_groups[0].port = 17891
    $configuration = Join-Path $TestDirectory 'updated.json'
    [IO.File]::WriteAllText($configuration, ($config | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Invoke-Client -Arguments @('set-config', '--config', $configuration) | Out-Null
    if ((Invoke-Client -Arguments @('get-config')).data.proxy_groups[0].port -ne 17891) {
        throw 'Configuration did not update'
    }
    Write-Host 'PASS configuration update through IPC'
    Invoke-Client -Arguments @('disengage') | Out-Null
    Invoke-AdminPhase 'Crash'
    Start-Sleep -Milliseconds 500
    if ((Invoke-Client -Arguments @('get-config')).data.proxy_groups[0].port -ne 17891) {
        throw 'Configuration did not survive service restart'
    }
    Write-Host 'PASS configuration survived SCM crash recovery'
} finally {
    Invoke-AdminPhase 'Cleanup'
    Pop-Location
    Write-Host "Service test artifacts: $TestDirectory"
}
