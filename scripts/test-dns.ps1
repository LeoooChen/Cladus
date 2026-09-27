param([string]$OutDir, [int]$ProxyPort = 7897, [switch]$Elevated)
# DNS acceptance through the real service: redirect, resolve through the
# proxy, kill the service, let SCM restart it, verify the exact restore.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root ("target\dns-test-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$OutDir = [IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir 'dns-test.log'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($Elevated) { throw 'Elevation did not provide administrator rights' }
    $child = Start-Process powershell.exe -Verb RunAs -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"",
        '-OutDir', "`"$OutDir`"", '-ProxyPort', $ProxyPort, '-Elevated')
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
    exit $child.ExitCode
}

function Say([string]$Text) { $Text | Out-File -LiteralPath $log -Append -Encoding utf8 }
function Snapshot {
    $keys = 'Tcpip', 'Tcpip6' | ForEach-Object {
        Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\$_\Parameters\Interfaces" |
            ForEach-Object { "$_ NameServer=[$((Get-ItemProperty -LiteralPath $_.PSPath).NameServer)]" }
    }
    ($keys | Sort-Object) -join "`n"
}
function Client([string[]]$Arguments) {
    $output = & $exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "stemma-engine $Arguments failed: $output" }
    ($output -join "`n") | ConvertFrom-Json
}
function Wait-Until([scriptblock]$Condition, [string]$What) {
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (& $Condition)) {
        if ((Get-Date) -gt $deadline) { throw "timed out waiting for $What" }
        Start-Sleep -Milliseconds 250
    }
}

if (Get-Service -Name StemmaEngine -ErrorAction SilentlyContinue) { throw 'A Stemma service already exists; not replacing it' }
$exe = Join-Path $OutDir 'stemma-engine.exe'
Copy-Item (Join-Path $root 'target\debug\stemma-engine.exe') $exe
$divert = Join-Path $root 'third_party\windivert'
$data = Join-Path $env:ProgramData ('Stemma-dns-test-' + (Split-Path -Leaf $OutDir))
$journal = Join-Path $data 'state\dns-journal.json'
$code = 1
$before = Snapshot
try {
    & $exe install --data-dir $data --windivert-dir $divert --allow-clew 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8
    & $exe start 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8
    Wait-Until { (Get-Service StemmaEngine).Status -eq 'Running' } 'service start'
    Start-Sleep -Milliseconds 500
    $config = (Client @('get-config')).data
    $config.proxy_groups[0].port = $ProxyPort
    $config.dns.enabled = $true
    $file = Join-Path $OutDir 'config.json'
    [IO.File]::WriteAllText($file, ($config | ConvertTo-Json -Depth 20))
    Client @('set-config', '--config', $file) | Out-Null
    Client @('engage') | Out-Null
    if (-not (Test-Path $journal)) { throw 'no DNS journal while redirected' }
    $redirected = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses -contains '127.0.0.2' }
    if (-not $redirected) { throw 'no interface points at 127.0.0.2' }
    Say "PASS redirected: $(($redirected.InterfaceAlias) -join ', ')"
    $udp = Resolve-DnsName -Name example.com -Type A -Server 127.0.0.2 -DnsOnly -QuickTimeout
    $tcp = Resolve-DnsName -Name example.org -Type A -Server 127.0.0.2 -DnsOnly -TcpOnly
    Say "PASS forwarder UDP $($udp[0].IPAddress) TCP $($tcp[0].IPAddress)"
    Clear-DnsClientCache
    $system = Resolve-DnsName -Name www.wikipedia.org -DnsOnly
    Say "PASS system resolver answered $($system.Count) records"
    $counters = (Client @('status')).data.counters
    if ($counters.'dns.proxied' -lt 3) { throw "expected proxied DNS answers, counters: $($counters | ConvertTo-Json)" }
    Say "PASS dns.proxied=$($counters.'dns.proxied') dns.fallback=$($counters.'dns.fallback')"
    Client @('disengage') | Out-Null
    if (Test-Path $journal) { throw 'journal remains after disengage' }
    if ((Snapshot) -ne $before) { throw 'DNS differs after disengage' }
    Say 'PASS disengage restored DNS exactly'
    Client @('engage') | Out-Null
    $old = (Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'").ProcessId
    Stop-Process -Id $old -Force
    Wait-Until {
        $s = Get-CimInstance Win32_Service -Filter "Name='StemmaEngine'"
        $s.State -eq 'Running' -and $s.ProcessId -ne $old -and -not (Test-Path $journal)
    } 'SCM restart and journal recovery'
    $after = Snapshot
    if ($after -ne $before) { Say "BEFORE`n$before`nAFTER`n$after"; throw 'DNS settings differ after crash recovery' }
    Say 'PASS killed service was restarted by SCM and restored DNS exactly'
    $code = 0
} catch {
    Say "FAIL $_"
} finally {
    if (Get-Service -Name StemmaEngine -ErrorAction SilentlyContinue) { & $exe uninstall 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8 }
    if (Test-Path $journal) { & $exe restore-dns --data-dir $data 2>&1 | Out-File -LiteralPath $log -Append -Encoding utf8 }
    if ((Snapshot) -ne $before) { Say 'WARNING system DNS differs from the start of the test' }
    Say "service logs: $data\logs"
}
exit $code
