param(
    [switch]$Release,
    [switch]$IPv6,
    [switch]$SkipBuild,
    [switch]$Elevated,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $root ("target\e2e-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $SkipBuild) {
    Push-Location $root
    try {
        $arguments = @('build', '--workspace')
        if ($Release) { $arguments += '--release' }
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Cargo build failed' }
    } finally {
        Pop-Location
    }
}

if (-not $admin) {
    if ($Elevated) { throw 'Elevation did not provide administrator rights' }
    $arguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"", '-SkipBuild', '-Elevated',
        '-OutputDirectory', "`"$OutputDirectory`""
    )
    if ($Release) { $arguments += '-Release' }
    if ($IPv6) { $arguments += '-IPv6' }
    $child = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden `
        -ArgumentList $arguments -PassThru -Wait
    $log = Join-Path $OutputDirectory 'acceptance.log'
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
    exit $child.ExitCode
}

$profile = if ($Release) { 'release' } else { 'debug' }
$program = Join-Path $root "target\$profile\stemma-e2e.exe"
$engine = Join-Path $root "target\$profile\stemma-engine.exe"
$divert = Join-Path $root 'third_party\windivert'
Push-Location $root
try {
    $arguments = @('run', '--engine', $engine, '--windivert-dir', $divert)
    if ($IPv6) { $arguments += '--ipv6' }
    & $program @arguments 2>&1 |
        Tee-Object -FilePath (Join-Path $OutputDirectory 'acceptance.log')
    $code = $LASTEXITCODE
    Write-Host "Acceptance log: $OutputDirectory"
    exit $code
} finally {
    Pop-Location
}
