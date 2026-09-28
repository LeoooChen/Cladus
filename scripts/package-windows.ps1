param([string]$Version)
# Builds the release binaries and the Stemma installer.
# Output: target/installer/stemma-<version>-windows-x64-setup.exe
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $Version) {
    $Version = ([regex]'(?ms)\[workspace\.package\].*?^version\s*=\s*"([^"]+)"').Match(
        (Get-Content -Raw (Join-Path $root 'Cargo.toml'))).Groups[1].Value
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'Version must be MAJOR.MINOR.PATCH' }
$deps = Join-Path $root 'target/installer-dependencies'
New-Item -ItemType Directory -Force $deps | Out-Null

function Get-Dependency($Url, $Name, $Hash = '') {
    $file = Join-Path $deps $Name
    if (-not (Test-Path -LiteralPath $file)) {
        $download = @{ Uri = $Url; OutFile = $file; UseBasicParsing = $true }
        if ($env:HTTPS_PROXY) { $download.Proxy = $env:HTTPS_PROXY }
        Invoke-WebRequest @download
    }
    if ($Hash) {
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $Hash) { throw "Checksum mismatch: $Name" }
    } else {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw "Invalid Microsoft signature: $Name"
        }
    }
    return $file
}

Push-Location $root
try {
    & (Join-Path $PSScriptRoot 'bootstrap-windows.ps1')
    Push-Location 'apps/stemma-gui'
    try {
        & npm ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        & npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed' }
    } finally { Pop-Location }
    & cargo build --release --locked -p stemma-engine -p stemma-gui
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed' }
    & node (Join-Path $PSScriptRoot 'package-licenses.mjs')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency license collection failed' }

    # Pinned compiler, verified before it runs.
    $innoSetup = Get-Dependency 'https://github.com/jrsoftware/issrc/releases/download/is-6_4_3/innosetup-6.4.3.exe' 'innosetup-6.4.3.exe' 'F3C42116542C4CC57263C5BA6C4FEABFC49FE771F2F98A79D2F7628B8762723B'
    $innoDir = Join-Path $deps 'InnoSetup'
    $compiler = Join-Path $innoDir 'ISCC.exe'
    if (-not (Test-Path -LiteralPath $compiler)) {
        $process = Start-Process -FilePath $innoSetup -Wait -PassThru -WindowStyle Hidden -ArgumentList @(
            '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/NOICONS', "/DIR=`"$innoDir`"")
        if ($process.ExitCode -ne 0) { throw "Inno Setup installation failed: $($process.ExitCode)" }
    }
    Get-Dependency 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' 'MicrosoftEdgeWebview2Setup.exe' | Out-Null
    & $compiler "/DAppVersion=$Version" (Join-Path $root 'installer/stemma.iss')
    if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed: $LASTEXITCODE" }
    $installer = Join-Path $root "target/installer/stemma-$Version-windows-x64-setup.exe"
    $checksum = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $root 'target/installer/SHA256SUMS'), "$checksum  $([IO.Path]::GetFileName($installer))`n")
    Write-Host "Installer: target/installer/stemma-$Version-windows-x64-setup.exe"
} finally {
    Pop-Location
}
