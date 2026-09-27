# Downloads WinDivert (hash-pinned) into third_party/windivert.
# WinDivert is LGPL-3.0 / GPL-2.0; it is shipped as separate, unmodified files.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'third_party/windivert'
$version = '2.2.2'
$sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

if (Test-Path (Join-Path $target 'WinDivert64.sys')) {
    Write-Host "WinDivert is already in $target"
    exit 0
}
$zip = Join-Path ([IO.Path]::GetTempPath()) "WinDivert-$version-A.zip"
$download = @{
    Uri             = "https://github.com/basil00/WinDivert/releases/download/v$version/WinDivert-$version-A.zip"
    OutFile         = $zip
    UseBasicParsing = $true
}
if ($env:HTTPS_PROXY) { $download.Proxy = $env:HTTPS_PROXY }
Invoke-WebRequest @download
if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $sha256) {
    throw 'WinDivert checksum mismatch'
}
$extract = Join-Path ([IO.Path]::GetTempPath()) "WinDivert-$version-extract"
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
$source = Join-Path $extract "WinDivert-$version-A"
New-Item -ItemType Directory -Force $target | Out-Null
Copy-Item (Join-Path $source 'x64/WinDivert.dll'), (Join-Path $source 'x64/WinDivert64.sys'), (Join-Path $source 'LICENSE') $target
Write-Host "WinDivert $version installed to $target"
