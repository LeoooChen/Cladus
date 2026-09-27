$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $metadata = & cargo metadata --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $packages = ($metadata | ConvertFrom-Json).packages
    foreach ($package in $packages) {
        if ($package.name -eq 'stemma-core') {
            $forbidden = $package.dependencies | Where-Object {
                $_.name -match '^(tokio|windows(-sys)?|stemma-platform-.+)$'
            }
        } elseif ($package.name -in @('stemma-engine', 'stemma-net', 'stemma-ipc')) {
            $forbidden = $package.dependencies | Where-Object { $_.name -match '^windows(-sys)?$' }
        } else {
            continue
        }
        if ($forbidden) {
            throw "$($package.name) has forbidden dependencies: $($forbidden.name -join ', ')"
        }
    }
    Write-Host 'Platform dependency boundaries passed.'
} finally {
    Pop-Location
}
