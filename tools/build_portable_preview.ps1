param(
    [string]$GitRoot = "D:\Git",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$distRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "dist"))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $distRoot "ProxyIPCheck-preview"
}
$packageRoot = [IO.Path]::GetFullPath($OutputDirectory)
$distPrefix = $distRoot.TrimEnd('\') + '\'
if (-not $packageRoot.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must remain inside $distRoot"
}

$guiPath = Join-Path $distRoot "ipcheck-preview.exe"
$helperPath = Join-Path $distRoot "ipquality-helper.exe"
foreach ($required in @($guiPath, $helperPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Build output is missing: $required"
    }
}

if (Test-Path -LiteralPath $packageRoot) {
    Remove-Item -LiteralPath $packageRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null

& (Join-Path $PSScriptRoot "prepare_ipquality_runtime.ps1") `
    -GitRoot $GitRoot `
    -OutputDirectory (Join-Path $packageRoot "runtime") `
    -HelperPath $helperPath

Copy-Item -LiteralPath $guiPath -Destination (Join-Path $packageRoot "ipcheck.exe")
Copy-Item -LiteralPath (Join-Path $repoRoot "config.json") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $repoRoot "README.md") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $repoRoot "LICENSE") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $repoRoot "THIRD_PARTY_NOTICES.txt") -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $repoRoot "LOCAL-PREVIEW.txt") -Destination $packageRoot

$ipqualityTarget = Join-Path $packageRoot "ipquality"
New-Item -ItemType Directory -Force -Path $ipqualityTarget | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "third_party\ipquality\ip.sh") -Destination $ipqualityTarget
Copy-Item -LiteralPath (Join-Path $repoRoot "third_party\ipquality\LICENSE") -Destination $ipqualityTarget
Copy-Item -LiteralPath (Join-Path $repoRoot "third_party\ipquality\UPSTREAM.md") -Destination $ipqualityTarget

$archivePath = Join-Path $distRoot "ProxyIPCheck-preview-windows-amd64.zip"
if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
}
Compress-Archive -Path (Join-Path $packageRoot "*") -DestinationPath $archivePath -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $distRoot "ProxyIPCheck-preview-SHA256.txt") -Value "$hash  $([IO.Path]::GetFileName($archivePath))" -Encoding ASCII

$packageFiles = Get-ChildItem -LiteralPath $packageRoot -Recurse -File
$packageMB = [Math]::Round((($packageFiles | Measure-Object Length -Sum).Sum / 1MB), 2)
$archiveMB = [Math]::Round(((Get-Item -LiteralPath $archivePath).Length / 1MB), 2)
Write-Host "Portable preview: $packageRoot ($packageMB MB)"
Write-Host "Archive: $archivePath ($archiveMB MB)"
Write-Host "SHA-256: $hash"
