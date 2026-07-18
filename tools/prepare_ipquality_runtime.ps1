param(
    [string]$GitRoot = "D:\Git",
    [string]$OutputDirectory = "",
    [string]$HelperPath = "",
    [string]$JqPath = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$distRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "dist"))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $distRoot "runtime"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
$distPrefix = $distRoot.TrimEnd('\') + '\'
if (-not $outputRoot.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must remain inside $distRoot"
}

$gitRootFull = [IO.Path]::GetFullPath($GitRoot)
$usrBinSource = Join-Path $gitRootFull "usr\bin"
$mingwBinSource = Join-Path $gitRootFull "mingw64\bin"
if (-not (Test-Path -LiteralPath (Join-Path $usrBinSource "bash.exe"))) {
    throw "Git for Windows Bash was not found under $gitRootFull"
}
if (-not (Test-Path -LiteralPath (Join-Path $mingwBinSource "curl.exe"))) {
    throw "Git for Windows curl was not found under $gitRootFull"
}

if ([string]::IsNullOrWhiteSpace($HelperPath)) {
    $HelperPath = Join-Path $distRoot "ipquality-helper.exe"
}
$helperFull = [IO.Path]::GetFullPath($HelperPath)
if (-not (Test-Path -LiteralPath $helperFull -PathType Leaf)) {
    throw "The IPQuality helper was not found: $helperFull"
}

if (Test-Path -LiteralPath $outputRoot) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
$usrBinTarget = Join-Path $outputRoot "usr\bin"
$mingwBinTarget = Join-Path $outputRoot "mingw64\bin"
$toolsTarget = Join-Path $outputRoot "tools"
$licensesTarget = Join-Path $outputRoot "licenses"
$tmpTarget = Join-Path $outputRoot "tmp"
New-Item -ItemType Directory -Force -Path $usrBinTarget, $mingwBinTarget, $toolsTarget, $licensesTarget, $tmpTarget | Out-Null
Set-Content -LiteralPath (Join-Path $tmpTarget ".keep") -Value "Runtime temporary directory." -Encoding ASCII

$usrExecutables = @(
    "bash.exe", "sh.exe", "awk.exe", "sed.exe", "grep.exe", "head.exe", "cut.exe",
    "sort.exe", "tr.exe", "timeout.exe", "date.exe", "od.exe", "stty.exe", "tail.exe",
    "gzip.exe", "touch.exe", "sleep.exe"
)
$usrLibraries = @(
    "msys-2.0.dll", "msys-gcc_s-seh-1.dll", "msys-gmp-10.dll", "msys-iconv-2.dll",
    "msys-intl-8.dll", "msys-mpfr-6.dll", "msys-ncursesw6.dll", "msys-pcre-1.dll",
    "msys-readline8.dll"
)
$mingwFiles = @(
    "curl.exe", "libbrotlicommon.dll", "libbrotlidec.dll", "libcurl-4.dll", "libiconv-2.dll",
    "libidn2-0.dll", "libintl-8.dll", "libpsl-5.dll", "libssh2-1.dll", "libunistring-5.dll",
    "libzstd.dll", "zlib1.dll"
)

foreach ($name in $usrExecutables + $usrLibraries) {
    Copy-Item -LiteralPath (Join-Path $usrBinSource $name) -Destination (Join-Path $usrBinTarget $name)
}
Copy-Item -LiteralPath (Join-Path $usrBinSource "gunzip") -Destination (Join-Path $usrBinTarget "gunzip")
foreach ($name in $mingwFiles) {
    Copy-Item -LiteralPath (Join-Path $mingwBinSource $name) -Destination (Join-Path $mingwBinTarget $name)
}

Copy-Item -LiteralPath $helperFull -Destination (Join-Path $toolsTarget "ipquality-helper.exe")
foreach ($name in @("bc", "dig", "nc", "ss")) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "third_party\ipquality\shims\$name") -Destination (Join-Path $toolsTarget $name)
}

$jqVersion = "1.8.1"
$jqSHA256 = "23CB60A1354EED6BCC8D9B9735E8C7B388CD1FDCB75726B93BC299EF22DD9334"
if ([string]::IsNullOrWhiteSpace($JqPath)) {
    $cacheDirectory = Join-Path $distRoot "download-cache"
    New-Item -ItemType Directory -Force -Path $cacheDirectory | Out-Null
    $JqPath = Join-Path $cacheDirectory "jq-windows-amd64-$jqVersion.exe"
    if (-not (Test-Path -LiteralPath $JqPath -PathType Leaf)) {
        Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/jqlang/jq/releases/download/jq-$jqVersion/jq-windows-amd64.exe" -OutFile $JqPath
    }
}
$jqFull = [IO.Path]::GetFullPath($JqPath)
$actualJqHash = (Get-FileHash -LiteralPath $jqFull -Algorithm SHA256).Hash
if ($actualJqHash -ne $jqSHA256) {
    throw "jq checksum mismatch: expected $jqSHA256, got $actualJqHash"
}
Copy-Item -LiteralPath $jqFull -Destination (Join-Path $toolsTarget "jq.exe")

$licenseSets = @(
    @{ Source = "usr\share\licenses\gcc-libs"; Target = "msys-gcc-libs" },
    @{ Source = "usr\share\licenses\ncurses"; Target = "msys-ncurses" },
    @{ Source = "mingw64\share\licenses\brotli"; Target = "brotli" },
    @{ Source = "mingw64\share\licenses\curl"; Target = "curl" },
    @{ Source = "mingw64\share\licenses\gettext-runtime"; Target = "gettext-runtime" },
    @{ Source = "mingw64\share\licenses\libiconv"; Target = "libiconv" },
    @{ Source = "mingw64\share\licenses\libpsl"; Target = "libpsl" },
    @{ Source = "mingw64\share\licenses\libssh2"; Target = "libssh2" },
    @{ Source = "mingw64\share\licenses\libunistring"; Target = "libunistring" },
    @{ Source = "mingw64\share\licenses\zlib"; Target = "zlib" },
    @{ Source = "mingw64\share\licenses\zstd"; Target = "zstd" }
)
foreach ($set in $licenseSets) {
    $source = Join-Path $gitRootFull $set.Source
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination (Join-Path $licensesTarget $set.Target) -Recurse
    }
}

$jqLicenseURL = "https://raw.githubusercontent.com/jqlang/jq/jq-$jqVersion/COPYING"
Invoke-WebRequest -UseBasicParsing -Uri $jqLicenseURL -OutFile (Join-Path $licensesTarget "jq-COPYING.txt")
Copy-Item -LiteralPath (Join-Path $repoRoot "third_party\ipquality\LICENSE") -Destination (Join-Path $licensesTarget "IPQuality-AGPL-3.0.txt")

$packageVersionsPath = Join-Path $gitRootFull "etc\package-versions.txt"
$packageSummary = @()
if (Test-Path -LiteralPath $packageVersionsPath) {
    $wantedPackages = @("bash", "coreutils", "gawk", "grep", "gzip", "msys2-runtime", "sed")
    foreach ($package in $wantedPackages) {
        $match = Get-Content -LiteralPath $packageVersionsPath | Where-Object { $_ -match "^$([Regex]::Escape($package))\s" } | Select-Object -First 1
        if ($match) {
            $packageSummary += "  $match"
        }
    }
}
if ($packageSummary.Count -eq 0) {
    $packageSummary = @("  See the source Git for Windows installation: $gitRootFull")
}
$componentManifest = @"
Portable runtime component manifest
===================================

IPQuality: xykt/IPQuality v2026-03-29, commit 44c35cca002782ddd6364e039be2949a2535d1cc
jq: $jqVersion, SHA-256 $jqSHA256
Git for Windows runtime source: $gitRootFull

The selected Git for Windows runtime contains these MSYS2 packages:
$($packageSummary -join "`r`n")

Corresponding package sources are available from:
  https://repo.msys2.org/msys/sources/
Git for Windows project sources and build system:
  https://github.com/git-for-windows/git
  https://github.com/git-for-windows/build-extra
"@
Set-Content -LiteralPath (Join-Path $licensesTarget "RUNTIME-COMPONENTS.txt") -Value $componentManifest -Encoding UTF8

Get-ChildItem -LiteralPath $outputRoot -Recurse -File |
    Sort-Object FullName |
    ForEach-Object {
        $relative = $_.FullName.Substring($outputRoot.Length + 1)
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relative"
    } | Set-Content -LiteralPath (Join-Path $outputRoot "SHA256SUMS.txt") -Encoding ASCII

$files = Get-ChildItem -LiteralPath $outputRoot -Recurse -File
$sizeMB = [Math]::Round((($files | Measure-Object Length -Sum).Sum / 1MB), 2)
Write-Host "Prepared IPQuality runtime: $outputRoot ($($files.Count) files, $sizeMB MB)"
