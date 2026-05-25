# ANAL installer (Windows / PowerShell).
#
# Data arrives, in order, with consent. This script downloads the `anal`
# binary for your platform from the latest GitHub Release, verifies its
# SHA-256, and inserts it into your PATH.
#
# Environment overrides:
#   $env:ANAL_VERSION       Tag to install (default: latest, e.g. v0.1.0).
#   $env:ANAL_INSTALL_DIR   Destination directory (default: %LOCALAPPDATA%\anal\bin).
#   $env:ANAL_NO_MODIFY_PATH=1   Skip PATH update.

$ErrorActionPreference = 'Stop'

$Repo = 'anal-lang/anal'
$Bin  = 'anal.exe'

function Say  { param($m) Write-Host $m }
function Note { param($m) Write-Host "  $m" }
function Die  { param($m) Write-Host "EVACUATE: $m" -ForegroundColor Red; exit 1 }

# --- detect target ---------------------------------------------------------

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { 'x86_64' }
  'ARM64' { Die 'aarch64-pc-windows-msvc not yet built; download a binary manually or use WSL' }
  default { Die "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$target = "$arch-pc-windows-msvc"

# --- pick version ----------------------------------------------------------

$version = $env:ANAL_VERSION
if (-not $version) {
  Say 'PREP install'
  Note 'asking GitHub for the latest tag...'
  try {
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'anal-installer' }
    $version = $rel.tag_name
  } catch {
    Die "could not determine latest version: $_"
  }
} else {
  Say 'PREP install'
  Note "version pinned: $version"
}

$versionBare = $version.TrimStart('v')
$name  = "anal-$versionBare-$target"
$asset = "$name.zip"
$url   = "https://github.com/$Repo/releases/download/$version/$asset"
$sumUrl = "$url.sha256"

Note "target: $target"
Note "asset:  $asset"

# --- consent ---------------------------------------------------------------

$installDir = $env:ANAL_INSTALL_DIR
if (-not $installDir) {
  $installDir = Join-Path $env:LOCALAPPDATA 'anal\bin'
}

Say ''
Say 'CONSENT install'
Note "will fetch:  $url"
Note "will insert: $installDir\$Bin"
Say ''

# --- fetch + verify + insert ----------------------------------------------

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("anal-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Say "INSERT $Bin"
  Note 'downloading...'
  $zipPath = Join-Path $tmp $asset
  $sumPath = "$zipPath.sha256"
  Invoke-WebRequest -Uri $url    -OutFile $zipPath -UseBasicParsing
  Invoke-WebRequest -Uri $sumUrl -OutFile $sumPath -UseBasicParsing

  Note 'verifying checksum...'
  $expected = (Get-Content $sumPath -Raw).Trim().Split(' ')[0].ToLowerInvariant()
  $actual   = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($expected -ne $actual) {
    Die "checksum mismatch -- refusing insertion (expected $expected, got $actual)"
  }

  Note 'unpacking...'
  Expand-Archive -Path $zipPath -DestinationPath $tmp -Force

  if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
  }
  Copy-Item -Path (Join-Path $tmp "$name\$Bin") -Destination (Join-Path $installDir $Bin) -Force

  Say ''
  Say 'EXPEL'
  Note "installed $version to $installDir\$Bin"

  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -eq $installDir })) {
    if (-not $env:ANAL_NO_MODIFY_PATH) {
      Note "adding $installDir to your user PATH..."
      $newPath = if ([string]::IsNullOrEmpty($userPath)) { $installDir } else { "$userPath;$installDir" }
      [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
      Note 'open a new terminal for PATH changes to take effect.'
    } else {
      Note "$installDir is not on your PATH; add it manually."
    }
  }

  Say ''
  Note 'try it:  anal --help'
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
