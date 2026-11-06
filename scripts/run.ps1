# Use from an interactive PowerShell terminal. No admin rights are needed.
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$MessengerArgs)
$ErrorActionPreference = 'Stop'
$repo = $env:P2PMESSENGER_REPO
if ($repo -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $repo -match '/\.{1,2}$|^\.{1,2}/') {
    throw 'Set P2PMESSENGER_REPO=OWNER/REPOSITORY.'
}
$version = $env:P2PMESSENGER_VERSION
if (-not $version) { $version = 'latest' }
if ($version -ne 'latest' -and $version -notmatch '^v[0-9][A-Za-z0-9._-]*$') { throw 'Invalid release version.' }
# The Windows release currently targets x64. Reject native ARM and 32-bit hosts.
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($env:OS -ne 'Windows_NT' -or $arch -ne 'AMD64') { throw 'This launcher requires Windows x64.' }
$asset = 'p2pmessenger-windows-amd64.exe'
$base = if ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" } else { "https://github.com/$repo/releases/download/$version" }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is not set.' }
$work = Join-Path $env:LOCALAPPDATA ("p2pmessenger\cache\launch-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    Write-Host "Downloading $asset ($version)…"
    $manifest = Join-Path $work 'SHA256SUMS'
    $binary = Join-Path $work $asset
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $manifest
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $binary
    $entries = @(Get-Content -LiteralPath $manifest | Where-Object { $_ -match ('^[a-f0-9]{64}  ' + [regex]::Escape($asset) + '$') })
    if ($entries.Count -ne 1) { throw 'Missing or ambiguous checksum.' }
    $expected = $entries[0].Substring(0, 64)
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $binary).Hash.ToLowerInvariant() -ne $expected) {
        throw 'Checksum mismatch; nothing was executed.'
    }
    & $binary @MessengerArgs
    $result = $LASTEXITCODE
} finally {
    # Only this launch's random directory; never touch the user's chat profile.
    Remove-Item -LiteralPath $work -Recurse -Force
}
exit $result
