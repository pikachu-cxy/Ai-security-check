# Windows PowerShell 5.1 and PowerShell 7. Run as a normal user.
[CmdletBinding()]
param([ValidateSet('codex', 'cursor', 'workbuddy')][string]$Editor = 'codex',
      [string]$LegacyAppData = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This installer requires Windows x64.' }
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
if ($architecture -ne 'AMD64') { throw 'Only Windows x64 is supported.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is unavailable.' }
if (-not $env:USERPROFILE -or -not [IO.Path]::IsPathRooted($env:USERPROFILE)) { throw 'USERPROFILE must be absolute.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$version = '0.3.14'
$archiveName = "ai-security-runtime-v$version-windows-x64.zip"
$baseUrl = "https://github.com/pikachu-cxy/Ai-security-check/releases/download/v$version"
# Keep this unique directory for diagnostics and optional status commands.
# Never overwrite another invocation's bundle or the active installation.
$downloadRoot = Join-Path $env:LOCALAPPDATA 'AI-Security-Runtime-downloads'
$stage = Join-Path $downloadRoot ([guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $stage
$archive = Join-Path $stage $archiveName
$checksum = "$archive.sha256"
try {
    Write-Host "Downloading AI Security Runtime $version for $Editor..."
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archiveName.sha256" -OutFile $checksum
    Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$archiveName" -OutFile $archive
    $localInstall = [Diagnostics.Stopwatch]::StartNew()
    $checksumText = (Get-Content -LiteralPath $checksum -Raw).Trim()
    $pattern = '\A([a-fA-F0-9]{64})\s+\*?' + [regex]::Escape($archiveName) + '\z'
    if ($checksumText -notmatch $pattern) { throw 'Invalid release checksum file.' }
    $expectedHash = $Matches[1]
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $expectedHash) {
        throw 'SHA256 mismatch; the downloaded program will not be executed.'
    }
    Write-Host 'Checksum verified. Extracting the complete bundle...'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $bundle = Join-Path $stage 'bundle'
    $boundary = [IO.Path]::GetFullPath($bundle) + [IO.Path]::DirectorySeparatorChar
    $zip = [IO.Compression.ZipFile]::OpenRead($archive)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('/', '\')
            if ([IO.Path]::IsPathRooted($name) -or $name.Contains(':')) { throw 'Unsafe archive entry.' }
            $target = [IO.Path]::GetFullPath((Join-Path $bundle $name))
            if (-not $target.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Archive entry escapes the extraction directory.'
            }
        }
    } finally { $zip.Dispose() }
    [IO.Compression.ZipFile]::ExtractToDirectory($archive, $bundle)
    $exe = Join-Path $bundle 'security-check\security-check.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'The complete bundle is missing security-check.exe.' }
    Write-Host "Installing integration for $Editor..."
    # Keep the versioned bundle path short on Windows systems where long paths
    # are disabled. The runtime validates the destination before activation.
    $installRoot = Join-Path $env:USERPROFILE '.asr'
    $migrationArgs = @()
    if ($LegacyAppData) { $migrationArgs = @('--legacy-appdata', $LegacyAppData) }
    $receiptText = & $exe install $Editor --bundle (Join-Path $bundle 'security-check') --root $installRoot --json @migrationArgs
    if ($LASTEXITCODE -ne 0) {
        $installExit = $LASTEXITCODE
        try { $failure = $receiptText | ConvertFrom-Json } catch { $failure = $null }
        if ($failure -and $failure.PSObject.Properties['installation'] -and
            $failure.installation.PSObject.Properties['message']) { throw $failure.installation.message }
        throw "Installation failed with exit code $installExit."
    }
    $receiptText | Set-Content -LiteralPath (Join-Path $stage 'installation.json') -Encoding UTF8
    $receipt = $receiptText | ConvertFrom-Json
    $expected = Get-Content -LiteralPath (Join-Path $bundle 'security-check\version.json') -Raw | ConvertFrom-Json
    if (-not $receipt.installation.local_files_ready -or $receipt.delivery.active_build -ne $expected.build_id) {
        throw 'Installation receipt does not match the downloaded build.'
    }
    if ($receipt.PSObject.Properties['launcher_verification']) {
        $actual = $receipt.launcher_verification
        if ($actual.status -ne 'VERIFIED') { throw 'Launcher verification did not succeed.' }
    } else {
        # Compatibility with an older installer: still verify the actual entry.
        $actualText = & $receipt.delivery.launcher runtime-info --json
        if ($LASTEXITCODE -ne 0) { throw 'Installed launcher could not be verified.' }
        $actual = ($actualText | ConvertFrom-Json).build_identity
    }
    if ($actual.build_id -ne $expected.build_id -or $actual.version -ne $version) {
        throw 'Installed launcher points to a different build; installation is not confirmed.'
    }
    $localInstall.Stop()
    Write-Host ('Local installation (excluding downloads): {0:N2} seconds.' -f $localInstall.Elapsed.TotalSeconds)
    Write-Host "Installation completed. Fully quit and reopen $Editor. Component preparation may continue in the background."
    Write-Host "To check preparation: & '$exe' preparation status"
} catch {
    throw "Installation stopped. Files retained at $stage. $($_.Exception.Message)"
}
