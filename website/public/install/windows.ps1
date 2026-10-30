# Windows PowerShell 5.1 and PowerShell 7. Run as a normal user.
[CmdletBinding()]
param([ValidateSet('codex', 'cursor')][string]$Editor = 'codex')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'This installer requires Windows x64.' }
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
if ($architecture -ne 'AMD64') { throw 'Only Windows x64 is supported.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is unavailable.' }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$version = '0.3.10'
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
    & $exe install $Editor --bundle (Join-Path $bundle 'security-check')
    if ($LASTEXITCODE -ne 0) { throw "Installation failed with exit code $LASTEXITCODE." }
    Write-Host "Installation completed. Fully quit and reopen $Editor. Component preparation may continue in the background."
    Write-Host "To check preparation: & '$exe' preparation status"
} catch {
    throw "Installation stopped. Files retained at $stage. $($_.Exception.Message)"
}
