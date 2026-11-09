"""Exercise the shipped installer with real ZIP/hash IO and isolated fake transport/runtime."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest


from security_runtime._version import __version__ as VERSION

INSTALLER = Path(__file__).resolve().parents[2] / 'website/public/install/windows.ps1'


@pytest.mark.skipif(os.name != 'nt', reason='Windows installer')
@pytest.mark.parametrize('shell', ['powershell', 'pwsh'])
@pytest.mark.parametrize('scenario', ['codex', 'cursor', 'workbuddy', 'migration', 'migration-error', 'stale', 'hash', 'checksum', 'download', 'traversal', 'missing', 'exit', 'arm64'])
def test_installer(tmp_path, shell, scenario):
    executable = shutil.which(shell)
    if not executable:
        pytest.skip(f'{shell} unavailable')
    archive = tmp_path / 'fixture.zip'
    with zipfile.ZipFile(archive, 'w') as bundle:
        name = '../escaped.exe' if scenario == 'traversal' else 'security-check/security-check.exe'
        if scenario != 'missing':
            bundle.writestr(name, b'fixture, never execute')
            bundle.writestr('security-check/version.json', json.dumps(dict(build_id='a'*64, version=VERSION)))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if scenario == 'hash':
        digest = '0' * 64
    checksum = tmp_path / 'fixture.sha256'
    checksum.write_text('invalid' if scenario == 'checksum' else f'{digest}  ai-security-runtime-v{VERSION}-windows-x64.zip\n')
    harness = tmp_path / 'harness.ps1'
    harness.write_text(r'''
$ErrorActionPreference = 'Stop'
$env:LOCALAPPDATA = Join-Path $env:FIXTURE_ROOT 'user data'
$env:USERPROFILE = Join-Path $env:FIXTURE_ROOT 'user profile'
$env:PROCESSOR_ARCHITECTURE = 'AMD64'
$env:PROCESSOR_ARCHITEW6432 = ''
if ($env:SCENARIO -eq 'arm64') { $env:PROCESSOR_ARCHITECTURE = 'ARM64' }
function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    if ($env:SCENARIO -eq 'download') { throw 'fixture download failed' }
    if ($Uri.EndsWith('.sha256')) {
        Copy-Item -LiteralPath (Join-Path $env:FIXTURE_ROOT 'fixture.sha256') -Destination $OutFile
    } else {
        Copy-Item -LiteralPath (Join-Path $env:FIXTURE_ROOT 'fixture.zip') -Destination $OutFile
        $fake = Join-Path (Split-Path $OutFile) 'bundle\security-check\security-check.exe'
        Set-Item -LiteralPath "Function:global:$fake" -Value {
            if ($args[0] -ne 'install' -or $args[1] -ne $env:EDITOR -or $args[2] -ne '--bundle') { throw 'Wrong arguments' }
            if (-not (Test-Path -LiteralPath (Join-Path $args[3] 'security-check.exe'))) { throw 'Wrong bundle path' }
            if ($args[4] -ne '--root' -or $args[5] -ne (Join-Path $env:USERPROFILE '.asr')) { throw 'Wrong install root' }
            if ($env:SCENARIO -eq 'migration' -and ($args[7] -ne '--legacy-appdata' -or $args[8] -ne (Join-Path $env:FIXTURE_ROOT 'old app data'))) { throw 'Missing migration source' }
            Write-Host 'FIXTURE_RUNTIME_INVOKED'
            $build = 'a' * 64
            $actualBuild = if ($env:SCENARIO -eq 'stale') { 'b' * 64 } else { $build }
            $installation=@{local_files_ready=$true}
            if ($env:SCENARIO -eq 'migration-error') { $installation.message='fixture migration blocked' }
            @{installation=$installation; delivery=@{active_build=$build};
              launcher_verification=@{status='VERIFIED';version=$env:FIXTURE_VERSION;build_id=$actualBuild}} | ConvertTo-Json -Compress
            $global:LASTEXITCODE = 0
            if ($env:SCENARIO -eq 'exit') { $global:LASTEXITCODE = 17 }
            if ($env:SCENARIO -eq 'migration-error') { $global:LASTEXITCODE = 2 }
        }
    }
}
try {
    $extra=@{}
    if ($env:SCENARIO -eq 'migration') { $extra.LegacyAppData=Join-Path $env:FIXTURE_ROOT 'old app data' }
    & ([scriptblock]::Create((Get-Content -LiteralPath $env:INSTALLER -Raw))) -Editor $env:EDITOR @extra
} catch { Write-Output $_.Exception.Message; exit 1 }
''', encoding='utf-8')
    env = dict(os.environ, FIXTURE_ROOT=str(tmp_path), FIXTURE_VERSION=VERSION, SCENARIO=scenario,
               INSTALLER=str(INSTALLER), EDITOR=scenario if scenario in ('cursor', 'workbuddy') else 'codex')
    # Let each shell discover its own standard modules, not the parent pwsh paths.
    env = {key: value for key, value in env.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run([executable, '-NoProfile', '-Command', harness.read_text(encoding='utf-8')], env=env,
                            capture_output=True, text=True, timeout=45)
    output = result.stdout + result.stderr
    success = scenario in ('codex', 'cursor', 'workbuddy', 'migration')
    assert (result.returncode == 0) == success, output
    assert ('FIXTURE_RUNTIME_INVOKED' in output) == (success or scenario in ('exit', 'stale', 'migration-error')), output
    expected = {'hash': 'SHA256 mismatch', 'checksum': 'Invalid release checksum',
                'download': 'fixture download failed', 'traversal': 'escapes the extraction',
                'missing': 'missing security-check.exe', 'exit': 'exit code 17',
                'arm64': 'Only Windows x64', 'stale': 'points to a different build',
                'migration-error': 'fixture migration blocked'}
    assert ('Installation completed' if success else expected[scenario]) in output
    assert not list(tmp_path.rglob('escaped.exe'))
