"""Exercise the shipped installer with real ZIP/hash IO and isolated fake transport/runtime."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest


INSTALLER = Path(__file__).resolve().parents[2] / 'website/public/install/windows.ps1'


@pytest.mark.skipif(os.name != 'nt', reason='Windows installer')
@pytest.mark.parametrize('shell', ['powershell', 'pwsh'])
@pytest.mark.parametrize('scenario', ['codex', 'cursor', 'hash', 'checksum', 'download', 'traversal', 'missing', 'exit', 'arm64'])
def test_installer(tmp_path, shell, scenario):
    executable = shutil.which(shell)
    if not executable:
        pytest.skip(f'{shell} unavailable')
    archive = tmp_path / 'fixture.zip'
    with zipfile.ZipFile(archive, 'w') as bundle:
        name = '../escaped.exe' if scenario == 'traversal' else 'security-check/security-check.exe'
        if scenario != 'missing':
            bundle.writestr(name, b'fixture, never execute')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if scenario == 'hash':
        digest = '0' * 64
    checksum = tmp_path / 'fixture.sha256'
    checksum.write_text('invalid' if scenario == 'checksum' else f'{digest}  ai-security-runtime-v0.3.10-windows-x64.zip\n')
    harness = tmp_path / 'harness.ps1'
    harness.write_text(r'''
$ErrorActionPreference = 'Stop'
$env:LOCALAPPDATA = Join-Path $env:FIXTURE_ROOT 'user data'
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
            Write-Output 'FIXTURE_RUNTIME_INVOKED'
            $global:LASTEXITCODE = 0
            if ($env:SCENARIO -eq 'exit') { $global:LASTEXITCODE = 17 }
        }
    }
}
try {
    & ([scriptblock]::Create((Get-Content -LiteralPath $env:INSTALLER -Raw))) -Editor $env:EDITOR
} catch { Write-Output $_.Exception.Message; exit 1 }
''', encoding='utf-8')
    env = dict(os.environ, FIXTURE_ROOT=str(tmp_path), SCENARIO=scenario,
               INSTALLER=str(INSTALLER), EDITOR='cursor' if scenario == 'cursor' else 'codex')
    # Let each shell discover its own standard modules, not the parent pwsh paths.
    env = {key: value for key, value in env.items() if key.lower() != 'psmodulepath'}
    result = subprocess.run([executable, '-NoProfile', '-Command', harness.read_text(encoding='utf-8')], env=env,
                            capture_output=True, text=True, timeout=45)
    output = result.stdout + result.stderr
    success = scenario in ('codex', 'cursor')
    assert (result.returncode == 0) == success, output
    assert ('FIXTURE_RUNTIME_INVOKED' in output) == (success or scenario == 'exit'), output
    expected = {'hash': 'SHA256 mismatch', 'checksum': 'Invalid release checksum',
                'download': 'fixture download failed', 'traversal': 'escapes the extraction',
                'missing': 'missing security-check.exe', 'exit': 'exit code 17',
                'arm64': 'Only Windows x64'}
    assert ('Installation completed' if success else expected[scenario]) in output
    assert not list(tmp_path.rglob('escaped.exe'))
