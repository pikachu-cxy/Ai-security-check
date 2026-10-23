"""Release boundaries and package-manager metadata checks."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.generate_winget_manifest import generate as generate_winget
from scripts.update_homebrew_formula import generate as generate_homebrew
from scripts.maintenance.validate_manager_metadata import validate
from scripts.check_wheel import check_python_modules
from security_runtime._version import __version__
from security_runtime.cli import main
from security_runtime.engines import BUILTIN_ENGINES
from security_runtime.rulepacks import FIRST_PARTY_RULE_PACK
from security_runtime.mcp_config import resolve_runtime_command
from security_runtime.licensing import LicenseAction, LicensePolicy, Permission, MANAGED_PYTHON_LICENSE, PYINSTALLER_BOOTLOADER_LICENSE


@pytest.mark.parametrize('drift', ['none', 'missing', 'stale'])
def test_wheel_module_inventory_follows_directory_moves(tmp_path, drift):
    package = tmp_path / 'security_runtime'
    (package / 'guidance').mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'guidance/host_guidance.py').write_text('')
    names = {'security_runtime/__init__.py', 'security_runtime/guidance/host_guidance.py'}
    if drift == 'missing':
        names.remove('security_runtime/guidance/host_guidance.py')
    if drift == 'stale':
        names.add('security_runtime/host_guidance.py')
    if drift == 'none':
        check_python_modules(names, package)
    else:
        with pytest.raises(ValueError, match='stale or missing Python modules'):
            check_python_modules(names, package)


def test_runtime_version_and_semgrep_delivery(capsys):
    with pytest.raises(SystemExit) as exit_code:
        main(["--version"])
    assert exit_code.value.code == 0
    assert capsys.readouterr().out.strip() == f"AI Security Runtime {__version__}"
    assert BUILTIN_ENGINES["semgrep"].install_strategy == "MANAGED_PYTHON_PACKAGE"
    assert LicensePolicy.permission(MANAGED_PYTHON_LICENSE, LicenseAction.AUTO_DOWNLOAD) != Permission.NO
    assert LicensePolicy.permission(MANAGED_PYTHON_LICENSE, LicenseAction.BUNDLE) == Permission.NO
    assert LicensePolicy.permission(PYINSTALLER_BOOTLOADER_LICENSE, LicenseAction.BUNDLE) != Permission.NO
    root = Path(__file__).resolve().parents[1]
    assert "PROPRIETARY LICENSE" in (root / "LICENSE").read_text(encoding="utf-8")
    assert FIRST_PARTY_RULE_PACK.license == "Apache-2.0"


def test_current_install_examples_follow_single_version_source():
    root = Path(__file__).resolve().parents[1]
    readme = (root / 'README.md').read_text(encoding='utf-8')
    guide = (root / 'docs/PILOT_INSTALL_AND_USE.zh-CN.md').read_text(encoding='utf-8')
    for platform, extension in [('windows-x64', '.zip'), ('macos-arm64', '.tar.gz'), ('macos-x64', '.tar.gz')]:
        assert f'ai-security-runtime-v{__version__}-{platform}{extension}' in readme
    assert f'ai-security-runtime-v{__version__}-macos-arm64.tar.gz' in guide
    assert f'{__version__} / Official release' in readme


def test_generators_require_real_versioned_release_metadata(tmp_path):
    archive_names = {"windows-x64": ".zip", "macos-arm64": ".tar.gz", "macos-x64": ".tar.gz"}
    data = {"version": __version__, "artifacts": {
        platform: {"url": f"https://github.com/pikachu-cxy/Ai-security-check/releases/download/v{__version__}/ai-security-runtime-v{__version__}-{platform}{extension}",
                   "sha256": "a" * 64} for platform, extension in archive_names.items()}}
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    formula = tmp_path / "Formula" / "ai-security-runtime.rb"
    generate_homebrew(manifest, formula)
    assert formula.read_text(encoding="utf-8").count('sha256 "' + "a" * 64 + '"') == 2
    assert 'depends_on :macos' in formula.read_text(encoding="utf-8")
    assert 'on_linux' not in formula.read_text(encoding="utf-8")
    assert "bin.install_symlink" in formula.read_text(encoding="utf-8")
    winget = tmp_path / "winget"
    generate_winget(manifest, winget)
    installer = yaml.safe_load((winget / "PikachuCXY.AISecurityRuntime.installer.yaml").read_text(encoding="utf-8"))
    assert installer["NestedInstallerType"] == "portable"
    assert installer["NestedInstallerFiles"][0]["RelativeFilePath"] == "security-check\\security-check.exe"
    assert installer["Installers"][0]["InstallerSha256"] == "A" * 64
    validate(manifest, winget, formula, archives=False)
    data["artifacts"].pop("macos-x64")
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KeyError):
        generate_homebrew(manifest, formula)


def test_doctor_redirected_ascii_environment_emits_utf8(tmp_path):
    environment = dict(os.environ, PYTHONIOENCODING="ascii", SECURITY_RUNTIME_OFFLINE="1",
                       SECURITY_RUNTIME_DATA_DIR=str(tmp_path / "data"))
    result = subprocess.run([sys.executable, "-m", "security_runtime.cli", "doctor", "--path", str(tmp_path)],
                            cwd=tmp_path, env=environment, capture_output=True, timeout=60)
    stdout, stderr = result.stdout.decode("utf-8"), result.stderr.decode("utf-8")
    assert result.returncode in (0, 1), (stdout, stderr)
    assert "codec can't encode" not in stderr
    assert "Security Runtime" in stdout


def test_frozen_mcp_preserves_stable_install_alias(tmp_path, monkeypatch):
    binary = tmp_path / "version-directory" / "security-check.exe"
    binary.parent.mkdir()
    binary.write_bytes(b"runtime")
    alias = tmp_path / "stable-bin" / "security-check.exe"
    alias.parent.mkdir()
    os.link(binary, alias)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(binary))
    monkeypatch.setattr("security_runtime.mcp_config.shutil.which", lambda _: str(alias))
    command = resolve_runtime_command()
    assert command.command == str(alias)
    assert command.args == ("mcp",)
    alias.unlink()
    alias.write_bytes(b"unrelated runtime")
    assert resolve_runtime_command().command == str(binary)
