"""Release boundaries and package-manager metadata checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts.generate_winget_manifest import generate as generate_winget
from scripts.update_homebrew_formula import generate as generate_homebrew
from scripts.validate_manager_metadata import validate
from security_runtime._version import __version__
from security_runtime.cli import main
from security_runtime.engines import BUILTIN_ENGINES
from security_runtime.rulepacks import FIRST_PARTY_RULE_PACK
from security_runtime.licensing import LicenseAction, LicensePolicy, Permission, MANAGED_PYTHON_LICENSE, PYINSTALLER_BOOTLOADER_LICENSE


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


def test_generators_require_real_versioned_release_metadata(tmp_path):
    archive_names = {"windows-x64": ".zip", "macos-arm64": ".tar.gz", "macos-x64": ".tar.gz", "linux-x64": ".tar.gz"}
    data = {"version": __version__, "artifacts": {
        platform: {"url": f"https://github.com/pikachu-cxy/Ai-security-check/releases/download/v{__version__}/ai-security-runtime-v{__version__}-{platform}{extension}",
                   "sha256": "a" * 64} for platform, extension in archive_names.items()}}
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    formula = tmp_path / "Formula" / "ai-security-runtime.rb"
    generate_homebrew(manifest, formula)
    assert formula.read_text(encoding="utf-8").count('sha256 "' + "a" * 64 + '"') == 3
    assert "bin.install_symlink" in formula.read_text(encoding="utf-8")
    winget = tmp_path / "winget"
    generate_winget(manifest, winget)
    installer = yaml.safe_load((winget / "PikachuCXY.AISecurityRuntime.installer.yaml").read_text(encoding="utf-8"))
    assert installer["NestedInstallerType"] == "portable"
    assert installer["NestedInstallerFiles"][0]["RelativeFilePath"] == "security-check\\security-check.exe"
    assert installer["Installers"][0]["InstallerSha256"] == "A" * 64
    validate(manifest, winget, formula, archives=False)
    data["artifacts"].pop("linux-x64")
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KeyError):
        generate_homebrew(manifest, formula)
