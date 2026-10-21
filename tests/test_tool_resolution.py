"""Offline resolution and local scanner execution contracts."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime.engines import BUILTIN_ENGINES
from security_runtime.findings import FindingNormalizer
from security_runtime.models import RunStatus, ScanContext, ScanMode
from security_runtime.scanners import SemgrepAdapter
from security_runtime.processes import ProcessResult
from security_runtime.toolchain import (
    OfficialReleaseProvider, ResolvedTool, ToolManager, ToolManifest, ToolSource,
    ToolStatus, sha256_file, tool_environment, matches_version,
)


TOOLS = ("semgrep", "gitleaks", "trivy", "osv-scanner")


def local_executable(root: Path, tool: str) -> Path:
    path = root / (tool + (".exe" if os.name == "nt" else ""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"local test executable")
    if tool == 'semgrep':
        package = root.parent / 'Lib/site-packages/semgrep'
        package.mkdir(parents=True, exist_ok=True)
        (package / '__init__.py').write_bytes(b'package identity fixture; execution is mocked')
    return path


def managed_executable(manager: ToolManager, tool: str) -> Path:
    path = manager.managed_path(tool)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"managed test executable")
    if tool == 'semgrep':
        package = path.parent.parent / 'Lib/site-packages/semgrep'
        package.mkdir(parents=True, exist_ok=True)
        (package / '__init__.py').write_bytes(b'package identity fixture; execution is mocked')
    install_dir = path.parents[2] if tool == "semgrep" else path.parent
    (install_dir / "LICENSE").write_text("test license", encoding="utf-8")
    (install_dir / "NOTICE").write_text("test notice", encoding="utf-8")
    (install_dir / "metadata.json").write_text(json.dumps({
        "license": manager.license_metadata(tool).license_spdx,
        "version": manager.versions[tool],
        "executable_sha256": sha256_file(path),
    }), encoding="utf-8")
    marker = {"archive_sha256": manager.manifest(tool).sha256,
              "binary_sha256": sha256_file(path)} if tool != "semgrep" else {}
    (install_dir / "install.json").write_text(json.dumps(marker), encoding="utf-8")
    return path


@pytest.mark.parametrize("tool", TOOLS)
def test_offline_explicit_precedes_managed_and_path(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    explicit = local_executable(tmp_path / "explicit", tool)
    managed_executable(manager, tool)
    monkeypatch.setenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", str(explicit))
    monkeypatch.setattr(manager, "_version", lambda name, path: manager.versions[name])
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: str(local_executable(tmp_path / "path", name)))
    resolved = manager.ensure(tool, offline=True)
    assert (resolved.status, resolved.source, Path(resolved.path)) == (ToolStatus.READY, ToolSource.EXPLICIT, explicit.resolve())


@pytest.mark.parametrize("tool", TOOLS)
def test_offline_managed_precedes_path(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    managed = managed_executable(manager, tool)
    monkeypatch.delenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", raising=False)
    monkeypatch.setattr(manager, "_version", lambda name, path: manager.versions[name])
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: str(local_executable(tmp_path / "path", name)))
    resolved = manager.ensure(tool, offline=True)
    assert (resolved.status, resolved.source, Path(resolved.path)) == (ToolStatus.READY, ToolSource.MANAGED, managed.resolve())


@pytest.mark.parametrize("tool", TOOLS)
def test_offline_system_path_is_used_without_install(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    system = local_executable(tmp_path / "path", tool)
    monkeypatch.delenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", raising=False)
    monkeypatch.setattr("security_runtime.toolchain.sysconfig.get_path", lambda name: str(tmp_path / "missing-scripts"))
    monkeypatch.setattr(manager, "_version", lambda name, path: manager.versions[name])
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: str(system) if name == tool else None)
    with patch.object(manager, "_install_binary", side_effect=AssertionError("download attempted")), \
         patch.object(manager, "install_python_package", side_effect=AssertionError("download attempted")):
        resolved = manager.ensure(tool, offline=True)
    assert (resolved.status, resolved.source, Path(resolved.path)) == (ToolStatus.READY, ToolSource.SYSTEM, system.resolve())


@pytest.mark.parametrize("tool", TOOLS)
def test_offline_missing_tool_never_installs(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    monkeypatch.delenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", raising=False)
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: None)
    monkeypatch.setattr("security_runtime.toolchain.sysconfig.get_path", lambda name: str(tmp_path / "missing-scripts"))
    with patch.object(manager, "_install_binary", side_effect=AssertionError("download attempted")), \
         patch.object(manager, "install_python_package", side_effect=AssertionError("download attempted")):
        resolved = manager.ensure(tool, offline=True)
    assert resolved.status == ToolStatus.OFFLINE


@pytest.mark.parametrize("tool", TOOLS)
def test_offline_reports_incompatible_local_version(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    system = local_executable(tmp_path / "path", tool)
    monkeypatch.delenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", raising=False)
    monkeypatch.setattr("security_runtime.toolchain.sysconfig.get_path", lambda name: str(tmp_path / "missing-scripts"))
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: str(system) if name == tool else None)
    monkeypatch.setattr(manager, "_version", lambda name, path: "0.0.0")
    resolved = manager.ensure(tool, offline=True)
    assert (resolved.status, resolved.source) == (ToolStatus.VERSION_MISMATCH, ToolSource.SYSTEM)


@pytest.mark.parametrize("tool", TOOLS)
def test_online_missing_tool_installs_then_resolves(tool, tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    monkeypatch.delenv(f"SECURITY_RUNTIME_{tool.upper().replace('-', '_')}_PATH", raising=False)
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: None)
    monkeypatch.setattr("security_runtime.toolchain.sysconfig.get_path", lambda name: str(tmp_path / "missing-scripts"))
    monkeypatch.setattr(manager, "_version", lambda name, path: manager.versions[name])
    installs = []

    def install(*args, **kwargs):
        installs.append(tool)
        managed_executable(manager, tool)

    monkeypatch.setattr(manager, "_install_binary", install)
    monkeypatch.setattr(manager, "install_python_package", install)
    resolved = manager.ensure(tool, offline=False)
    assert installs == [tool]
    assert (resolved.status, resolved.source) == (ToolStatus.READY, ToolSource.MANAGED)


def test_semgrep_pip_script_outside_path_is_validated_as_system_tool(tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path / "managed")
    scripts = tmp_path / "Scripts"
    semgrep = local_executable(scripts, "semgrep")
    monkeypatch.delenv("SECURITY_RUNTIME_SEMGREP_PATH", raising=False)
    monkeypatch.setattr("security_runtime.toolchain.shutil.which", lambda name: None)
    monkeypatch.setattr("security_runtime.toolchain.sysconfig.get_path", lambda name: str(scripts))
    monkeypatch.setattr("security_runtime.toolchain.importlib.metadata.version", lambda name: manager.versions[name])
    monkeypatch.setattr(manager, "_version", lambda name, path: manager.versions[name])
    resolved = manager.ensure("semgrep", offline=True)
    assert (resolved.status, resolved.source, Path(resolved.path)) == (ToolStatus.READY, ToolSource.SYSTEM, semgrep.resolve())


def test_first_party_rules_scan_offline():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("import os\nuser_input = input()\nos.system(user_input)\nresult = eval(user_input)\n", encoding="utf-8")
        adapter = SemgrepAdapter()
        context = ScanContext(str(root), ScanMode.QUICK, ("app.py",))
        offline_env = {"SECURITY_RUNTIME_OFFLINE": "1", "HTTP_PROXY": "http://127.0.0.1:9",
                       "HTTPS_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": ""}
        with patch.dict(os.environ, offline_env), patch("urllib.request.urlopen", side_effect=AssertionError("network attempted")):
            findings, run = adapter.scan(context, FindingNormalizer(root))
        assert run.status == RunStatus.SUCCESS, run.error
        rule_ids = {finding.technical_details.get("rule_id") for finding in findings}
        assert any("command-injection" in str(rule_id) for rule_id in rule_ids)
        assert any("unsafe-eval" in str(rule_id) for rule_id in rule_ids)
        assert all(finding.technical_details.get("rule_pack") == "ai-security-core" for finding in findings)


def test_release_checksum_failure_removes_untrusted_asset(tmp_path):
    class Response(io.BytesIO):
        url = "https://github.com/example/release.zip"

    manifest = ToolManifest("fake", "Fake", "1.0", "windows", "x64",
        "https://github.com/example/release.zip", "0" * 64, "zip", "fake.exe",
        "https://github.com/example", "MIT", BUILTIN_ENGINES["gitleaks"].license_metadata)
    destination = tmp_path / "asset.zip"
    with patch("urllib.request.urlopen", return_value=Response(b"unverified bytes")):
        with pytest.raises(ValueError, match="SHA256 mismatch"):
            OfficialReleaseProvider().download(manifest, destination)
    assert not destination.exists()


def test_engine_helpers_use_selected_environment(tmp_path, monkeypatch):
    selected = tmp_path / "engine" / "bin" / "semgrep"
    monkeypatch.setenv("PATH", str(tmp_path / "old-engine"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "old-python"))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "old-python"))
    environment = tool_environment(selected)
    assert environment["PATH"].split(os.pathsep)[0] == str(selected.parent.resolve())
    assert "PYTHONPATH" not in environment and "PYTHONHOME" not in environment
    assert matches_version("1.178.0", "semgrep 1.178.0")
    assert not matches_version("1.178.0", "semgrep 11.178.0")
    assert not matches_version("1.178.0", "semgrep 1.178.01")


def test_missing_managed_python_offline_never_downloads(tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path)
    monkeypatch.setenv("SECURITY_RUNTIME_OFFLINE", "1")
    with patch.object(manager.provider, "download", side_effect=AssertionError("network attempted")):
        with pytest.raises(ValueError, match="unavailable offline"):
            manager.prepare_python_runtime()


def test_trivy_db_preparation_does_not_use_docker_credentials(tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path)
    seen = []

    def run(*args, **kwargs):
        seen.append(kwargs["env"]["DOCKER_CONFIG"])
        return ProcessResult(1, "", "temporary failure", 1)

    monkeypatch.setenv("SECURITY_RUNTIME_TRIVY_CACHE_DIR", str(tmp_path / "cache"))
    with patch("security_runtime.toolchain.run_process", side_effect=run), \
         patch("security_runtime.toolchain.time.sleep"):
        assert manager.prepare_trivy_database(str(tmp_path / "trivy.exe"), offline=False) == ToolStatus.BROKEN
    assert len(seen) == 2
    assert seen[0] == str(tmp_path / "cache" / "docker-config")
