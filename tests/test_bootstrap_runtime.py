"""Frozen first-install orchestration; native archive gate exercises real engines.

Only download transport and external processes are simulated here. The bootstrap
entry selection, checksum verification, tar extraction, version validation,
metadata/identity checks and Semgrep install/resolve paths run unchanged.
"""
import io
import json
import os
import tarfile
from contextlib import nullcontext
from pathlib import Path

import pytest

from security_runtime import toolchain
from security_runtime.processes import ProcessResult
from security_runtime.toolchain import ToolManager, ToolStatus, sha256_file


@pytest.fixture
def frozen_install(tmp_path, monkeypatch):
    root = tmp_path / "empty-managed-data"
    package = tmp_path / "package"
    package.mkdir()
    entries = json.loads(Path(toolchain.__file__).with_name("python_downloads.json").read_text())
    key = "-".join(toolchain.platform_key())
    relative = Path("python.exe") if os.name == "nt" else Path("bin/python3.12")
    entry = entries[key]
    state = {"version": entry["version"], "license": True, "bad_sha": False, "downloads": 0, "calls": []}

    class Response(io.BytesIO):
        url = entry["url"]

    def download(request, **kwargs):
        assert request.full_url == entry["url"]
        state["downloads"] += 1
        return Response(state["archive"])

    def archive():
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            files = {"python/" + relative.as_posix(): b"synthetic CPython executable"}
            if state["license"]:
                files["python/LICENSE"] = b"Python license fixture"
            for name, content in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
        state["archive"] = stream.getvalue()
        import hashlib
        entry["sha256"] = "0" * 64 if state["bad_sha"] else hashlib.sha256(state["archive"]).hexdigest()
        (package / "python_downloads.json").write_text(json.dumps(entries))

    def process(args, **kwargs):
        state["calls"].append(args)
        if args[1:2] == ["scan"]:
            assert Path(args[0]).stem == "semgrep" and args[-1] == "probe.py"
            return ProcessResult(0, json.dumps({"results": [{"check_id": "runtime-engine-probe",
                "path": "probe.py", "start": {"line": 1}}], "errors": []}), "", 1)
        if args[1:] == ["--version"]:
            version = toolchain.VERSIONS["semgrep"] if Path(args[0]).stem == "semgrep" else state["version"]
            return ProcessResult(0, version, "", 1)
        if args[1:3] == ["-m", "venv"]:
            target = Path(args[3])
            python = target / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            python.parent.mkdir(parents=True)
            python.write_bytes(b"synthetic venv Python")
            return ProcessResult(0, "", "", 1)
        assert args[1:4] == ["-m", "pip", "install"]
        runtime = Path(args[0]).parent.parent
        packages = runtime / "Lib/site-packages"
        (packages / "semgrep").mkdir(parents=True)
        (packages / "semgrep/__init__.py").write_text("")
        dist = packages / ("semgrep-" + toolchain.VERSIONS["semgrep"] + ".dist-info")
        dist.mkdir()
        (dist / "LICENSE").write_text("Semgrep license fixture")
        (dist / "METADATA").write_text("Name: semgrep\nVersion: " + toolchain.VERSIONS["semgrep"])
        (Path(args[0]).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")).write_bytes(b"synthetic Semgrep executable")
        Path(args[args.index("--report") + 1]).write_text(json.dumps({"install": [{
            "metadata": {"name": "semgrep", "version": toolchain.VERSIONS["semgrep"]},
            "download_info": {"url": "https://example.invalid/semgrep.whl", "archive_info": {"hashes": {"sha256": "a" * 64}}},
        }]}))
        return ProcessResult(0, "", "", 1)

    monkeypatch.setattr(toolchain, "__file__", str(package / "toolchain.py"))
    monkeypatch.setattr(toolchain.sys, "frozen", True, raising=False)
    monkeypatch.setattr(toolchain, "external_tool_loader", nullcontext)
    monkeypatch.setattr(toolchain, "run_process", process)
    monkeypatch.setattr('security_runtime.engine_probe.run_process', process)
    monkeypatch.setattr(toolchain.urllib.request, "urlopen", download)
    monkeypatch.setattr(toolchain.shutil, "which", lambda name: None)
    monkeypatch.setenv("SECURITY_RUNTIME_DATA_DIR", str(root))
    monkeypatch.setenv("SECURITY_RUNTIME_OFFLINE", "0")
    monkeypatch.delenv("SECURITY_RUNTIME_SEMGREP_PATH", raising=False)
    monkeypatch.delenv("SECURITY_RUNTIME_CONFIG", raising=False)
    return root, state, archive, relative


def test_frozen_first_semgrep_install_and_bootstrap_reuse(frozen_install):
    root, state, archive, relative = frozen_install
    archive()
    assert not root.exists()
    manager = ToolManager()
    assert manager.root == root and not manager.managed_path("semgrep").exists()
    assert "cpython" not in manager.versions and "cpython" not in toolchain.BUILTIN_ENGINES
    result = manager.ensure("semgrep", offline=False)
    assert result.status == ToolStatus.READY, result.detail
    assert state["downloads"] == 1
    assert any(args[1:3] == ["-m", "venv"] for args in state["calls"])
    assert any(args[1:4] == ["-m", "pip", "install"] for args in state["calls"])
    assert all(('--only-binary=:all:' in args) == (toolchain.sys.platform == 'darwin')
               for args in state['calls'] if args[1:4] == ['-m', 'pip', 'install'])
    python_metadata = next((root / "python").rglob("metadata.json"))
    python = python_metadata.parent / relative
    metadata = json.loads(python_metadata.read_text())
    assert metadata["binary_sha256"] == sha256_file(python)
    assert metadata["engine_id"] == "cpython-bootstrap"
    semgrep_metadata = root / "engines/semgrep" / manager.versions["semgrep"] / "metadata.json"
    assert json.loads(semgrep_metadata.read_text())["executable_sha256"] == sha256_file(Path(result.path))
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in (python_metadata, semgrep_metadata, python)}
    calls = len(state["calls"])
    fresh_manager = ToolManager()
    assert fresh_manager.prepare_python_runtime() == python
    assert fresh_manager.ensure("semgrep", offline=True).status == ToolStatus.READY
    assert state["downloads"] == 1
    assert all(args[1:] == ["--version"] for args in state["calls"][calls:])
    assert all((p.read_bytes(), p.stat().st_mtime_ns) == saved for p, saved in before.items())
    assert "cpython" not in fresh_manager.versions
    # Reuse still verifies the actual binary, not just the installation marker.
    python.write_bytes(b"tampered executable")
    assert fresh_manager.prepare_python_runtime() == python
    assert state["downloads"] == 2 and sha256_file(python) == metadata["binary_sha256"]


@pytest.mark.skipif(__import__('sys').platform != 'darwin', reason='macOS source Semgrep environment')
def test_macos_source_semgrep_uses_pinned_bootstrap_instead_of_copying_python(frozen_install, monkeypatch):
    root, state, archive, _ = frozen_install
    archive()
    monkeypatch.setattr(toolchain.sys, 'frozen', False)
    result = ToolManager().ensure('semgrep', offline=False)
    assert result.status == ToolStatus.READY, result.detail
    assert state['downloads'] == 1
    assert any(args[1:3] == ['-m', 'venv'] for args in state['calls'])


@pytest.mark.parametrize("failure", ["version", "checksum", "license"])
def test_frozen_bootstrap_rejects_invalid_input_before_venv(frozen_install, failure):
    root, state, archive, _ = frozen_install
    if failure == "version":
        state["version"] = "3.11.0"
    elif failure == "checksum":
        state["bad_sha"] = True
    else:
        state["license"] = False
    archive()
    result = ToolManager().ensure("semgrep", offline=False)
    assert result.status == ToolStatus.BROKEN
    assert not any(args[1:3] == ["-m", "venv"] for args in state["calls"])
    assert not list(root.rglob("metadata.json"))
