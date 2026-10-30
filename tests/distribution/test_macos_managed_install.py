"""Focused delivery tests; these never configure the developer's editor."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "distribution/macos/managed_install.py"
SPEC = importlib.util.spec_from_file_location("macos_managed_install", SOURCE)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def tar_payload(tmp_path, entries):
    archive = tmp_path / "payload.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(content)
                bundle.addfile(info, io.BytesIO(content))
            else:
                info.linkname = content.decode() if content else ""
                bundle.addfile(info)
    return archive, installer.digest(archive)


@pytest.mark.parametrize("name,kind,content", [
    ("../escape", tarfile.REGTYPE, b"x"),
    ("/absolute", tarfile.REGTYPE, b"x"),
    ("a/../../escape", tarfile.REGTYPE, b"x"),
    ("a\\escape", tarfile.REGTYPE, b"x"),
    ("a", tarfile.SYMTYPE, b"../escape"),
    ("a", tarfile.LNKTYPE, b"safe"),
    ("a", tarfile.FIFOTYPE, b""),
    ("a", tarfile.CHRTYPE, b""),
])
def test_rejects_unsafe_members_before_any_extraction(tmp_path, name, kind, content):
    archive, sha = tar_payload(tmp_path, [("safe", b"x", tarfile.REGTYPE), (name, content, kind)])
    destination = tmp_path / "unpacked"
    with pytest.raises(installer.InstallError):
        installer.safe_extract(archive, destination, sha)
    assert not destination.exists()
    assert not (tmp_path.parent / "escape").exists()


@pytest.mark.parametrize("entries", [
    [("same", b"1", tarfile.REGTYPE), ("same", b"2", tarfile.REGTYPE)],
    [("Name", b"1", tarfile.REGTYPE), ("name", b"2", tarfile.REGTYPE)],
    [("caf\u00e9", b"1", tarfile.REGTYPE), ("cafe\u0301", b"2", tarfile.REGTYPE)],
    [("parent", b"1", tarfile.REGTYPE), ("parent/child", b"2", tarfile.REGTYPE)],
])
def test_rejects_archive_path_collisions(tmp_path, entries):
    archive, sha = tar_payload(tmp_path, entries)
    with pytest.raises(installer.InstallError):
        installer.safe_extract(archive, tmp_path / "unpacked", sha)


def test_hash_failure_and_existing_destination_never_extract(tmp_path):
    archive, sha = tar_payload(tmp_path, [("safe", b"expected", tarfile.REGTYPE)])
    target = tmp_path / "unpacked"
    with pytest.raises(installer.InstallError, match="SHA256"):
        installer.safe_extract(archive, target, "0" * 64)
    target.mkdir()
    sentinel = target / "user"
    sentinel.write_text("keep")
    with pytest.raises(installer.InstallError, match="覆盖"):
        installer.safe_extract(archive, target, sha)
    assert sentinel.read_text() == "keep"


def test_extracts_regular_files_and_enforces_size_limit(tmp_path, monkeypatch):
    archive, sha = tar_payload(tmp_path, [("dir/file", b"verified", tarfile.REGTYPE)])
    installer.safe_extract(archive, tmp_path / "ok", sha)
    assert (tmp_path / "ok/dir/file").read_bytes() == b"verified"
    monkeypatch.setattr(installer, "MAX_BYTES", 4)
    with pytest.raises(installer.InstallError, match="大小"):
        installer.safe_extract(archive, tmp_path / "too-large", sha)


def make_payload(tmp_path, *, build_id="a" * 64):
    payload = tmp_path / ("payload-" + build_id[:8])
    payload.mkdir()
    shutil.copyfile(SOURCE, payload / "managed_install.py")
    (payload / "wheelhouse").mkdir()
    wheel = payload / "wheelhouse/ai_security_runtime-0.3.11-py3-none-any.whl"
    wheel.write_bytes(b"Test fixture; subprocess execution is mocked.")
    (payload / "requirements.txt").write_text(
        "ai-security-runtime==0.3.11 --hash=sha256:" + installer.digest(wheel) + "\n")
    manifest = {
        "schema": installer.SCHEMA, "release_tag": installer.RELEASE_TAG,
        "version": "0.3.11", "platform": "macos-arm64",
        "source_commit": "b" * 40, "build_id": build_id,
        "files": {path.relative_to(payload).as_posix(): installer.digest(path)
                  for path in payload.rglob("*") if path.is_file()},
    }
    (payload / "manifest.json").write_text(json.dumps(manifest))
    return payload, manifest


def test_payload_verifies_every_file_and_rejects_added_file(tmp_path):
    payload, manifest = make_payload(tmp_path)
    assert installer.verify_payload(payload, "macos-arm64") == manifest
    (payload / "wheelhouse/extra.whl").write_text("unexpected")
    with pytest.raises(installer.InstallError, match="清单"):
        installer.verify_payload(payload, "macos-arm64")


def test_payload_rejects_tampered_dependency_platform_and_installer(tmp_path):
    payload, manifest = make_payload(tmp_path)
    with pytest.raises(installer.InstallError, match="平台"):
        installer.verify_payload(payload, "macos-x64")
    requirements = payload / "requirements.txt"
    original = requirements.read_bytes()
    requirements.write_bytes(original + b"--extra-index-url https://other.invalid\n")
    with pytest.raises(installer.InstallError, match="校验"):
        installer.verify_payload(payload, "macos-arm64")
    manifest["files"]["requirements.txt"] = installer.digest(requirements)
    (payload / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(installer.InstallError, match="固定"):
        installer.verify_payload(payload, "macos-arm64")
    requirements.write_bytes(original)
    manifest["files"]["requirements.txt"] = installer.digest(requirements)
    (payload / "managed_install.py").write_text("print('other installer')")
    manifest["files"]["managed_install.py"] = installer.digest(payload / "managed_install.py")
    (payload / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(installer.InstallError, match="安装器"):
        installer.verify_payload(payload, "macos-arm64")


def mock_runtime(monkeypatch, manifest, *, install_ready=True, pip_exit=0, identity_good=True):
    commands = []
    class Builder:
        def __init__(self, **kwargs):
            assert kwargs == {"with_pip": True, "symlinks": installer.sys.platform == "darwin"}
        def create(self, root):
            folder = root / ("Scripts" if installer.os.name == "nt" else "bin")
            folder.mkdir(parents=True)
            (folder / ("python.exe" if installer.os.name == "nt" else "python")).write_text("fixture")
    monkeypatch.setattr(installer.venv, "EnvBuilder", Builder)
    def run(command, **kwargs):
        commands.append(command)
        if "pip" in command:
            return subprocess.CompletedProcess(command, pip_exit, b"pip output", b"")
        if "runtime-info" in command:
            info = dict(version=manifest["version"], build_identity={
                **{k: manifest[k] for k in ("version", "build_id", "source_commit")},
                "status": "IDENTIFIED" if identity_good else "DEV",
                "delivery_kind": "managed-wheel",
                "integrity": "PACKAGE_CONTENT_HASHES_VERIFIED"})
            return subprocess.CompletedProcess(command, 0, json.dumps(info).encode(), b"")
        assert command[-3:] == ["install", "cursor", "--json"]
        receipt = {"installation": {"contract": "personal-install-v1",
                   "status": "INSTALLED" if install_ready else "PREFLIGHT_BLOCKED",
                   "local_files_ready": install_ready, "scan_ready": False,
                   "message": "local configuration"},
                   "background_preparation": {"status": "RUNNING"},
                   "diagnostics": [] if install_ready else ["OWNERSHIP_CONFLICT"]}
        return subprocess.CompletedProcess(command, 2, json.dumps(receipt).encode(), b"")
    monkeypatch.setattr(installer, "run", run)
    return commands


def test_offline_hash_install_and_repeat_are_idempotent(tmp_path, monkeypatch, capsys):
    payload, manifest = make_payload(tmp_path)
    calls = mock_runtime(monkeypatch, manifest)
    root = tmp_path / "installed"
    installer.install(payload, root, "cursor", "macos-arm64")
    pip = next(command for command in calls if "pip" in command)
    for flag in ("--isolated", "--no-index", "--no-cache-dir", "--require-hashes", "--only-binary=:all:"):
        assert flag in pip
    assert "--dev" not in sum(calls, [])
    assert "--path" not in sum(calls, [])
    before = (root / "security-check").read_bytes()
    installer.install(payload, root, "cursor", "macos-arm64")
    assert sum("pip" in command for command in calls) == 1
    assert (root / "security-check").read_bytes() == before
    assert installer.read_json(root / "active.json")["build_id"] == manifest["build_id"]
    output = capsys.readouterr().out
    assert "尚未全部准备完成" in output
    assert "真实连接和项目路径需要重启后确认" in output


@pytest.mark.parametrize("pip_exit,identity_good,install_ready", [
    (1, True, True), (0, False, True), (0, True, False),
])
def test_failed_candidate_preserves_existing_active_entry(tmp_path, monkeypatch,
                                                         pip_exit, identity_good, install_ready):
    first, first_manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, first_manifest)
    root = tmp_path / "installed"
    installer.install(first, root, "cursor", "macos-arm64")
    previous_launcher = (root / "security-check").read_bytes()
    previous_active = (root / "active.json").read_bytes()
    second, second_manifest = make_payload(tmp_path, build_id="c" * 64)
    mock_runtime(monkeypatch, second_manifest, pip_exit=pip_exit,
                 identity_good=identity_good, install_ready=install_ready)
    with pytest.raises(installer.InstallError):
        installer.install(second, root, "cursor", "macos-arm64")
    assert (root / "security-check").read_bytes() == previous_launcher
    assert (root / "active.json").read_bytes() == previous_active
    assert (root / "versions" / second_manifest["build_id"] / "owner.json").exists()


def test_retry_preserves_incomplete_environment(tmp_path, monkeypatch):
    payload, manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, manifest, pip_exit=1)
    root = tmp_path / "installed"
    with pytest.raises(installer.InstallError):
        installer.install(payload, root, "cursor", "macos-arm64")
    mock_runtime(monkeypatch, manifest)
    installer.install(payload, root, "cursor", "macos-arm64")
    assert len(list((root / "versions" / manifest["build_id"]).glob("venv-incomplete-*"))) == 1


def test_macos_venv_preserves_interpreter_symlinks(tmp_path, monkeypatch):
    monkeypatch.setattr(installer.sys, "platform", "darwin")
    payload, manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, manifest)
    installer.install(payload, tmp_path / "installed", "cursor", "macos-arm64")


def test_upgrade_uses_one_atomic_pointer_and_keeps_stable_launcher(tmp_path, monkeypatch):
    first, first_manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, first_manifest)
    root = tmp_path / "installed"
    installer.install(first, root, "cursor", "macos-arm64")
    before = (root / "security-check").read_bytes()
    second, second_manifest = make_payload(tmp_path, build_id="c" * 64)
    mock_runtime(monkeypatch, second_manifest)
    installer.install(second, root, "cursor", "macos-arm64")
    assert (root / "security-check").read_bytes() == before
    assert installer.read_json(root / "active.json")["build_id"] == "c" * 64


def test_changed_bootstrap_path_refused_before_host_install(tmp_path, monkeypatch):
    first, first_manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, first_manifest)
    root = tmp_path / "installed"
    installer.install(first, root, "cursor", "macos-arm64")
    previous_launcher = (root / "security-check").read_bytes()
    previous_active = (root / "active.json").read_bytes()
    second, second_manifest = make_payload(tmp_path, build_id="c" * 64)
    calls = mock_runtime(monkeypatch, second_manifest)
    monkeypatch.setattr(installer.sys, "executable", str(tmp_path / "different-python/bin/python3"))
    with pytest.raises(installer.InstallError, match="不同的运行环境"):
        installer.install(second, root, "cursor", "macos-arm64")
    assert not calls
    assert not (root / "versions" / second_manifest["build_id"]).exists()
    assert (root / "security-check").read_bytes() == previous_launcher
    assert (root / "active.json").read_bytes() == previous_active


def test_activation_write_failure_keeps_existing_active_pointer(tmp_path, monkeypatch):
    first, first_manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, first_manifest)
    root = tmp_path / "installed"
    installer.install(first, root, "cursor", "macos-arm64")
    old_active = (root / "active.json").read_bytes()
    old_launcher = (root / "security-check").read_bytes()
    second, second_manifest = make_payload(tmp_path, build_id="c" * 64)
    mock_runtime(monkeypatch, second_manifest)
    atomic = installer.atomic_json
    def fail_active(path, value):
        if path.name == "active.json":
            raise OSError("simulated disk failure")
        atomic(path, value)
    monkeypatch.setattr(installer, "atomic_json", fail_active)
    with pytest.raises(OSError, match="disk"):
        installer.install(second, root, "cursor", "macos-arm64")
    assert (root / "active.json").read_bytes() == old_active
    assert (root / "security-check").read_bytes() == old_launcher


def test_interrupted_first_pointer_write_can_be_retried(tmp_path, monkeypatch):
    payload, manifest = make_payload(tmp_path)
    mock_runtime(monkeypatch, manifest)
    root = installer.validate_root(tmp_path / "installed")
    (root / "security-check").write_bytes(installer.launcher_bytes(root))
    # Simulate process termination after the immutable launcher was written,
    # before there was any active candidate.
    installer.install(payload, root, "cursor", "macos-arm64")
    assert installer.read_json(root / "active.json")["build_id"] == manifest["build_id"]


def test_unowned_or_modified_launcher_is_never_overwritten(tmp_path, monkeypatch):
    payload, manifest = make_payload(tmp_path)
    calls = mock_runtime(monkeypatch, manifest)
    root = tmp_path / "installed"
    root.mkdir()
    launcher = root / "security-check"
    launcher.write_text("user content")
    with pytest.raises(installer.InstallError, match="归属"):
        installer.install(payload, root, "cursor", "macos-arm64")
    assert launcher.read_text() == "user content"
    assert not calls
    launcher.unlink()
    installer.install(payload, root, "cursor", "macos-arm64")
    launcher.write_text("user update")
    with pytest.raises(installer.InstallError, match="修改"):
        installer.install(payload, root, "cursor", "macos-arm64")
    assert launcher.read_text() == "user update"


def test_symbolic_destination_is_rejected(tmp_path):
    target = tmp_path / "user-directory"
    target.mkdir()
    alias = tmp_path / "installed"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("Host does not permit creating symlinks")
    with pytest.raises(installer.InstallError, match="符号链接"):
        installer.validate_root(alias)
    assert not list(target.iterdir())
