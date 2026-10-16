from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "create_codex_pilot_demo.py"
SPEC = importlib.util.spec_from_file_location("create_codex_pilot_demo", SCRIPT)
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


def _run(project, *arguments):
    return subprocess.run([sys.executable, *arguments], cwd=project, text=True,
                          encoding="utf-8", capture_output=True, timeout=30)


def test_creates_new_business_project_without_host_configuration(tmp_path):
    root = demo.create_demo(tmp_path / "orders")
    assert root.is_absolute()
    assert {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()} == set(demo.FILES)
    assert not (root / ".git").exists()
    assert not (root / ".codex").exists()
    assert not (root / "AGENTS.md").exists()
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "任务一" in readme and "任务二" in readme and "任务三" in readme
    assert "不使用固定补丁重放" in readme


@pytest.mark.parametrize("existing_kind", ["empty", "nonempty", "file"])
def test_refuses_existing_root_without_changing_contents(tmp_path, existing_kind):
    root = tmp_path / "existing"
    if existing_kind == "file":
        root.write_bytes(b"existing bytes")
        original = {"file": root.read_bytes()}
    else:
        root.mkdir()
        if existing_kind == "nonempty":
            (root / "important.txt").write_bytes(b"keep this")
        original = {p.name: p.read_bytes() for p in root.iterdir()}
    with pytest.raises(FileExistsError):
        demo.create_demo(root)
    actual = ({"file": root.read_bytes()} if root.is_file()
              else {p.name: p.read_bytes() for p in root.iterdir()})
    assert actual == original


def test_generated_initial_tests_really_pass(tmp_path):
    root = demo.create_demo(tmp_path / "orders")
    result = _run(root, "-m", "unittest", "discover", "-s", "tests", "-v")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Ran 9 tests" in result.stderr


def test_cli_queries_preserve_owner_boundary(tmp_path):
    root = demo.create_demo(tmp_path / "orders")
    listed = _run(root, "-m", "orderdesk", "list", "--user", "alice")
    assert listed.returncode == 0, listed.stderr
    assert [row["id"] for row in json.loads(listed.stdout)] == [
        "order-1001", "order-1002", "order-1003"]
    own = _run(root, "-m", "orderdesk", "receipt", "--user", "alice", "--order", "order-1001")
    assert own.returncode == 0
    assert json.loads(own.stdout)["receipt"] == "R-1001"
    for command in ("details", "receipt"):
        foreign = _run(root, "-m", "orderdesk", command, "--user", "alice", "--order", "order-2001")
        absent = _run(root, "-m", "orderdesk", command, "--user", "alice", "--order", "missing")
        assert foreign.returncode == absent.returncode == 1
        assert foreign.stdout == absent.stdout


def test_cli_generator_supports_new_nested_destination(tmp_path):
    root = tmp_path / "new parent" / "orders"
    result = subprocess.run([sys.executable, str(SCRIPT), str(root)], text=True,
                            encoding="utf-8", capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert Path(receipt["root"]) == root
    assert receipt["git_initialized"] is False
    refused = subprocess.run([sys.executable, str(SCRIPT), str(root)], text=True,
                             encoding="utf-8", capture_output=True, timeout=30)
    assert refused.returncode != 0
    assert "Refusing to overwrite" in refused.stderr
