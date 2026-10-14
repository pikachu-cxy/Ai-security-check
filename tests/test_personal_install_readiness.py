"""Product installation owns engine and data readiness after configuration.

No test downloads engines, updates the real cache, or runs a target project.
"""
from __future__ import annotations

import copy
import json
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.cli import main
import security_runtime.personal_install as personal
from test_personal_install import portable, installed, projects, skill
from security_runtime.delivery import EXE


def readiness(*, ready=True, freshness="FRESH", version="0.74.0"):
    data_ready = ready and freshness == "FRESH"
    versions = {"semgrep": "1.178.0", "gitleaks": "8.30.0", "trivy": version}
    return {
        "contract": "installation-readiness-v1",
        "status": "READY" if data_ready else "PARTIAL",
        "ready": data_ready,
        "message": "代码、密钥和依赖检查已准备完成。" if data_ready else "依赖检查的数据尚未准备完成，请重新运行产品安装。",
        "network_allowed": False,
        "tools": {name: {"status": "READY", "version": value, "expected_version": value,
                          "ready": True} for name, value in versions.items()},
        "vulnerability_db": {"status": "READY", "freshness": freshness,
                              "ready": data_ready, "cached_usable": True},
        "failures": [],
    }


def mock_prepare(monkeypatch, data):
    import security_runtime.install_readiness as module
    calls = []

    def prepare(**kwargs):
        calls.append(kwargs)
        return copy.deepcopy(data)

    monkeypatch.setattr(module, "prepare_installation_readiness", prepare)
    # Both module imports and direct imports are deliberately supported here;
    # the public installation behavior is the contract under test.
    monkeypatch.setattr(personal, "prepare_installation_readiness", prepare, raising=False)
    return calls


@pytest.mark.parametrize("offline", [False, True])
def test_python_install_prepares_once_after_successful_configuration(installed, monkeypatch, offline):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, "GlobalCodexIntegration", lambda **kwargs: installed)
    calls = mock_prepare(monkeypatch, readiness())
    data = personal.install_personal_codex(offline=offline)
    assert len(calls) == 1 and calls[0]["offline"] is True
    assert data["installation"]["local_files_ready"] is True
    assert data["installation"]["scan_ready"] is True
    assert data["scan_readiness"]["status"] == "READY"
    assert data["overall"] == "CONFIGURED"
    assert not data["execution"]["scanner_run"]


def test_repeat_install_rechecks_once_and_preserves_user_files(installed, monkeypatch):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, "GlobalCodexIntegration", lambda **kwargs: installed)
    calls = mock_prepare(monkeypatch, readiness())
    first = personal.install_personal_codex()
    assert first["installation"]["scan_ready"]
    config = installed.home / "config.toml"
    original = (config.read_bytes(), config.stat().st_mtime_ns)
    second = personal.install_personal_codex()
    assert second["installation"]["scan_ready"] and len(calls) == 2
    assert original == (config.read_bytes(), config.stat().st_mtime_ns)


def test_configuration_conflict_never_prepares_or_overwrites_user_content(installed, monkeypatch):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, "GlobalCodexIntegration", lambda **kwargs: installed)
    installed.home.mkdir()
    config = installed.home / "config.toml"
    raw = b'[mcp_servers.ai_security_runtime]\ncommand="user-custom-command"\n'
    config.write_bytes(raw)
    calls = mock_prepare(monkeypatch, readiness())
    data = personal.install_personal_codex()
    assert not calls and not data["installation"]["local_files_ready"]
    assert data["overall"] == "BROKEN" and config.read_bytes() == raw


def test_stale_preparation_keeps_committed_configuration_and_can_retry(installed, monkeypatch):
    import security_runtime.global_integration as module
    monkeypatch.setattr(module, "GlobalCodexIntegration", lambda **kwargs: installed)
    mock_prepare(monkeypatch, readiness(ready=False, freshness="STALE"))
    partial = personal.install_personal_codex(offline=True)
    assert partial["overall"] == "DEGRADED"
    assert partial["installation"]["local_files_ready"] is True
    assert partial["installation"]["scan_ready"] is False
    assert partial["scan_readiness"]["status"] == "PARTIAL"
    config = installed.home / "config.toml"
    original = config.read_bytes()
    calls = mock_prepare(monkeypatch, readiness())
    ready = personal.install_personal_codex()
    assert ready["installation"]["scan_ready"] and len(calls) == 1
    assert config.read_bytes() == original


def test_portable_prepares_with_new_validated_slot_after_configuration(installed, portable, monkeypatch):
    package, root = portable
    calls, stages = [], []
    response = readiness(version="0.75.0")

    def run(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        assert str(root / "versions") in argv[0]
        if argv[1:4] == ["setup", "codex", "--json"]:
            assert kwargs["stdin"] is subprocess.DEVNULL
            assert kwargs["timeout"] == 120
            return SimpleNamespace(returncode=0, stdout=json.dumps(personal.setup_personal_codex(installed)).encode(), stderr=b"")
        assert argv[1:] == ["prepare-installation", "--json", "--offline"]
        assert kwargs["timeout"] == 45
        assert kwargs['env']['SECURITY_RUNTIME_INSTALL_PROGRESS'] == '1'
        return SimpleNamespace(returncode=0, stdout=json.dumps(response).encode(), stderr=b"PRIVATE-SCANNER-OUTPUT")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(personal, 'run_process', run)
    data = personal.install_personal_codex(bundle=package, root=root, progress=stages.append, offline=True)
    assert len(calls) == 2 and calls[0][0][0] == calls[1][0][0]
    assert data["installation"]["local_files_ready"] and data["installation"]["scan_ready"]
    assert data["scan_readiness"] == response
    assert "PRIVATE-SCANNER-OUTPUT" not in json.dumps(data)


@pytest.mark.parametrize("failure", ["partial", "timeout", "os-error", "invalid-json", "contradictory", "wrong-exit"])
def test_preparation_failure_after_portable_setup_is_degraded_and_keeps_configuration(installed, portable, monkeypatch, failure):
    package, root = portable

    def run(argv, **kwargs):
        if argv[1] == "setup":
            return SimpleNamespace(returncode=0, stdout=json.dumps(personal.setup_personal_codex(installed)).encode(), stderr=b"")
        if failure == "timeout":
            raise subprocess.TimeoutExpired("fixed", kwargs["timeout"], output=b"PRIVATE-PREPARE-OUTPUT")
        if failure == "os-error":
            raise OSError("PRIVATE-PREPARE-OUTPUT")
        response = readiness(ready=False, freshness="STALE") if failure == "partial" else readiness()
        if failure == "contradictory":
            response["vulnerability_db"]["freshness"] = "STALE"
        output = b"PRIVATE-PREPARE-OUTPUT" if failure == "invalid-json" else json.dumps(response).encode()
        return SimpleNamespace(returncode=2 if failure in {"partial", "wrong-exit"} else 0,
                               stdout=output, stderr=b"PRIVATE-PREPARE-OUTPUT")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(personal, 'run_process', run)
    data = personal.install_personal_codex(bundle=package, root=root, offline=True)
    assert data["overall"] == "DEGRADED"
    assert data["installation"]["local_files_ready"] is True
    assert data["installation"]["scan_ready"] is False
    assert data["scan_readiness"]["status"] != "READY"
    assert (installed.home / "config.toml").is_file()
    assert (root / 'launcher' / EXE).is_file()
    assert data["installation"]["status"] not in {"ROLLED_BACK", "RECOVERY_REQUIRED"}
    assert "PRIVATE-PREPARE-OUTPUT" not in json.dumps(data)


@pytest.mark.parametrize("ready", [True, False])
def test_install_cli_truthfully_reports_scan_readiness_in_one_json_receipt(monkeypatch, capsys, ready):
    data = {"integration": "codex", "scope": "GLOBAL", "overall": "CONFIGURED" if ready else "DEGRADED",
            "installation": {"contract": personal.CONTRACT, "status": "INSTALLED", "local_files_ready": True,
                             "scan_ready": ready, "message": "产品安装完成。" if ready else "配置已经保存，检查数据还未准备完成。"},
            "scan_readiness": readiness(ready=ready, freshness="FRESH" if ready else "STALE")}
    calls = []

    def install(**kwargs):
        calls.append(kwargs)
        return copy.deepcopy(data)

    monkeypatch.setattr(personal, "install_personal_codex", install)
    assert main(["install", "codex", "--json", "--offline"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == data and len(output.out.splitlines()) == 1
    assert calls[0]["offline"] is True
    if not ready:
        assert "扫描能力准备状态" in output.err
        assert "本地安装完成" in output.err
    assert "READY" not in output.err and "PARTIAL" not in output.err


@pytest.mark.parametrize("ready", [True, False])
def test_preparation_cli_is_single_receipt_and_reports_current_readiness(monkeypatch, capsys, ready):
    calls = mock_prepare(monkeypatch, readiness(ready=ready, freshness="FRESH" if ready else "STALE"))
    assert main(["prepare-installation", "--json", "--offline"]) == (0 if ready else 2)
    output = capsys.readouterr()
    assert json.loads(output.out)["ready"] is ready and len(output.out.splitlines()) == 1
    assert calls and calls[0]["offline"] is True
    assert "Traceback" not in output.out + output.err


@pytest.mark.parametrize("environment_offline,ready", [("0", True), ("1", False)])
def test_preparation_cli_without_offline_flag_checks_environment(monkeypatch, capsys, environment_offline, ready):
    monkeypatch.setenv("SECURITY_RUNTIME_OFFLINE", environment_offline)
    calls = mock_prepare(monkeypatch, readiness(ready=ready, freshness="FRESH" if ready else "STALE"))
    assert main(["prepare-installation", "--json"]) == (0 if ready else 2)
    output = capsys.readouterr()
    assert json.loads(output.out)["ready"] is ready and len(output.out.splitlines()) == 1
    assert len(calls) == 1 and calls[0]["offline"] is (environment_offline == "1")
    assert "Traceback" not in output.out + output.err


def test_plain_installation_feedback_does_not_show_component_enums(monkeypatch, capsys):
    data = {"integration": "codex", "scope": "GLOBAL", "overall": "DEGRADED",
            "installation": {"contract": personal.CONTRACT, "status": "NOT_READY",
                "local_files_ready": True, "scan_ready": False,
                "message": "产品配置已保存。漏洞数据已过期，本次更新未完成。重新运行产品安装即可重试。"},
            "scan_readiness": readiness(ready=False, freshness="STALE")}
    monkeypatch.setattr(personal, "install_personal_codex", lambda **kwargs: copy.deepcopy(data))
    assert main(["install", "codex", "--offline"]) == 0
    output = capsys.readouterr()
    assert data["installation"]["message"] in output.out
    assert all(term not in output.out + output.err for term in ("DEGRADED", "NOT_READY", "STALE", "PARTIAL"))
