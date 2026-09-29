from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
import asyncio
from pathlib import Path

import pytest

from security_runtime.integration_config import IntegrationConfigError, IntegrationConfigStore, SERVER_NAME
from security_runtime.integration_state import DogfoodEvent, IntegrationStateStore
from security_runtime.integrations import CursorIntegration, IntegrationStatusCode, WorkBuddyIntegration
from security_runtime.mcp_config import json_config, server_entry, toml_config
from security_runtime.mcp_verify import verify_mcp_entry
from security_runtime.cli import main


def git_repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Test"], check=True)
    (path / "example.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(path), "add", "example.py"], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-qm", "initial"], check=True)
    return path


def test_config_merge_idempotency_and_uninstall(tmp_path):
    repo = git_repo(tmp_path / "project")
    store = IntegrationConfigStore(repo, ".cursor/mcp.json")
    store.path.parent.mkdir()
    original = {"other": {"setting": 1}, "mcpServers": {"another": {"command": "own"}}}
    store.path.write_text(json.dumps(original), encoding="utf-8")
    entry = server_entry(repo, "cursor")
    assert store.install(entry, lambda: True)
    assert store.load()["mcpServers"][SERVER_NAME] == entry
    assert store.load()["mcpServers"]["another"] == original["mcpServers"]["another"]
    assert not store.backup.exists()
    before = store.path.read_bytes()
    assert not store.install(entry, lambda: True)
    assert store.path.read_bytes() == before
    assert store.uninstall()
    assert store.load() == original


def test_config_invalid_and_rollback(tmp_path):
    repo = git_repo(tmp_path / "project")
    store = IntegrationConfigStore(repo, ".workbuddy/mcp.json")
    store.path.parent.mkdir()
    store.path.write_text("{broken", encoding="utf-8")
    with pytest.raises(IntegrationConfigError, match="invalid JSON"):
        store.install(server_entry(repo, "workbuddy"), lambda: True)
    assert store.path.read_text(encoding="utf-8") == "{broken"
    store.path.write_text('{"mcpServers":{"mine":{"command":"keep"}}}', encoding="utf-8")
    before = store.path.read_bytes()
    with pytest.raises(IntegrationConfigError, match="verification failed"):
        store.install(server_entry(repo, "workbuddy"), lambda: False)
    assert store.path.read_bytes() == before
    assert not store.backup.exists()


def test_native_setup_and_state(tmp_path, monkeypatch):
    repo = git_repo(tmp_path / "project")
    state = IntegrationStateStore(tmp_path / "state.db")
    monkeypatch.setattr("security_runtime.integrations.verify_mcp_entry", lambda entry, workspace: (True, "verified"))
    for adapter_class, config in ((CursorIntegration, ".cursor/mcp.json"), (WorkBuddyIntegration, ".workbuddy/mcp.json")):
        adapter = adapter_class(state)
        assert adapter.status(repo).status in {IntegrationStatusCode.NOT_INSTALLED, IntegrationStatusCode.DETECTED}
        assert adapter.install(repo).status == IntegrationStatusCode.NEEDS_RESTART
        record = state.get(adapter.integration_id, repo)
        assert record["binding"]["root"] == str(repo.resolve())
        entry = json.loads((repo / config).read_text(encoding="utf-8"))["mcpServers"][SERVER_NAME]
        assert entry["env"]["SECURITY_RUNTIME_WORKSPACE"] == str(repo.resolve())
        assert adapter.uninstall(repo).status in {IntegrationStatusCode.NOT_INSTALLED, IntegrationStatusCode.DETECTED}
        assert state.get(adapter.integration_id, repo) is None


def test_repair_updates_only_own_command(tmp_path, monkeypatch):
    repo = git_repo(tmp_path / "project")
    state = IntegrationStateStore(tmp_path / "state.db")
    monkeypatch.setattr("security_runtime.integrations.verify_mcp_entry", lambda entry, workspace: (True, "verified"))
    adapter = CursorIntegration(state)
    adapter.install(repo)
    config = IntegrationConfigStore(repo, adapter.config_relative)
    value = config.load()
    value["mcpServers"]["another"] = {"command": "untouched"}
    value["mcpServers"][SERVER_NAME]["command"] = "C:/old/security-check.exe"
    config.path.write_text(json.dumps(value), encoding="utf-8")
    assert adapter.status(repo).status == IntegrationStatusCode.BROKEN
    assert adapter.repair(repo).status == IntegrationStatusCode.NEEDS_RESTART
    assert config.load()["mcpServers"]["another"] == {"command": "untouched"}
    assert config.load()["mcpServers"][SERVER_NAME]["command"] == server_entry(repo, "cursor")["command"]


def test_generic_formats_and_stats(tmp_path):
    repo = git_repo(tmp_path / "project")
    assert json.loads(json_config(repo))["mcpServers"][SERVER_NAME]["env"]["SECURITY_RUNTIME_WORKSPACE"] == str(repo.resolve())
    assert tomllib.loads(toml_config(repo))["mcp_servers"]["ai_security_runtime"]["env"]["SECURITY_RUNTIME_WORKSPACE"] == str(repo.resolve())
    state = IntegrationStateStore(tmp_path / "state.db")
    state.event(DogfoodEvent("cursor", str(repo), "quick", 120, 2, "PARTIAL"))
    state.event(DogfoodEvent("cursor", str(repo), verify_result="RESOLVED"))
    assert state.stats()["scans"] == 1
    assert state.stats()["issues_found"] == 2
    assert state.stats()["issues_resolved"] == 1


def test_detection_and_clipboard_fallback(tmp_path, monkeypatch, capsys):
    repo = git_repo(tmp_path / "project")
    executable = tmp_path / "WorkBuddyAI.exe"
    executable.write_bytes(b"test")
    monkeypatch.setenv("SECURITY_RUNTIME_WORKBUDDY_EXECUTABLE", str(executable))
    assert WorkBuddyIntegration(IntegrationStateStore(tmp_path / "state.db")).detect()
    monkeypatch.setattr("security_runtime.cli.copy_to_clipboard", lambda value: False)
    assert main(["mcp", "config", "--path", str(repo), "--copy"]) == 0
    output = capsys.readouterr().out
    assert "Clipboard unavailable" in output
    assert json.loads(output[output.index("{"):])["mcpServers"][SERVER_NAME]["args"] == ["mcp"]


def test_real_sdk_stdio_bound_workspace(tmp_path, monkeypatch):
    repo = git_repo(tmp_path / "project")
    other = git_repo(tmp_path / "other")
    (repo / "example.py").write_text("value = 2\n", encoding="utf-8")
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SECURITY_RUNTIME_OFFLINE", "1")
    entry = server_entry(repo, "cursor")
    ok, detail = verify_mcp_entry(entry, other, call_scan_diff=True)
    assert ok, detail
    generic = json.loads(json_config(repo))["mcpServers"][SERVER_NAME]
    ok, detail = verify_mcp_entry(generic, other, call_scan_diff=True)
    assert ok, detail

    async def session_check():
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        environment = dict(os.environ, **entry["env"])
        params = StdioServerParameters(command=entry["command"], args=entry["args"],
                                      cwd=other, env=environment)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                listed = await client.list_tools()
                assert {"scan_diff", "scan_project", "get_findings", "generate_fix", "verify"} <= {item.name for item in listed.tools}
                scan = await client.call_tool("scan_diff", {})
                assert not scan.isError
                payload = scan.structuredContent or json.loads(scan.content[0].text)
                if "result" in payload:
                    payload = payload["result"]
                assert payload["workspace"] == str(repo.resolve())
                rejected = await client.call_tool("scan_diff", {"workspace_path": str(other)})
                assert rejected.isError

    asyncio.run(session_check())
