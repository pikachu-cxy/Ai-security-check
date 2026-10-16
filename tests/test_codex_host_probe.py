"""Whole-request inventory checks cannot omit additional tool definitions."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
probe = importlib.import_module("codex_host_probe")


def test_request_inventory_visits_nested_additional_tools_without_prompt_retention():
    body = {"tools": [{"type": "function", "name": "read_security_batch_context"}],
            "input": [{"type": "message", "content": [{"type": "additional_tools", "tools": [
                {"type": "namespace", "name": "collaboration", "tools": [
                    {"type": "function", "name": "spawn_agent"}]}]}],
                       "text": "do not retain this prompt"}]}
    inventory = probe.request_tool_inventory(body)
    assert "collaboration.spawn_agent" in inventory["flattened_tool_names"]
    assert "request.input[0].content[0].tools" in inventory["tool_container_paths"]
    assert "do not retain this prompt" not in str(inventory)


def test_request_inventory_handles_direct_additional_tools_and_malformed_records():
    inventory = probe.request_tool_inventory({"additional_tools": [
        {"type": "function", "name": "shell"}], "tools": ["unknown"]})
    assert inventory["flattened_tool_names"] == ["shell"]
    assert inventory["malformed_tool_entries"] == 1


def test_request_inventory_reports_nested_namespace_inventory_once():
    inventory = probe.request_tool_inventory({"tools": [{"type": "namespace", "name": "functions", "tools": [
        {"type": "function", "name": "exec"}, {"type": "function", "name": "wait"}]}]})
    # Namespace descendants are covered by their enclosing schema.
    assert inventory["flattened_tool_names"][:2] == ["functions.exec", "functions.wait"]
    assert inventory["tool_container_paths"] == ["request.tools"]


def test_nonlist_tools_container_cannot_be_mistaken_for_no_extra_tools():
    inventory = probe.request_tool_inventory({"tools": [], "input": [
        {"additional_tools": {"type": "function", "name": "shell"}}]})
    assert inventory["malformed_tool_entries"] == 1


def test_override_disables_inherited_servers_without_retaining_values(monkeypatch, tmp_path):
    (tmp_path / "config.toml").write_text(
        '[mcp_servers.review-reader]\ncommand="secret-command"\n'
        '[mcp_servers.review-reader.env]\nAPI_KEY="never-retain-this"\n', encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    config = probe.readonly_host_config()
    assert config["mcp_servers.review-reader.enabled"] == "false"
    assert config["agents.enabled"] == "false"
    assert config["features.code_mode.enabled"] == "false"
    assert config["features.code_mode.direct_only_tool_namespaces"] == '["functions"]'
    assert "secret-command" not in str(config)
    assert "never-retain-this" not in str(config)


def test_unsupported_server_key_fails_closed_before_starting_host(monkeypatch, tmp_path):
    (tmp_path / "config.toml").write_text(
        '[mcp_servers."unsafe.server"]\ncommand="never-retain-this"\n', encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))
    with pytest.raises(ValueError, match="cannot be safely overridden"):
        probe.readonly_host_config()
