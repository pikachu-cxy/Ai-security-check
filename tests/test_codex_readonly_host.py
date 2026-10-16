"""The real-host adapter must not silently fall back to a privileged model."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
host = importlib.import_module("codex_readonly_host")
probe = importlib.import_module("codex_host_probe")


def test_nested_orchestration_inventory_is_not_mistaken_for_zero_tools():
    tools = [{"type": "namespace", "name": "functions", "tools": [
        {"type": "custom", "name": "exec"}, {"type": "function", "name": "wait"}]},
        {"type": "namespace", "name": "collaboration", "tools": [
            {"type": "function", "name": "spawn_agent"}]}]
    assert probe.flatten_tool_names(tools) == [
        "functions.exec", "functions.wait", "collaboration.spawn_agent"]


@pytest.mark.parametrize("ready", [False, True])
def test_unsupported_host_never_reads_context_or_dispatches_model(tmp_path, ready):
    calls = []
    with pytest.raises(host.UnsupportedReadonlyHost) as caught:
        host.run_review("private prompt", {}, lambda **kwargs: calls.append(kwargs), tmp_path,
                        preflight={"ready_for_model": ready})
    assert calls == []
    assert caught.value.receipt["actual_model_calls"] == 0
    assert caught.value.receipt["usage"] is None
    assert caught.value.receipt["ready_for_model"] is False


def test_successful_dummy_provider_probe_cannot_authorize_live_provider(monkeypatch, tmp_path):
    monkeypatch.setattr(host, "probe_inventory", lambda *_args: {
        "status": "PROBE_COMPLETE", "ready_for_model": True,
        "exact_inventory_observed": True, "matches_expected_inventory": True})
    result = host.probe_host("dummy-codex", tmp_path)
    assert result["ready_for_model"] is False
    assert result["model_observed"] is False
    assert result["usage_complete"] is False
