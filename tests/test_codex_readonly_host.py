"""Only internal positive/negative execution proof can authorize model work."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
host = importlib.import_module("codex_readonly_host")
probe = importlib.import_module("codex_host_probe")


@pytest.fixture(autouse=True)
def empty_trusted_proof_cache():
    host._TRUSTED_PROOFS.clear()
    yield
    host._TRUSTED_PROOFS.clear()


@pytest.fixture
def installed_host(monkeypatch, tmp_path):
    executable = tmp_path / "codex.bin"
    executable.write_bytes(b"test installed host")
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "empty-codex-home"))
    return str(executable)


def _proof(executable):
    profile = host.isolation_profile(executable)
    return {"profile_version": host.PROFILE_VERSION,
        "host_binary_sha256": profile["host_binary_sha256"],
        "isolation_config_sha256": profile["isolation_config_sha256"],
        "checks": {check: True for check in host.REQUIRED_CHECKS},
        "execution_profile_verified": True, "effective_model": "same-installed-model",
        "effective_reasoning_effort": "high", "actual_model_calls": 0,
        "real_model_called": False, "usage": None}


def test_pre_cancelled_review_never_runs_proof_or_model(monkeypatch, tmp_path):
    import threading
    cancelled = threading.Event()
    cancelled.set()
    monkeypatch.setattr(host, 'run_suite', lambda *a, **kw: pytest.fail('Cancelled review must not run host probes'))
    receipt = host.run_review('not sent', {}, lambda **kw: pytest.fail('no reads'),
                              tmp_path/'cancelled', codex='not-executed', cancel_event=cancelled)
    assert receipt['status'] == 'CANCELLED'
    assert receipt['actual_model_calls'] == 0
    assert receipt['usage'] is None
    assert receipt['usage_complete'] is False


def test_nested_orchestration_inventory_is_not_mistaken_for_zero_tools():
    tools = [{"type": "namespace", "name": "functions", "tools": [
        {"type": "custom", "name": "exec"}, {"type": "function", "name": "wait"}]},
        {"type": "namespace", "name": "collaboration", "tools": [
            {"type": "function", "name": "spawn_agent"}]}]
    assert probe.flatten_tool_names(tools) == [
        "functions.exec", "functions.wait", "collaboration.spawn_agent"]


@pytest.mark.parametrize("ready", [False, True])
def test_caller_ready_boolean_never_authorizes_model_or_context(monkeypatch, tmp_path, installed_host, ready):
    monkeypatch.setattr(host, "run_suite", lambda *_args, **_kwargs: {"ready_for_model": True})
    calls = []
    with pytest.raises(host.UnsupportedReadonlyHost) as caught:
        host.run_review("private prompt", {}, lambda **kwargs: calls.append(kwargs), tmp_path / "review",
                        codex=installed_host, preflight={"ready_for_model": ready})
    assert calls == []
    assert caught.value.receipt["actual_model_calls"] == 0
    assert caught.value.receipt["usage"] is None
    assert caught.value.receipt["ready_for_model"] is False


@pytest.mark.parametrize("failed_check", [
    "exec_disabled", "wait_disabled", "bound_reader_works", "exact_declared_inventory",
    "spawn_rejected", "mcp_servers_disabled_without_tools_or_resources", "readonly_sandbox_and_no_approvals",
])
def test_missing_native_denial_reader_or_inventory_check_blocks_dispatch(
        monkeypatch, tmp_path, installed_host, failed_check):
    proof = _proof(installed_host)
    proof["checks"][failed_check] = False
    monkeypatch.setattr(host, "run_suite", lambda *_args, **_kwargs: proof)
    result = host.probe_host(installed_host, tmp_path / "preflight")
    assert result["ready_for_model"] is False
    assert failed_check in result["failures"]


def test_policy_is_fixed_namespace_reader_and_four_inert_protocol_tools(installed_host):
    profile = host.isolation_profile(installed_host)
    assert profile["expected_tool_names"] == sorted({
        "functions.exec", "functions.wait", "functions.request_user_input", "functions.request_user_input_async",
        "security_review.read_security_batch_context"})
    assert profile["config_overrides"]["agents.enabled"] == "false"
    assert profile["config_overrides"]["features.code_mode.direct_only_tool_namespaces"] == '["security_review"]'
    assert "code_mode_host" in profile["disabled_features"]


def test_verified_internal_proof_dispatches_pinned_model_and_profile(monkeypatch, tmp_path, installed_host):
    suite_calls = []
    model_calls = []

    def execute_suite(*args, **kwargs):
        suite_calls.append((args, kwargs))
        return _proof(installed_host)

    def model_turn(*args, **kwargs):
        model_calls.append((args, kwargs))
        return {"actual_model_calls": 1, "model_observed": True, "usage": {"input_tokens": 1}}

    monkeypatch.setattr(host, "run_suite", execute_suite)
    monkeypatch.setitem(sys.modules, "codex_app_server_client", SimpleNamespace(run_model_turn=model_turn))
    callback = lambda **_kwargs: {"snapshot": "bound"}
    result = host.run_review("actual prompt", {"type": "object"}, callback, tmp_path / "review", codex=installed_host,
                             preflight={"ready_for_model": False})
    assert len(suite_calls) == len(model_calls) == 1
    args, kwargs = model_calls[0]
    assert args[1] == "actual prompt" and args[3] is callback
    assert kwargs["model"] == "same-installed-model"
    assert kwargs["expected_profile"]["effective_model"] == "same-installed-model"
    assert kwargs["expected_profile"]["effective_reasoning_effort"] == "high"
    assert result["isolation_contract"] == host.ISOLATION_CONTRACT


def test_returned_receipt_mutation_cannot_poison_internal_cache(monkeypatch, tmp_path, installed_host):
    suite_calls = []
    monkeypatch.setattr(host, "run_suite", lambda *_args, **_kwargs: suite_calls.append(1) or _proof(installed_host))
    first = host.probe_host(installed_host, tmp_path / "first")
    first["ready_for_model"] = False
    first["execution_profile"]["config_overrides"]["agents.enabled"] = "true"
    second = host.probe_host(installed_host, tmp_path / "second")
    assert len(suite_calls) == 1
    assert second["ready_for_model"] is True
    assert second["trusted_proof_cache_hit"] is True
    assert second["execution_profile"]["config_overrides"]["agents.enabled"] == "false"


def test_profile_change_invalidates_cache(monkeypatch, tmp_path, installed_host):
    suite_calls = []
    monkeypatch.setattr(host, "run_suite", lambda *_args, **_kwargs: suite_calls.append(1) or _proof(installed_host))
    host.probe_host(installed_host, tmp_path / "first")
    Path(installed_host).write_bytes(b"replaced installed host")
    second = host.probe_host(installed_host, tmp_path / "second")
    assert len(suite_calls) == 2
    assert second["trusted_proof_cache_hit"] is False


def test_config_change_during_probe_cannot_authorize_dispatch(monkeypatch, tmp_path, installed_host):
    def execute_suite(*_args, **_kwargs):
        proof = _proof(installed_host)
        Path(installed_host).write_bytes(b"host changed during probes")
        return proof

    monkeypatch.setattr(host, "run_suite", execute_suite)
    receipt = host.probe_host(installed_host, tmp_path / "probe")
    assert receipt["ready_for_model"] is False
    assert "profile_changed_during_probe" in receipt["failures"]


def test_requested_model_cannot_bypass_probed_model(monkeypatch, tmp_path, installed_host):
    monkeypatch.setattr(host, "run_suite", lambda *_args, **_kwargs: _proof(installed_host))
    with pytest.raises(host.UnsupportedReadonlyHost, match="differs"):
        host.run_review("prompt", {}, lambda **_kwargs: None, tmp_path / "review", codex=installed_host,
                        model="unprobed-model")
