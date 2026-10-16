"""Codex reviews gated by actual installed-host tool-execution controls.

The four native protocol tools remain declared, but code execution is disabled
and the live client does not forward user-input requests. The sole application
callback reads a bound immutable snapshot. Caller-supplied ready flags never
authorize model dispatch; proof comes from internal credential-free probes.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Callable

from codex_host_probe import DISABLED_FEATURES
from codex_tool_execution_probe import (
    EXPECTED_INVENTORY, PROFILE_VERSION, READ_NAMESPACE,
    profile_config, profile_fingerprint, run_suite,
)


ISOLATION_CONTRACT = "bound-reader-host-execution-v2"
REQUIRED_CHECKS = frozenset({
    "complete", "same_binary_and_config", "exact_declared_inventory", "exec_disabled", "wait_disabled",
    "bound_reader_works", "unknown_tool_rejected", "shell_rejected", "spawn_rejected",
    "mcp_servers_disabled_without_tools_or_resources", "resource_listing_empty",
    "unknown_resource_server_rejected", "sync_questions_unavailable",
    "async_questions_produce_no_client_request", "no_auth_header_observed", "no_real_model_called",
    "same_effective_model", "same_effective_reasoning_effort", "readonly_sandbox_and_no_approvals",
})
_PROOF_LOCK = threading.Lock()
# Immutable serialized copies prevent callers mutating a returned receipt from
# changing the authorization record used by a subsequent background worker.
_TRUSTED_PROOFS: dict[tuple[str, str, str | None], str] = {}


class UnsupportedReadonlyHost(RuntimeError):
    def __init__(self, receipt: dict[str, Any]):
        self.receipt = receipt
        super().__init__(receipt.get("reason", "Read-only execution controls are unverified."))


def _config_file_digest() -> str | None:
    config_path = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))) / "config.toml"
    return hashlib.sha256(config_path.read_bytes()).hexdigest() if config_path.is_file() else None


def isolation_profile(codex: str, effective_model: str | None = None,
                      effective_reasoning_effort: str | None = None) -> dict[str, Any]:
    """Safe capability metadata; never reads or copies authentication files."""
    executable = str(Path(codex).resolve(strict=True))
    config = profile_config()
    profile = {
        "contract_version": ISOLATION_CONTRACT, "profile_version": PROFILE_VERSION,
        "read_namespace": READ_NAMESPACE, "config_overrides": config,
        "disabled_features": list(DISABLED_FEATURES), "expected_tool_names": sorted(EXPECTED_INVENTORY),
        **profile_fingerprint(executable, config), "global_config_sha256": _config_file_digest(),
        "effective_model": effective_model,
        "effective_reasoning_effort": effective_reasoning_effort,
    }
    digest = hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {**profile, "profile_sha256": digest, "executable": executable}


def _verified_gate(executable: str, directory: Path, timeout_s: float) -> dict[str, Any]:
    before = isolation_profile(executable)
    key = before["host_binary_sha256"], before["isolation_config_sha256"], before["global_config_sha256"]
    with _PROOF_LOCK:
        if key in _TRUSTED_PROOFS:
            receipt = json.loads(_TRUSTED_PROOFS[key])
            receipt["trusted_proof_cache_hit"] = True
            return receipt
        probe_dir = directory / "execution-proof"
        probe_dir.mkdir(parents=True, exist_ok=True)
        # This call executes the installed binary against a local synthetic SSE
        # provider. No supplied JSON file or caller boolean is accepted as proof.
        proof = run_suite(executable, probe_dir, timeout_s=min(timeout_s, 45))
        after = isolation_profile(executable)
        failures = [name for name, passed in proof.get("checks", {}).items() if passed is not True]
        if not REQUIRED_CHECKS <= proof.get("checks", {}).keys() or proof.get("execution_profile_verified") is not True:
            failures.append("execution_proof_incomplete")
        if proof.get("profile_version") != PROFILE_VERSION:
            failures.append("execution_contract_mismatch")
        if before != after:
            failures.append("profile_changed_during_probe")
        for field in ("host_binary_sha256", "isolation_config_sha256"):
            if proof.get(field) != before[field]:
                failures.append(field + "_mismatch")
        effective_model = proof.get("effective_model")
        if not isinstance(effective_model, str) or not effective_model:
            failures.append("effective_model_not_observed")
        profile = isolation_profile(executable, effective_model, proof.get("effective_reasoning_effort"))
        receipt = {
            **proof, "status": "HOST_EXECUTION_ISOLATED" if not failures else "UNSUPPORTED_HOST",
            "ready_for_model": not failures, "reason": "; ".join(failures) if failures else
                "Installed-host controls verified; only the bound reader has project access.",
            "isolation_contract": ISOLATION_CONTRACT, "execution_profile": profile,
            "failures": failures, "expected_tool_names": sorted(EXPECTED_INVENTORY),
            "exact_inventory_observed": proof.get("checks", {}).get("exact_declared_inventory") is True,
            "inventory_assurance": "dummy_route_inventory_and_installed_host_execution_controls",
            "live_provider_inventory_observed": False, "live_provider_parity_verified": False,
            "trusted_proof_cache_hit": False,
            "actual_model_calls": 0, "real_model_called": False, "usage": None,
            "model_observed": False, "model_response_received": False,
        }
        if not failures:
            _TRUSTED_PROOFS[key] = json.dumps(receipt, sort_keys=True)
        return receipt


def probe_host(codex: str | None = None, output_dir: Path | str | None = None,
               timeout_s: float = 60) -> dict[str, Any]:
    """Run actual no-model positive/negative controls under a fixed profile."""
    start = time.monotonic()
    directory = Path(output_dir) if output_dir else Path(__file__).resolve().parents[1] / "artifacts" / "host-preflight"
    directory.mkdir(parents=True, exist_ok=True)
    executable = codex or shutil.which("codex")
    try:
        if not executable:
            raise FileNotFoundError("Installed Codex executable was not found.")
        receipt = _verified_gate(executable, directory, timeout_s)
    except Exception as exc:
        receipt = {"status": "HOST_UNAVAILABLE", "ready_for_model": False,
                   "reason": f"{type(exc).__name__}: {exc}", "real_model_called": False,
                   "actual_model_calls": 0, "usage": None, "exact_inventory_observed": False}
    receipt.update(elapsed_ms=round((time.monotonic() - start) * 1000, 3), backend="codex_app_server",
                   simulation=False, model_observed=False, model_response_received=False, usage_complete=False)
    (directory / "preflight.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return receipt


def run_review(prompt: str, schema: dict[str, Any], read_context: Callable[..., Any],
               output_dir: Path | str, timeout_s: float = 180, *, codex: str | None = None,
               preflight: dict[str, Any] | None = None, model: str | None = None) -> dict[str, Any]:
    """Dispatch only after internal proof; caller preflight is informational."""
    del preflight
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    executable = codex or shutil.which("codex")
    if not executable:
        raise UnsupportedReadonlyHost({"status": "HOST_UNAVAILABLE", "ready_for_model": False,
            "reason": "Installed Codex executable was not found.", "actual_model_calls": 0, "usage": None})
    try:
        receipt = _verified_gate(executable, directory / "host-gate", min(timeout_s, 60))
    except Exception as exc:
        raise UnsupportedReadonlyHost({"status": "UNSUPPORTED_HOST", "ready_for_model": False,
            "reason": f"{type(exc).__name__}: {exc}", "actual_model_calls": 0, "usage": None}) from exc
    if not receipt.get("ready_for_model"):
        raise UnsupportedReadonlyHost(receipt)
    if model is not None and model != receipt["execution_profile"]["effective_model"]:
        raise UnsupportedReadonlyHost({**receipt, "ready_for_model": False,
            "reason": "Requested model differs from the model used by the trusted execution probe."})
    from codex_app_server_client import run_model_turn

    result = run_model_turn(executable, prompt, schema, read_context, directory, timeout_s,
                            model=receipt["execution_profile"]["effective_model"],
                            expected_profile=copy.deepcopy(receipt["execution_profile"]))
    result["isolation_contract"] = ISOLATION_CONTRACT
    result["isolation_profile_sha256"] = receipt["execution_profile"]["profile_sha256"]
    result["isolation_proof_cache_hit"] = receipt.get("trusted_proof_cache_hit", False)
    return result
