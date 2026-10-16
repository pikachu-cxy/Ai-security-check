"""Fail-closed experimental Codex backend capability gate.

This installed host currently exposes additional orchestration tools. The backend
therefore supports a real no-model preflight only. It deliberately does not send
a security review to a model until complete tool isolation has been established.
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from codex_host_probe import probe_inventory


class UnsupportedReadonlyHost(RuntimeError):
    def __init__(self, receipt: dict[str, Any]):
        self.receipt = receipt
        super().__init__(receipt.get("reason", "Complete read-only tool isolation is unverified."))


def probe_host(
    codex: str | None = None,
    output_dir: Path | str | None = None,
    timeout_s: float = 60,
) -> dict[str, Any]:
    """Observe a host request against a credential-free loopback fake provider.

    No real model is called. The observed request is evidence for the dummy
    provider only; it is not proof of a live provider's complete tool inventory.
    """
    start = time.monotonic()
    directory = Path(output_dir) if output_dir else Path(__file__).resolve().parents[1] / "artifacts" / "host-preflight"
    directory.mkdir(parents=True, exist_ok=True)
    executable = codex or shutil.which("codex")
    if not executable:
        receipt = {
            "status": "HOST_UNAVAILABLE", "ready_for_model": False,
            "reason": "Installed Codex executable was not found.",
            "real_model_called": False, "actual_model_calls": 0, "usage": None,
            "exact_inventory_observed": False,
        }
    else:
        receipt = probe_inventory(executable, directory / "inventory.json", timeout_s)
    receipt["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
    receipt["backend"] = "codex_app_server"
    receipt["simulation"] = False
    receipt["model_observed"] = False
    receipt["model_response_received"] = False
    receipt["usage_complete"] = False
    # A successful dummy-provider construction alone never authorizes live work.
    receipt["ready_for_model"] = False
    (directory / "preflight.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return receipt


def run_review(
    prompt: str,
    schema: dict[str, Any],
    read_context: Callable[..., Any],
    output_dir: Path | str,
    timeout_s: float = 180,
    *,
    codex: str | None = None,
    preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Refuse model dispatch before verified complete tool isolation exists.

    The prompt, schema and read_context callback are intentionally not consumed
    on the unsupported path. In particular, the callback is never invoked.
    """
    receipt = preflight if preflight is not None else probe_host(codex, output_dir, min(timeout_s, 60))
    # Do not trust a caller-provided boolean as proof of host-enforced isolation.
    blocked = dict(receipt)
    blocked.update({
        "status": "UNSUPPORTED_HOST", "ready_for_model": False,
        "real_model_called": False, "actual_model_calls": 0, "usage": None,
        "model_observed": False, "model_response_received": False,
        "reason": receipt.get("reason") or "Verified complete tool isolation and live-provider parity are unavailable.",
    })
    raise UnsupportedReadonlyHost(blocked)
