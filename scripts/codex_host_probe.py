"""Inspect this installed Codex host's constructed tool inventory without a model.

The loopback provider is an explicitly configured dummy provider, does not use
OpenAI authentication, and returns an error after capturing only tool names.
No credentials, prompt content, or request headers are saved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
import tomllib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DISABLED_FEATURES = (
    "shell_tool", "unified_exec", "code_mode_host",
    "computer_use", "browser_use", "browser_use_external",
    "browser_use_full_cdp_access", "in_app_browser", "image_generation",
    "view_image", "artifact", "apps", "plugins", "plugin_sharing",
    "hooks", "multi_agent", "multi_agent_v2", "skill_search",
    "workspace_dependencies", "sleep_tool", "goals", "memories",
    "unavailable_dummy_tools", "tool_suggest", "remote_plugin",
)


def disabled_mcp_config() -> dict[str, str]:
    """Disable inherited server names without retaining their config values.

    TOML override tables merge with user configuration, so mcp_servers={}
    alone does not remove required servers from this separate review process.
    """
    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    config_path = codex_home / "config.toml"
    if not config_path.is_file():
        return {}
    config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    names = list(config.get("mcp_servers", {}))
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in names):
        raise ValueError("MCP server name cannot be safely overridden with this host's dotted-key CLI")
    return {f"mcp_servers.{name}.enabled": "false" for name in names}


def readonly_host_config(*, code_mode_enabled: bool = False) -> dict[str, str]:
    """Process-local overrides shared by inventory and execution probes."""
    return {
        "web_search": '"disabled"',
        "mcp_servers": "{}",
        **disabled_mcp_config(),
        "features.code_mode.enabled": str(code_mode_enabled).lower(),
        "features.code_mode.direct_only_tool_namespaces": '["functions"]',
        "agents.enabled": "false",
        "approval_policy": '"never"',
        "sandbox_mode": '"read-only"',
    }


def flatten_tool_names(tools: list[dict], prefix: str = "") -> list[str]:
    names = []
    for tool in tools:
        if not isinstance(tool, dict):
            names.append(prefix + "unknown")
            continue
        name = prefix + str(tool.get("name", tool.get("type", "unknown")))
        if tool.get("type") == "namespace":
            names.extend(flatten_tool_names(tool.get("tools", []), name + "."))
        else:
            names.append(name)
    return names


def request_tool_inventory(body: dict) -> dict:
    """Inspect every tool container, including nested additional_tools entries.

    Do not retain model prompts, arbitrary input content, or request headers.
    An inventory is only complete when all tool containers across the request
    were inspected; checking only the top-level tools field is insufficient.
    """
    containers: list[dict] = []

    def visit(value, path: str):
        if isinstance(value, dict):
            for key, entry in value.items():
                entry_path = f"{path}.{key}"
                if key in {"tools", "additional_tools"} and not isinstance(entry, list):
                    containers.append({"path": entry_path, "tools": [], "malformed_entries": 1})
                elif key in {"tools", "additional_tools"} and isinstance(entry, list):
                    # Some protocol variants wrap additional_tools around an
                    # object containing tools, others contain tool schemas.
                    schemas = [tool for tool in entry if isinstance(tool, dict)
                               and isinstance(tool.get("type"), str)
                               and tool.get("type") != "additional_tools"]
                    if schemas or key == "tools":
                        containers.append({"path": entry_path, "tools": schemas,
                                           "malformed_entries": len(entry) - len(schemas)})
                        # Namespace children belong to their enclosing tool
                        # schema and are flattened with its namespace prefix.
                        continue
                visit(entry, entry_path)
        elif isinstance(value, list):
            for index, entry in enumerate(value):
                visit(entry, f"{path}[{index}]")

    visit(body, "request")
    tools = [tool for container in containers for tool in container["tools"]]
    return {
        "tools": tools,
        "tool_names": [tool.get("name", tool.get("type")) for tool in tools],
        "flattened_tool_names": list(dict.fromkeys(flatten_tool_names(tools))),
        "tool_container_paths": [container["path"] for container in containers],
        "malformed_tool_entries": sum(container["malformed_entries"] for container in containers),
    }


def probe_inventory(codex: str, output: Path, timeout_s: float = 60, *, code_mode_enabled: bool = False) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    cwd = output.parent / "empty-review-workspace"
    cwd.mkdir(exist_ok=True)
    captured: dict = {}
    captures: list[dict] = []
    received = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request_bytes = self.rfile.read(int(self.headers["Content-Length"]))
            body = json.loads(request_bytes)
            captured.update({
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "path": self.path,
                "model": body.get("model"),
                **request_tool_inventory(body),
                "tool_choice": body.get("tool_choice"),
                "authorization_header_present": bool(self.headers.get("Authorization")),
                "request_keys": list(body),
                "input_types": [entry.get("type") for entry in body.get("input", []) if isinstance(entry, dict)],
            })
            captures.append(captured.copy())
            received.set()
            response = json.dumps({"error": {"message": "Intentional no-model inventory probe", "type": "invalid_request_error", "code": "probe_complete"}}).encode()
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = {
        "model_provider": '"readonly_inventory_probe"',
        "model_providers.readonly_inventory_probe": json.dumps({
            "name": "Local no-model inventory probe",
            "base_url": f"http://127.0.0.1:{server.server_port}/v1",
            "wire_api": "responses",
            "requires_openai_auth": False,
            "request_max_retries": 0,
            "stream_max_retries": 0,
        }, separators=(",", ":")),
        **readonly_host_config(code_mode_enabled=code_mode_enabled),
    }
    # JSON objects use ':' whereas a TOML inline table requires '='.
    config["model_providers.readonly_inventory_probe"] = (
        '{name="Local no-model inventory probe",'
        f'base_url="http://127.0.0.1:{server.server_port}/v1",'
        'wire_api="responses",requires_openai_auth=false,'
        'request_max_retries=0,stream_max_retries=0}'
    )
    command = [codex, "app-server", "--stdio"]
    for key, value in config.items():
        command += ["-c", f"{key}={value}"]
    for feature in DISABLED_FEATURES:
        command += ["--disable", feature]
    child_env = {key: value for key, value in os.environ.items()
                 if key not in {"CODEX_APP_TOOLS_PIPE_PATH", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
                                "CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "CODEX_PERMISSION_PROFILE"}}
    child = subprocess.Popen(command, cwd=cwd, env=child_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    messages: queue.Queue = queue.Queue()
    errors: list[str] = []

    def read_stdout():
        for line in child.stdout:
            try:
                messages.put(json.loads(line))
            except json.JSONDecodeError:
                pass

    def read_stderr():
        for line in child.stderr:
            errors.append(line.rstrip())

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()
    next_id = 0

    def request(method, params, timeout=None):
        nonlocal next_id
        next_id += 1
        rpc_id = next_id
        child.stdin.write(json.dumps({"id": rpc_id, "method": method, "params": params}) + "\n")
        child.stdin.flush()
        deadline = time.monotonic() + min(timeout or timeout_s, timeout_s)
        while time.monotonic() < deadline:
            response = messages.get(timeout=max(0.1, deadline - time.monotonic()))
            if response.get("id") == rpc_id:
                return response
        raise TimeoutError(method)

    binary_hash = hashlib.sha256(Path(codex).read_bytes()).hexdigest()
    outcome = {"probe_type": "local_dummy_provider_no_model", "disabled_features": list(DISABLED_FEATURES),
               "config_overrides": {key: value for key, value in config.items()
                                    if not key.startswith("model_providers.")},
               "real_model_called": False, "actual_model_calls": 0, "usage": None,
               "model_usage": None, "exact_inventory_observed": False,
               "host_binary_sha256": binary_hash,
               "inventory_assurance": "observed_dummy_provider_request_only",
               "live_provider_parity_verified": False}
    try:
        outcome["initialize"] = request("initialize", {"clientInfo": {"name": "batch_readonly_inventory_probe", "version": "1"},
                                                         "capabilities": {"experimentalApi": True}})
        child.stdin.write(json.dumps({"method": "initialized"}) + "\n")
        child.stdin.flush()
        started = request("thread/start", {
            "cwd": str(cwd), "ephemeral": True, "environments": [], "sandbox": "read-only",
            "approvalPolicy": "never", "baseInstructions": "Use only the supplied snapshot read tool.",
            "developerInstructions": "This is a no-model local tool inventory probe.",
            "dynamicTools": [{"type": "function", "name": "read_security_batch_context",
                              "description": "Read a bound immutable security snapshot.",
                              "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}},
                                              "required": ["path"], "additionalProperties": False}}],
        })
        result = started.get("result", {})
        outcome["thread_start_error"] = started.get("error")
        outcome["effective_model"] = result.get("model")
        outcome["effective_model_provider"] = result.get("modelProvider")
        outcome["effective_sandbox"] = result.get("sandbox")
        outcome["effective_approval_policy"] = result.get("approvalPolicy")
        thread_id = result.get("thread", {}).get("id")
        if thread_id:
            status = request("mcpServerStatus/list", {})
            outcome["effective_mcp_server_names"] = [entry.get("name") for entry in
                status.get("result", {}).get("data", [])]
            outcome["mcp_status_error"] = status.get("error")
            outcome["turn_start"] = request("turn/start", {"threadId": thread_id, "environments": [],
                                                           "input": [{"type": "text", "text": "Inventory probe."}]})
            received.wait(min(25, timeout_s))
            time.sleep(3)
        outcome["constructed_request"] = captured
        outcome["constructed_requests"] = captures
        outcome["exact_inventory_observed"] = bool(captured)
        outcome["expected_tool_names"] = ["read_security_batch_context"]
        outcome["observed_tool_names"] = list(dict.fromkeys(
            name for request in captures for name in request.get("flattened_tool_names", [])))
        outcome["unexpected_tool_names"] = [
            name for name in outcome["observed_tool_names"]
            if name not in {"read_security_batch_context", "functions.read_security_batch_context"}
        ]
        outcome["no_auth_header_observed"] = bool(captures) and all(
            request.get("authorization_header_present") is False for request in captures)
        outcome["matches_expected_inventory"] = outcome["no_auth_header_observed"] and all(
            request.get("malformed_tool_entries") == 0 and request.get("flattened_tool_names") in (
                ["read_security_batch_context"], ["functions.read_security_batch_context"])
            for request in captures)
        outcome["ready_for_model"] = False
        outcome["status"] = "UNSUPPORTED_HOST" if captured else "HOST_INVENTORY_UNOBSERVED"
        outcome["reason"] = (
            "Host tool inventory includes additional native or orchestration tools; "
            "the required sole bound snapshot reader is not the complete tool inventory."
            if captured and not outcome["matches_expected_inventory"] else
            "Dummy-provider inventory matches, but live-provider parity is not verified."
            if captured else "Host did not construct a provider request; inspect thread_start_error or error."
        )
    except Exception as exc:
        outcome["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        child.terminate()
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        server.shutdown()
        # Stderr is not retained: existing provider warnings can contain paths.
        outcome["stderr_line_count"] = len(errors)
        outcome.setdefault("ready_for_model", False)
        outcome.setdefault("status", "PROBE_ERROR")
        output.write_text(json.dumps(outcome, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--code-mode", action="store_true")
    args = parser.parse_args()
    outcome = probe_inventory(args.codex, args.output, code_mode_enabled=args.code_mode)
    print(json.dumps({key: outcome.get(key) for key in (
        "error", "effective_model", "effective_model_provider", "exact_inventory_observed", "matches_expected_inventory",
        "stderr_line_count")}, ensure_ascii=False))
    return 0 if outcome.get("matches_expected_inventory") else 1


if __name__ == "__main__":
    raise SystemExit(main())
