"""Exercise Codex tool execution against a credential-free dummy SSE provider.

No model, shell command, filesystem tool, or child agent is invoked by the
provider. Its only executable call evaluates harmless JavaScript capability
checks and invokes one client-bound marker reader. Receipts retain selected
tool outputs and event types, never authentication or request prompt content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from codex_host_probe import DISABLED_FEATURES, readonly_host_config, request_tool_inventory


MARKER = "BOUND_SNAPSHOT_READER_MARKER"
READ_NAMESPACE = "security_review"
PROFILE_VERSION = "bound-snapshot-reader-with-inert-host-stubs-v1"
PROBE_KINDS = ("exec", "wait", "read_direct", "unknown_direct", "unavailable_shell",
               "unavailable_spawn", "list_resources", "read_resource", "request_input", "request_input_async")
EXPECTED_INVENTORY = {"functions.exec", "functions.wait", "functions.request_user_input",
                      "functions.request_user_input_async", "security_review.read_security_batch_context"}
PROBE_PROGRAM = """text({kind:'runtime_capabilities',process:typeof process,require:typeof require,fetch:typeof fetch,WebSocket:typeof WebSocket,toolNames:ALL_TOOLS.map(t=>t.name).sort(),execCommand:typeof tools.exec_command,applyPatch:typeof tools.apply_patch,spawnAgent:typeof tools.spawn_agent});
try { text({kind:'bound_reader_result',value:await tools.read_security_batch_context({path:'marker.py'})}); } catch(e) { text({kind:'bound_reader_result',readerExposed:false}); }
try { await tools.__security_forbidden_probe__({}); text({kind:'unknown_nested',rejected:false}); } catch(e) { text({kind:'unknown_nested',rejected:true}); }"""


def profile_config() -> dict[str, str]:
    """Exact process-local isolation configuration shared with live clients."""
    return {**readonly_host_config(), "features.code_mode.direct_only_tool_namespaces": '["security_review"]'}


def dynamic_tools(input_schema: dict | None = None) -> list[dict]:
    """Register the sole application callback in its dedicated direct namespace."""
    schema = input_schema if input_schema is not None else {"type": "object",
        "properties": {"path": {"type": "string"}}, "required": ["path"], "additionalProperties": False}
    return [{"type": "namespace", "name": READ_NAMESPACE,
             "description": "Only bound immutable snapshot reads.", "tools": [{"type": "function",
             "name": "read_security_batch_context", "description": "Read a bound immutable security snapshot.",
             "inputSchema": schema}]}]


def profile_fingerprint(codex: str, config: dict[str, str] | None = None) -> dict[str, str]:
    configuration = config if config is not None else profile_config()
    material = {"profile": PROFILE_VERSION, "config": configuration, "disabled_features": list(DISABLED_FEATURES)}
    return {"host_binary_sha256": hashlib.sha256(Path(codex).read_bytes()).hexdigest(),
            "isolation_config_sha256": hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}


def synthetic_response(call_kind: str, sequence: int) -> list[dict]:
    """Return protocol-only SSE events; usage is intentionally absent."""
    response_id = f"resp_local_probe_{sequence}"
    if sequence == 1:
        if call_kind == "exec":
            item = {"id": "ctc_probe", "type": "custom_tool_call", "call_id": "call_probe",
                    "namespace": "functions", "name": "exec", "input": PROBE_PROGRAM}
        elif call_kind == "unknown_direct":
            item = {"id": "fc_probe", "type": "function_call", "call_id": "call_probe",
                    "namespace": "functions", "name": "__security_forbidden_probe__", "arguments": "{}"}
        elif call_kind == "read_direct":
            item = {"id": "fc_probe", "type": "function_call", "call_id": "call_probe",
                    "namespace": READ_NAMESPACE, "name": "read_security_batch_context", "arguments": '{"path":"marker.py"}'}
        elif call_kind in {"unavailable_shell", "unavailable_spawn", "list_resources", "read_resource", "wait", "request_input", "request_input_async"}:
            names = {"unavailable_shell": ("functions", "exec_command", {}),
                     "unavailable_spawn": ("collaboration", "spawn_agent", {}),
                     "list_resources": ("functions", "list_mcp_resources", {}),
                     "read_resource": ("functions", "read_mcp_resource", {"server": "__security_nonexistent_server__", "uri": "security-probe://unregistered"}),
                     "wait": ("functions", "wait", {"cell_id": "__security_nonexistent_cell__", "yield_time_ms": 1}),
                     "request_input": ("functions", "request_user_input", {"questions": [{"id": "probe", "header": "Probe", "question": "Synthetic local probe", "options": [{"label": "One", "description": "Synthetic"}, {"label": "Two", "description": "Synthetic"}]}]}),
                     "request_input_async": ("functions", "request_user_input_async", {"questions": [{"title": "Synthetic local probe", "options": ["One", "Two"]}]})}
            namespace, name, arguments = names[call_kind]
            item = {"id": "fc_probe", "type": "function_call", "call_id": "call_probe",
                    "namespace": namespace, "name": name, "arguments": json.dumps(arguments)}
        else:
            raise ValueError("unsupported synthetic probe kind")
    else:
        item = {"id": "msg_probe", "type": "message", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": "Local no-model execution probe complete.", "annotations": []}]}
    response = {"id": response_id, "object": "response", "status": "completed", "output": [item], "usage": None}
    return [
        {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
        {"type": "response.output_item.added", "output_index": 0, "item": item},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]


def tool_output_items(body: dict) -> list[dict]:
    """Retain only tool outputs generated by this harmless synthetic probe."""
    return [entry for entry in body.get("input", []) if isinstance(entry, dict)
            and entry.get("type") in {"function_call_output", "custom_tool_call_output"}]


def bound_tool_response(params: dict) -> tuple[dict, bool]:
    allowed = (params.get("namespace") == READ_NAMESPACE and params.get("tool") == "read_security_batch_context"
               and params.get("arguments") == {"path": "marker.py"})
    payload = {"marker": MARKER} if allowed else {"error": "UNREGISTERED_TOOL_OR_ARGUMENTS"}
    return {"contentItems": [{"type": "inputText", "text": json.dumps(payload)}], "success": allowed}, allowed


def run_probe(codex: str, output: Path, *, call_kind: str = "exec", timeout_s: float = 45,
              config_overrides: dict[str, str] | None = None) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    cwd = output.parent / "empty-execution-workspace"
    cwd.mkdir(exist_ok=True)
    captures: list[dict] = []
    rpc_events: list[dict] = []
    capture_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            inventory = request_tool_inventory(body)
            with capture_lock:
                sequence = len(captures) + 1
                captures.append({"sequence": sequence, "authorization_header_present": bool(self.headers.get("Authorization")),
                                 "tool_names": inventory["flattened_tool_names"], "tool_outputs": tool_output_items(body)})
            wire = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                           for event in synthetic_response(call_kind, sequence)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(wire)))
            self.end_headers()
            self.wfile.write(wire)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    config = {
        "model_provider": '"tool_execution_probe"',
        "model_providers.tool_execution_probe": (
            '{name="Local no-model execution probe",'
            f'base_url="http://127.0.0.1:{server.server_port}/v1",'
            'wire_api="responses",requires_openai_auth=false,'
            'request_max_retries=0,stream_max_retries=0}'),
        **profile_config(),
    }
    config.update(config_overrides or {})
    command = [codex, "app-server", "--stdio"]
    for key, value in config.items():
        command += ["-c", f"{key}={value}"]
    for feature in DISABLED_FEATURES:
        if feature != "code_mode":
            command += ["--disable", feature]
    env = {key: value for key, value in os.environ.items()
           if key not in {"CODEX_APP_TOOLS_PIPE_PATH", "CODEX_THREAD_ID", "CODEX_SESSION_ID",
                          "CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "CODEX_PERMISSION_PROFILE"}}
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    incoming: queue.Queue = queue.Queue()
    stderr_count = [0]

    def stdout_reader():
        for line in process.stdout:
            try:
                incoming.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def stderr_reader():
        for _line in process.stderr:
            stderr_count[0] += 1

    threading.Thread(target=stdout_reader, daemon=True).start()
    threading.Thread(target=stderr_reader, daemon=True).start()

    def send(value):
        process.stdin.write(json.dumps(value) + "\n")
        process.stdin.flush()

    reader_calls = 0
    denied_requests = 0
    request_id = 0
    deadline = time.monotonic() + timeout_s

    def consume():
        nonlocal reader_calls, denied_requests
        message = incoming.get(timeout=max(0.1, deadline - time.monotonic()))
        method = message.get("method")
        if method:
            record = {"method": method}
            params = message.get("params", {})
            if method == "item/tool/call" and "id" in message:
                response, allowed = bound_tool_response(params)
                reader_calls += int(allowed)
                denied_requests += int(not allowed)
                record.update(namespace=params.get("namespace"), tool=params.get("tool"), allowed=allowed)
                send({"id": message["id"], "result": response})
            elif "id" in message:
                denied_requests += 1
                record["denied"] = True
                send({"id": message["id"], "error": {"code": -32601, "message": "Unregistered client request"}})
            if method == "item/completed":
                item = params.get("item", {})
                record["item_type"] = item.get("type")
                if item.get("type") in {"dynamicToolCall", "mcpToolCall"}:
                    record["tool"] = item.get("tool")
            if method == "turn/completed":
                record["turn_status"] = params.get("turn", {}).get("status")
            if method == "error":
                record["error"] = params.get("error", {}).get("message")
            rpc_events.append(record)
        return message

    def request(method, params):
        nonlocal request_id
        request_id += 1
        expected_id = request_id
        send({"id": expected_id, "method": method, "params": params})
        while time.monotonic() < deadline:
            response = consume()
            if response.get("id") == expected_id and "method" not in response:
                return response
        raise TimeoutError(method)

    result = {"probe_type": "local_dummy_provider_synthetic_sse_execution", "real_model_called": False,
              "actual_model_calls": 0, "usage": None, "call_kind": call_kind,
              **profile_fingerprint(codex, {**profile_config(), **(config_overrides or {})}), "profile_version": PROFILE_VERSION,
              "config_overrides": config_overrides or {}, "source_io_attempted": False,
              "shell_command_attempted": False, "child_agent_spawn_attempted": False}
    try:
        request("initialize", {"clientInfo": {"name": "security_tool_execution_probe", "version": "1"},
                               "capabilities": {"experimentalApi": True}})
        send({"method": "initialized"})
        started = request("thread/start", {"cwd": str(cwd), "ephemeral": True, "environments": [],
            "sandbox": "read-only", "approvalPolicy": "never", "baseInstructions": "Synthetic no-model execution probe.",
            "developerInstructions": "Only a bound marker reader is registered by the client.",
            "dynamicTools": dynamic_tools()})
        result["thread_start_error"] = started.get("error")
        effective = started.get("result", {})
        result.update(effective_model=effective.get("model"), effective_model_provider=effective.get("modelProvider"),
                      effective_reasoning_effort=effective.get("reasoningEffort"), effective_sandbox=effective.get("sandbox"),
                      effective_approval_policy=effective.get("approvalPolicy"))
        thread_id = effective.get("thread", {}).get("id")
        if not thread_id:
            raise RuntimeError("No ephemeral probe thread created")
        registry = request("mcpServerStatus/list", {"threadId": thread_id})
        statuses = registry.get("result", {}).get("data")
        result["mcp_registry_error"] = registry.get("error")
        result["mcp_registry_empty"] = statuses == []
        result["mcp_registry_count"] = len(statuses) if isinstance(statuses, list) else None
        result["mcp_registry_metadata"] = [
            {"name": entry.get("name"), "enabled": entry.get("enabled"), "status": entry.get("status"),
             "runtime_status": entry.get("runtimeStatus"),
             "auth_status": entry.get("authStatus"), "field_names": sorted(entry),
             "tool_names": sorted(entry.get("tools", {})), "resource_count": len(entry.get("resources", [])),
             "resource_template_count": len(entry.get("resourceTemplates", []))}
            for entry in statuses or []]
        request("turn/start", {"threadId": thread_id, "environments": [],
                               "input": [{"type": "text", "text": "Run the harmless local protocol probe."}]})
        while time.monotonic() < deadline:
            message = consume()
            if message.get("method") == "turn/completed":
                result["turn_status"] = message.get("params", {}).get("turn", {}).get("status")
                break
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        server.shutdown()
        result.update(requests=captures, rpc_events=rpc_events, bound_reader_calls=reader_calls,
                      denied_client_requests=denied_requests, stderr_line_count=stderr_count[0])
        result["no_auth_header_observed"] = bool(captures) and all(not entry["authorization_header_present"] for entry in captures)
        result["ready_for_real_model"] = False  # This probe establishes dummy-route execution only.
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def assess_suite(receipts: dict[str, dict]) -> dict:
    """Assess observed executions without treating a caller's ready flag as proof."""
    def outputs(kind):
        return [item.get("output", "") for request in receipts.get(kind, {}).get("requests", [])
                for item in request.get("tool_outputs", [])]

    def contains(kind, text):
        return any(text in str(value) for value in outputs(kind))

    records = list(receipts.values())
    complete = set(receipts) == set(PROBE_KINDS) and all(record.get("turn_status") == "completed" and not record.get("error") for record in records)
    fingerprints = {(record.get("host_binary_sha256"), record.get("isolation_config_sha256")) for record in records}
    models = {record.get("effective_model") for record in records}
    efforts = {record.get("effective_reasoning_effort") for record in records}
    checks = {
        "complete": complete,
        "same_binary_and_config": len(fingerprints) == 1 and all(all(pair) for pair in fingerprints),
        "exact_declared_inventory": bool(records) and all(len(record.get("requests", [])) >= 2 and all(
            set(request.get("tool_names", [])) == EXPECTED_INVENTORY for request in record["requests"]) for record in records),
        "same_effective_model": len(models) == 1 and None not in models and "" not in models,
        "same_effective_reasoning_effort": len(efforts) == 1,
        "readonly_sandbox_and_no_approvals": bool(records) and all(record.get("effective_sandbox", {}).get("type") == "readOnly"
            and record.get("effective_sandbox", {}).get("networkAccess") is False and record.get("effective_approval_policy") == "never"
            for record in records),
        "exec_disabled": contains("exec", "code-mode host is disabled"),
        "wait_disabled": contains("wait", "code-mode host is disabled"),
        "bound_reader_works": receipts.get("read_direct", {}).get("bound_reader_calls") == 1 and contains("read_direct", MARKER),
        "unknown_tool_rejected": contains("unknown_direct", "unsupported call:"),
        "shell_rejected": contains("unavailable_shell", "unsupported call:"),
        "spawn_rejected": contains("unavailable_spawn", "unsupported call:"),
        "mcp_servers_disabled_without_tools_or_resources": bool(records) and all(record.get("mcp_registry_error") is None and
            isinstance(record.get("mcp_registry_metadata"), list) and record.get("mcp_registry_count") == len(record["mcp_registry_metadata"]) and all(entry.get("runtime_status") == "disabled" and
                entry.get("tool_names") == [] and entry.get("resource_count") == 0 and entry.get("resource_template_count") == 0
                for entry in record["mcp_registry_metadata"]) for record in records),
        "resource_listing_empty": contains("list_resources", '{"resources":[]}'),
        "unknown_resource_server_rejected": contains("read_resource", "unknown MCP server"),
        "sync_questions_unavailable": contains("request_input", "unavailable in Default mode"),
        "async_questions_produce_no_client_request": receipts.get("request_input_async", {}).get("bound_reader_calls") == 0
            and receipts.get("request_input_async", {}).get("denied_client_requests") == 0
            and not any("requestUserInput" in event.get("method", "") for event in receipts.get("request_input_async", {}).get("rpc_events", [])),
        "no_auth_header_observed": bool(records) and all(record.get("no_auth_header_observed") is True for record in records),
        "no_real_model_called": bool(records) and all(record.get("actual_model_calls") == 0 and record.get("real_model_called") is False for record in records),
    }
    verified = all(checks.values())
    fingerprint = dict(zip(("host_binary_sha256", "isolation_config_sha256"), next(iter(fingerprints)))) if len(fingerprints) == 1 else {}
    return {"profile_version": PROFILE_VERSION, **fingerprint, "status": "VERIFIED_DUMMY_ROUTE" if verified else "PROBE_FAILED",
            "effective_model": next(iter(models)) if len(models) == 1 else None,
            "effective_reasoning_effort": next(iter(efforts)) if len(efforts) == 1 else None,
            "execution_profile_verified": verified, "checks": checks, "actual_model_calls": 0, "usage": None,
            "real_model_called": False, "live_provider_parity_verified": False,
            "async_question_behavior": "accepted metadata only; not a disabled tool; client must never forward UI requests",
            "limitations": ["Dummy-provider execution proof does not observe live-provider requests.",
                            "Declared inventory contains inert host stubs; application callback inventory contains only the bound reader."]}


def run_suite(codex: str, output_dir: Path, timeout_s: float = 45) -> dict:
    receipts = {kind: run_probe(codex, output_dir / f"{kind}.json", call_kind=kind, timeout_s=timeout_s) for kind in PROBE_KINDS}
    result = assess_suite(receipts)
    (output_dir / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--call-kind", choices=("exec", "unknown_direct", "read_direct", "unavailable_shell",
                        "unavailable_spawn", "list_resources", "read_resource", "wait", "request_input", "request_input_async"), default="exec")
    parser.add_argument("--timeout", type=float, default=45)
    parser.add_argument("--suite", action="store_true")
    parser.add_argument("-c", "--config", action="append", default=[])
    args = parser.parse_args()
    overrides = dict(entry.split("=", 1) for entry in args.config)
    result = (run_suite(args.codex, args.output, timeout_s=args.timeout) if args.suite else
              run_probe(args.codex, args.output, call_kind=args.call_kind, timeout_s=args.timeout, config_overrides=overrides))
    print(json.dumps({key: result.get(key) for key in (("status", "execution_profile_verified", "effective_model", "effective_reasoning_effort", "checks") if args.suite else
        ("error", "turn_status", "bound_reader_calls", "denied_client_requests", "no_auth_header_observed"))}, ensure_ascii=False))


if __name__ == "__main__":
    main()
