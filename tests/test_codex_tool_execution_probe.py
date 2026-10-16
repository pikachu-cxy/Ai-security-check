"""No-model execution probes must never request real privileged operations."""
import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
probe = importlib.import_module("codex_tool_execution_probe")


def test_program_checks_capabilities_without_privileged_invocations():
    program = probe.PROBE_PROGRAM
    assert "typeof process" in program and "typeof require" in program and "typeof fetch" in program
    assert "typeof tools.exec_command" in program and "typeof tools.spawn_agent" in program
    assert "await tools.read_security_batch_context({path:'marker.py'})" in program
    assert "tools.exec_command(" not in program and "tools.spawn_agent(" not in program
    assert "tools.apply_patch(" not in program


@pytest.mark.parametrize("kind", ["exec", "unknown_direct", "read_direct", "unavailable_shell", "unavailable_spawn", "list_resources", "read_resource", "wait", "request_input", "request_input_async"])
def test_sse_emits_no_usage_or_model_generated_content(kind):
    events = probe.synthetic_response(kind, 1)
    assert [event["type"] for event in events] == ["response.created", "response.output_item.added", "response.output_item.done", "response.completed"]
    assert events[-1]["response"]["usage"] is None
    assert len(events[-1]["response"]["output"]) == 1
    assert probe.synthetic_response(kind, 2)[-1]["response"]["output"][0]["type"] == "message"


def test_marker_callback_is_bound_to_exact_tool_and_arguments():
    value, allowed = probe.bound_tool_response({"namespace": "security_review", "tool": "read_security_batch_context", "arguments": {"path": "marker.py"}})
    assert allowed and json.loads(value["contentItems"][0]["text"])["marker"] == probe.MARKER
    for params in ({"tool": "exec_command", "arguments": {}},
                   {"tool": "read_security_batch_context", "arguments": {"path": "other.py"}},
                   {"tool": "read_security_batch_context", "arguments": {"path": "marker.py", "workspace": "other"}}):
        value, allowed = probe.bound_tool_response(params)
        assert not allowed and value["success"] is False


def test_negative_privileged_probes_never_supply_command_or_agent_prompt():
    for kind in ("unavailable_shell", "unavailable_spawn"):
        item = probe.synthetic_response(kind, 1)[-1]["response"]["output"][0]
        assert json.loads(item["arguments"]) == {}


def test_request_capture_excludes_prompt_content_and_other_items():
    outputs = [{"type": "function_call_output", "output": "allowed"},
               {"type": "custom_tool_call_output", "output": "also allowed"}]
    body = {"input": [{"type": "message", "content": "private"}, *outputs]}
    assert probe.tool_output_items(body) == outputs


def test_unknown_probe_kind_rejected_before_protocol_execution():
    with pytest.raises(ValueError):
        probe.synthetic_response("spawn_agent", 1)


def test_profile_exposes_only_one_application_reader_in_separate_namespace():
    tools = probe.dynamic_tools()
    assert len(tools) == 1 and tools[0]["name"] == "security_review"
    assert [tool["name"] for tool in tools[0]["tools"]] == ["read_security_batch_context"]
    assert tools[0]["tools"][0]["inputSchema"]["additionalProperties"] is False


def test_fingerprint_changes_for_host_binary_or_configuration(tmp_path):
    binary = tmp_path / "codex.exe"
    binary.write_bytes(b"first host binary")
    first = probe.profile_fingerprint(str(binary), {"agents.enabled": "false"})
    changed_config = probe.profile_fingerprint(str(binary), {"agents.enabled": "true"})
    assert first["isolation_config_sha256"] != changed_config["isolation_config_sha256"]
    binary.write_bytes(b"second host binary")
    changed_host = probe.profile_fingerprint(str(binary), {"agents.enabled": "false"})
    assert first["host_binary_sha256"] != changed_host["host_binary_sha256"]


def test_missing_execution_evidence_cannot_be_authorized_by_ready_boolean():
    result = probe.assess_suite({"read_direct": {"ready_for_model": True, "execution_profile_verified": True}})
    assert result["execution_profile_verified"] is False
    assert result["status"] == "PROBE_FAILED"
