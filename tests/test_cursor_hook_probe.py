"""The probe must not turn transport evidence into repair authority."""
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("cursor_hook_probe", Path(__file__).resolve().parents[1] / "scripts/cursor_hook_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    project, state = tmp_path / "project", tmp_path / "state"
    project.mkdir(); state.mkdir()
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(project))
    payload = dict(hook_event_name="stop", workspace_roots=[str(project)],
                   conversation_id="synthetic-session", generation_id="synthetic-generation",
                   status="completed", loop_count=0)
    return project, state, payload


def test_followup_once_even_if_host_repeats_zero(fixture):
    project, state, payload = fixture
    output, row = probe.handle(payload, project, state, followup=True)
    assert row["receipt_marker"] in output["followup_message"]
    assert "没有用户修复授权" in output["followup_message"]
    assert probe.handle(payload, project, state, followup=True)[0] == {}
    payload["generation_id"] = "next-generation"
    assert probe.handle(payload, project, state, followup=True)[0] == {}


@pytest.mark.parametrize("status,count", [("aborted", 0), ("error", 0), ("completed", 1), ("completed", True), ("completed", -1)])
def test_cancellation_errors_and_loops_do_not_continue(fixture, status, count):
    project, state, payload = fixture
    payload.update(status=status, loop_count=count)
    assert probe.handle(payload, project, state, followup=True)[0] == {}


def test_foreign_project_or_missing_session_rejected(fixture, monkeypatch):
    project, state, payload = fixture
    monkeypatch.delenv("CURSOR_PROJECT_DIR")
    assert not probe.handle(payload, project, state, followup=True)[1]["accepted"]
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(project))
    payload["conversation_id"] = None
    assert not probe.handle(payload, project, state, followup=True)[1]["accepted"]


def test_raw_content_and_identity_not_logged(fixture):
    project, state, payload = fixture
    payload.update(hook_event_name="postToolUse", tool_name="Write", tool_output="secret-body",
                   transcript_path="private-path", user_email="private-email", command="untrusted-command")
    output, row = probe.handle(payload, project, state)
    assert output.get("additional_context")
    encoded = json.dumps(row)
    for raw in ["secret-body", "private-path", "private-email", "untrusted-command", "synthetic-session", "synthetic-generation"]:
        assert raw not in encoded
    assert probe.handle(payload, project, state)[0] == {}


def test_relative_display_root_uses_fixed_env_anchor_only(fixture, monkeypatch):
    project, state, payload = fixture
    payload["workspace_roots"] = ["project"]
    assert probe.handle(payload, project, state)[1]["workspace_root_corroboration"] == "UNVERIFIED_RELATIVE_METADATA"
    monkeypatch.setenv("CURSOR_PROJECT_DIR", str(state))
    assert not probe.handle(payload, project, state)[1]["accepted"]


def test_other_absolute_root_and_multiroot_are_rejected(fixture):
    project, state, payload = fixture
    for roots in [[str(state)], [str(project), str(state)]]:
        payload["workspace_roots"] = roots
        assert not probe.handle(payload, project, state)[1]["accepted"]


def test_context_waits_for_write_instead_of_read_only_tool(fixture):
    project, state, payload = fixture
    payload.update(hook_event_name="postToolUse", tool_name="Read")
    assert probe.handle(payload, project, state)[0] == {}
    payload["tool_name"] = "Write"
    assert probe.handle(payload, project, state)[0].get("additional_context")
