"""Bound-project MCP wiring, using no model, scanner, or global installation."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.codex_host_claims import CodexClaimGuard
from security_runtime.hook_state import HookStateStore
from security_runtime.integration_state import WorkspaceBinding
from security_runtime.mcp_server import create_server


def run_sdk(coroutine):
    """Exercise SDK validation/serialization without Windows socketpair I/O."""
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    finally:
        coroutine.close()
    raise AssertionError("Unexpected asynchronous suspension")


def structured(result):
    if hasattr(result, "structuredContent"):
        return result.structuredContent
    if isinstance(result, tuple):
        return result[1]
    return json.loads(result[0].text)


def invoke(server, name, **arguments):
    return structured(run_sdk(server.call_tool(name, arguments)))


class FakeTasks:
    def __init__(self, events):
        self.events = events

    def finish(self, workspace, ref):
        self.events.append(("tasks.finish_static", workspace, ref))
        return dict(status="STATIC_COMPLETE", scanner_run=True)

    def prepare(self, workspace, ref):
        self.events.append(("tasks.prepare_final", workspace, ref))
        return dict(status="REVIEW_REQUIRED", review_session="final-session")

    def skip(self, workspace, ref, reason):
        self.events.append(("tasks.skip", workspace, ref, reason))
        return dict(status="SKIPPED")


class FakeBatches:
    def __init__(self, events):
        self.events = events
        self.packet = dict(status="REVIEW_REQUIRED", task_ref="task-1", batch_ref="batch-1",
            review_session="private-session-value", dispatch_required=True,
            review_scope=["orders.py"], review_handoff={"private": "constructor-only"},
            scanner_run=False)

    def prepare(self, workspace, ref, key):
        self.events.append(("batches.prepare", workspace, ref, key))
        return self.packet

    def get(self, workspace, ref):
        self.events.append(("batches.get", workspace, ref))
        return dict(status="OK", batches=[])


class FakeHost:
    def __init__(self, events):
        self.events = events
        self.private_packets = []

    def checkpoint(self, workspace, ref, key, packet):
        self.events.append(("host.checkpoint", workspace, ref, key))
        self.private_packets.append(deepcopy(packet))
        # A trusted adapter owns a private copy; a later adapter mutation must
        # not alter the Runtime packet or the developing agent's public data.
        packet["review_scope"].append("adapter-private.py")
        return dict(running=True, reviews_started=1, pending_checkpoint=False)

    def status(self, workspace, ref):
        self.events.append(("host.status", workspace, ref))
        return dict(running=False, reviews_started=0, usage={"input_tokens": 0})

    def stop_dispatch(self, workspace, ref):
        self.events.append(("host.stop_dispatch", workspace, ref))

    def before_final(self, workspace, ref):
        self.events.append(("host.before_final", workspace, ref))
        return dict(final_closed=True, dispatch_closed=True)

    def close(self):
        self.events.append(("host.close",))


@pytest.fixture
def wired(tmp_path, monkeypatch):
    root = tmp_path / "project"
    root.mkdir()
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    # A pytest temp directory may be nested under the development repository.
    # Give both projects their own boundary so resolution cannot select that
    # enclosing repository instead of the explicitly bound fixture project.
    for project in (root, foreign):
        subprocess.run(["git", "init", "-q", str(project)], check=True,
                       capture_output=True)
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("SECURITY_RUNTIME_GLOBAL", "0")
    monkeypatch.delenv("SECURITY_RUNTIME_WORKSPACE", raising=False)
    monkeypatch.delenv("SECURITY_RUNTIME_BATCH_REVIEW", raising=False)
    events = []
    tasks, batches, host = FakeTasks(events), FakeBatches(events), FakeHost(events)
    import security_runtime.task_security as task_module
    import security_runtime.task_security_batch as batch_module
    monkeypatch.setattr(task_module, "TaskSecurityService", lambda *a, **k: tasks)
    monkeypatch.setattr(batch_module, "TaskSecurityBatchService", lambda *a, **k: batches)
    binding = WorkspaceBinding.create(root, "generic-mcp")
    hooks = SimpleNamespace(store=HookStateStore(tmp_path / "hooks"), managed_registry=lambda: None)
    runtime = SimpleNamespace(store=None)

    def factory(received_tasks, received_batches, bound_root):
        assert received_tasks is tasks and received_batches is batches
        assert bound_root == root
        events.append(("host.factory",))
        return host

    def build(*, enabled=True, background=True, readiness=None):
        return create_server(runtime, hook_coordinator=hooks, workspace_binding=binding,
            global_mode=False, include_batch_review=enabled,
            batch_review_host_factory=factory if background else None,
            project_readiness_adapter=readiness,
            remediation_factory=lambda *a, **k: SimpleNamespace(config=None))

    return SimpleNamespace(root=root, foreign=foreign, events=events, tasks=tasks,
                           batches=batches, host=host, factory=factory, build=build,
                           runtime=runtime, hooks=hooks)


def test_checkpoint_is_owned_by_host_and_returns_without_developer_dispatch(wired):
    server = wired.build()
    original = deepcopy(wired.batches.packet)
    out = invoke(server, "prepare_security_batch", task_ref="task-1", checkpoint_key="orders-query")
    assert [event[0] for event in wired.events] == [
        "batches.prepare", "host.factory", "host.checkpoint"]
    assert wired.host.private_packets == [original]
    assert wired.batches.packet["review_scope"] == ["orders.py"]
    assert out["review_scope"] == ["orders.py"]
    assert out["host_background_owned"] is True
    assert out["dispatch_required"] is False
    assert out["background_host"]["running"] is True
    assert out["scanner_run"] is False
    assert "review_session" not in out and "review_handoff" not in out
    assert "private-session-value" not in json.dumps(out)


def test_status_is_not_read_only_but_never_checkpoints_or_starts_work(wired):
    server = wired.build()
    metadata = {tool.name: tool for tool in run_sdk(server.list_tools())}
    assert metadata["get_security_batches"].annotations.readOnlyHint is False
    assert metadata["get_security_batches"].annotations.openWorldHint is False
    first = invoke(server, "get_security_batches", task_ref="task-1")
    second = invoke(server, "get_security_batches", task_ref="task-1")
    assert first == second and first["background_host"]["reviews_started"] == 0
    assert [event[0] for event in wired.events] == [
        "batches.get", "host.factory", "host.status", "batches.get", "host.status"]
    assert not wired.host.private_packets


def test_static_finish_closes_dispatch_before_scanning(wired):
    server = wired.build()
    out = invoke(server, "finish_security_task", task_ref="task-1")
    assert out["status"] == "STATIC_COMPLETE"
    assert [event[0] for event in wired.events] == [
        "host.factory", "host.stop_dispatch", "tasks.finish_static", "host.status"]
    assert not wired.host.private_packets


def test_skip_also_stops_dispatch_without_finishing_or_starting_a_model(wired):
    server = wired.build()
    out = invoke(server, "finish_security_task", task_ref="task-1", skip_review_reason="test gap")
    assert out["status"] == "SKIPPED"
    assert [event[0] for event in wired.events] == [
        "host.factory", "host.stop_dispatch", "tasks.skip"]


def test_final_preparation_drains_existing_host_before_sealing_core_version(wired):
    server = wired.build()
    out = invoke(server, "prepare_task_security_review", task_ref="task-1")
    assert [event[0] for event in wired.events] == [
        "host.factory", "host.before_final", "tasks.prepare_final"]
    assert out["review_session"] == "final-session"
    assert out["background_host"]["final_closed"] is True
    assert not wired.host.private_packets


def test_installed_host_rejects_manual_intermediate_submission(wired):
    server = wired.build()
    with pytest.raises(Exception, match="owns intermediate submissions"):
        invoke(server, "submit_security_batch_review", task_ref="task-1", batch_ref="batch-1",
               review_session="private-session-value", findings=[], coverage="PARTIAL",
               limitations=["test only"])
    assert wired.events == []


def test_existing_opt_in_batch_flow_retains_its_manual_handoff(wired):
    server = wired.build(background=False)
    out = invoke(server, "prepare_security_batch", task_ref="task-1", checkpoint_key="legacy")
    assert out["review_session"] == "private-session-value"
    assert out["review_handoff"] == {"private": "constructor-only"}
    assert out["dispatch_required"] is True
    assert "host_background_owned" not in out
    metadata = {tool.name: tool for tool in run_sdk(server.list_tools())}
    assert metadata["get_security_batches"].annotations.readOnlyHint is True
    assert [event[0] for event in wired.events] == ["batches.prepare"]


def test_default_connection_has_no_background_or_batch_tools(wired):
    server = wired.build(enabled=None, background=False)
    names = {tool.name for tool in run_sdk(server.list_tools())}
    assert "prepare_security_batch" not in names
    assert "get_security_batches" not in names
    out = invoke(server, "finish_security_task", task_ref="task-1")
    assert out == dict(status="STATIC_COMPLETE", scanner_run=True)
    assert [event[0] for event in wired.events] == ["tasks.finish_static"]


@pytest.mark.parametrize("extra", [
    {"global_mode": True, "include_batch_review": True},
    {"global_mode": False, "include_batch_review": False},
    {"global_mode": False, "include_batch_review": True},
])
def test_trusted_background_factory_rejects_global_disabled_or_unbound_connections(wired, extra):
    with pytest.raises(ValueError, match="requires"):
        create_server(wired.runtime, hook_coordinator=wired.hooks,
            batch_review_host_factory=wired.factory, **extra)
    assert wired.events == []


def test_readiness_adapter_cannot_be_added_to_global_or_unbound_connection(wired):
    for global_mode in (False, True):
        with pytest.raises(ValueError, match="requires"):
            create_server(wired.runtime, global_mode=global_mode,
                          project_readiness_adapter=lambda *a: pytest.fail("must not execute"))


def test_readiness_guard_runs_before_project_adapter(wired, monkeypatch):
    original = CodexClaimGuard.accept

    def observed_guard(self, arguments, root, diagnostics):
        result = original(self, arguments, root, diagnostics)
        wired.events.append(("claims.accept", result, diagnostics["host_claim_status"]))
        return result

    monkeypatch.setattr(CodexClaimGuard, "accept", observed_guard)

    def readiness(root, session_id, tools):
        wired.events.append(("readiness.adapter", root, session_id))
        assert root == wired.root and "prepare_security_batch" in tools
        return dict(status="EXPERIMENTAL_CONNECTION_OBSERVED", scanner_run=False, model_run=False)

    server = wired.build(readiness=readiness)
    out = structured(server._tool_manager.get_tool("handle_readiness_event").fn(
        event="SessionStart", workspace_path=str(wired.root), session_id="session-1"))
    assert out["host_claim_status"] == "VALID"
    assert out["status"] == "EXPERIMENTAL_CONNECTION_OBSERVED"
    assert wired.events == [
        ("claims.accept", None, "VALID"), ("readiness.adapter", wired.root, "session-1")]
    assert not out["scanner_run"] and not out["model_run"]


@pytest.mark.parametrize("change", [
    {"event": "Stop"}, {"session_id": "${session_id}"}, {"workspace_path": "."},
    {"session_id": ""}, {"permission_mode": "untrusted-value"},
])
def test_invalid_readiness_claims_never_reach_adapter(wired, change):
    server = wired.build(readiness=lambda *a: pytest.fail("invalid claims reached adapter"))
    arguments = dict(event="SessionStart", workspace_path=str(wired.root), session_id="session-1")
    arguments.update(change)
    out = structured(server._tool_manager.get_tool("handle_readiness_event").fn(**arguments))
    assert out["status"] == "INCONCLUSIVE" and out["scanner_run"] is False
    assert wired.events == []


def test_foreign_readiness_workspace_never_reaches_adapter(wired):
    server = wired.build(readiness=lambda *a: pytest.fail("foreign workspace reached adapter"))
    out = structured(server._tool_manager.get_tool("handle_readiness_event").fn(
        event="SessionStart", workspace_path=str(wired.foreign), session_id="session-1"))
    assert out["status"] == "INCONCLUSIVE"
    assert out["workspace_claim_match"] is False and not out["scanner_run"]
    assert wired.events == []


@pytest.mark.parametrize("tool,arguments", [
    ("prepare_security_batch", dict(task_ref="task-1", checkpoint_key="foreign")),
    ("get_security_batches", dict(task_ref="task-1")),
    ("finish_security_task", dict(task_ref="task-1")),
    ("prepare_task_security_review", dict(task_ref="task-1")),
])
def test_foreign_workspace_rejected_before_core_or_host_call(wired, tool, arguments):
    server = wired.build()
    with pytest.raises(Exception, match="outside this MCP connection"):
        invoke(server, tool, **arguments, workspace_path=str(wired.foreign))
    assert wired.events == []


def test_public_tool_arguments_cannot_supply_or_replace_trusted_factory(wired):
    server = wired.build()
    with pytest.raises(Exception):
        invoke(server, "prepare_security_batch", task_ref="task-1", checkpoint_key="claim",
               batch_review_host_factory="untrusted", ready=True)
    assert wired.events == []


def test_closing_unused_connection_never_constructs_or_starts_background_host(wired):
    server = wired.build()
    server._experimental_batch_host_close()
    assert wired.events == []
    invoke(server, "get_security_batches", task_ref="task-1")
    server._experimental_batch_host_close()
    assert wired.events[-1] == ("host.close",)
