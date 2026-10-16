"""Trusted adapter concurrency tests; deterministic backend, no real model."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.task_security import TaskSecurityService
from security_runtime.task_security_batch import TaskSecurityBatchService

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
Host = importlib.import_module("experimental_batch_host").ExperimentalBatchHost


class NoScan:
    def scan(self, *_args, **_kwargs):
        pytest.fail("An intermediate model checkpoint must not scan or build")


class ControlledBackend:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = []
        self.reads = []
        self.read_after_release = False
        self.result_status = "COMPLETED"
        self.foreign_binding = False
        self.usage_incomplete = False

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        if not self.read_after_release:
            self.reads.append(kwargs["read_context"](path="route.py"))
        self.started.set()
        assert self.release.wait(5), "Test failed to release its synthetic reviewer"
        if self.read_after_release:
            try:
                self.reads.append(kwargs["read_context"](path="route.py"))
            except ValueError:
                self.reads.append("READ_CLOSED")
        fields = kwargs["schema"]["properties"]
        value = {key: fields[key]["const"] for key in ("task_ref", "batch_ref", "review_session")}
        if self.foreign_binding:
            value["batch_ref"] = "tb1-" + "f" * 32
        value.update(findings=[], coverage="REVIEWED", limitations=[])
        return dict(status=self.result_status, result=value, model_observed=self.result_status == "COMPLETED",
            usage_accounting_may_be_incomplete=self.usage_incomplete,
            usage=dict(input_tokens=13, cached_input_tokens=0, output_tokens=2, reasoning_output_tokens=0))


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    (root / "route.py").write_text("def route(user):\n    return allowed(user)\n")
    tasks = TaskSecurityService(NoScan(), HookStateStore(tmp_path / "hooks"))
    ref = tasks.begin(root, "desktop-experience")['task_ref']
    batches = TaskSecurityBatchService(tasks)
    backend = ControlledBackend()
    host = Host(tasks, batches, root, tmp_path / "reviews", backend=backend, drain_timeout_s=0)
    yield root, ref, tasks, batches, backend, host
    backend.release.set()
    host.close()


def checkpoint(sample, key="unit-1", text="def route(user):\n    return load(user)\n"):
    root, ref, _, batches, _, host = sample
    (root / "route.py").write_text(text)
    packet = batches.prepare(root, ref, key)
    return packet, host.checkpoint(root, ref, key, packet)


def wait_status(host, root, ref, predicate):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        value = host.status(root, ref)
        if predicate(value):
            return value
        time.sleep(.01)
    pytest.fail("Background adapter did not reach its expected bounded state")


def test_checkpoint_returns_while_model_runs_and_old_snapshot_becomes_stale(sample):
    root, ref, tasks, batches, backend, host = sample
    packet, first = checkpoint(sample)
    assert first["running"] and backend.started.wait(2)
    assert tasks.load(root, ref)["phase"] == "ACTIVE"
    (root / "route.py").write_text("def route(user):\n    return replacement(user)\n")
    backend.release.set()
    result = wait_status(host, root, ref, lambda value: not value["running"])
    assert len(backend.calls) == 1
    assert "load(user)" in json.dumps(backend.reads[0])
    assert result["reviews"][0]["submission_accepted"]
    assert result["reviews"][0]["validity"] == "STALE"
    assert batches.get(root, ref)["batches"][0]["validity"] == "STALE"
    assert packet["review_session"] not in json.dumps(result)
    assert "review_handoff" not in backend.calls[0]["prompt"]
    saved = (host.directory / ref / "status.json").read_text(encoding="utf-8")
    assert packet["review_session"] not in saved and "def route" not in saved


def test_only_latest_pending_snapshot_starts_after_current_parent_submission(sample):
    root, ref, _, _, backend, host = sample
    checkpoint(sample)
    assert backend.started.wait(2)
    checkpoint(sample, "unit-2", "def route(user):\n    return second(user)\n")
    packet, queued = checkpoint(sample, "unit-3", "def route(user):\n    return third(user)\n")
    assert queued["pending_checkpoint"] and len(backend.calls) == 1
    backend.release.set()
    result = wait_status(host, root, ref,
        lambda value: value["reviews_started"] == 2 and not value["running"])
    assert len(backend.calls) == 2
    assert "third(user)" in json.dumps(backend.reads[1])
    assert result["reviews"][1]["batch_ref"] == packet["batch_ref"]
    assert result["reviews"][1]["submission_accepted"]


def test_busy_parent_submission_is_retried_without_a_second_model_call(sample, monkeypatch):
    root, ref, _, batches, backend, host = sample
    original = batches.submit
    attempts = []

    def busy_twice(*args, **kwargs):
        attempts.append(True)
        return dict(status="BUSY") if len(attempts) <= 2 else original(*args, **kwargs)

    monkeypatch.setattr(batches, "submit", busy_twice)
    checkpoint(sample)
    assert backend.started.wait(2)
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: row["reviews"][0]["submission_accepted"])
    assert len(backend.calls) == 1 and len(attempts) == 3
    assert value["reviews"][0]["usage"]["input_tokens"] == 13


def test_final_deadline_revokes_reader_cancels_and_never_accepts_late_result(sample):
    root, ref, _, batches, backend, host = sample
    backend.read_after_release = True
    backend.usage_incomplete = True
    checkpoint(sample)
    assert backend.started.wait(2)
    result = host.before_final(root, ref)
    assert result["final_closed"] and result["dispatch_closed"]
    assert backend.calls[0]["cancel_event"].is_set()
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert backend.reads == ["READ_CLOSED"]
    assert not value["reviews"][0]["submission_accepted"]
    assert value["reviews"][0]["usage"]["input_tokens"] == 13
    assert value["reviews"][0]["usage_accounting_may_be_incomplete"] is True
    assert batches.get(root, ref)["batches"][0]["status"] == "RUNNING"
    # Core final preparation owns persisted CANCELLED_AT_FINAL, not this host.


def test_finish_stops_pending_dispatch_while_existing_model_may_complete(sample):
    root, ref, _, _, backend, host = sample
    checkpoint(sample)
    assert backend.started.wait(2)
    checkpoint(sample, "unit-2", "def route(user):\n    return second(user)\n")
    host.stop_dispatch(root, ref)
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert len(backend.calls) == 1
    assert value["reviews"][0]["submission_accepted"]
    assert not value["pending_checkpoint"]


def test_failed_host_records_partial_and_stops_further_model_dispatch(sample):
    root, ref, _, batches, backend, host = sample
    backend.result_status = "UNSUPPORTED_HOST"
    checkpoint(sample)
    assert backend.started.wait(2)
    checkpoint(sample, "unit-2", "def route(user):\n    return second(user)\n")
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert len(backend.calls) == 1 and value["disabled_reason"]
    assert value["reviews"][0]["status"] == "FAILED_PARTIAL"
    assert value["reviews"][0]["model_observed"] is False
    assert batches.get(root, ref)["batches"][0]["coverage"] == "PARTIAL"


def test_foreign_model_binding_is_not_submitted_as_a_successful_review(sample):
    root, ref, _, _, backend, host = sample
    backend.foreign_binding = True
    checkpoint(sample)
    assert backend.started.wait(2)
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert value["reviews"][0]["status"] == "FAILED_PARTIAL"
    assert value["reviews"][0]["coverage"] == "PARTIAL"


def test_review_limit_and_bound_project_cannot_be_overridden(sample):
    root, ref, tasks, batches, backend, old = sample
    old.close()
    host = Host(tasks, batches, root, old.directory, backend=backend, max_reviews_per_task=1)
    (root / "route.py").write_text("def route(user):\n    return first(user)\n")
    first = batches.prepare(root, ref, "one")
    host.checkpoint(root, ref, "one", first)
    assert backend.started.wait(2)
    (root / "route.py").write_text("def route(user):\n    return second(user)\n")
    pending = batches.prepare(root, ref, "two")
    host.checkpoint(root, ref, "two", pending)
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert len(backend.calls) == 1 and value["disabled_reason"]
    with pytest.raises(ValueError):
        host.status(root.parent, ref)
    with pytest.raises(ValueError):
        host.status(root, "../../unsafe")
    host.close()


def test_restart_never_resumes_or_reconstructs_a_model_task(sample):
    root, ref, tasks, batches, backend, host = sample
    checkpoint(sample)
    assert backend.started.wait(2)
    backend.release.set()
    wait_status(host, root, ref, lambda row: not row["running"])
    host.close()
    fresh = Host(tasks, batches, root, host.directory, backend=backend)
    summary = fresh.status(root, ref)
    assert summary["reviews_started"] == 1 and summary["automatic_restart"] is False
    assert summary["dispatch_closed"] and summary["disabled_reason"]
    assert len(backend.calls) == 1
    fresh.close()


def test_read_status_can_retry_parent_submission_but_never_dispatches_pending_model(sample, monkeypatch):
    root, ref, _, batches, backend, host = sample
    original = batches.submit
    busy = threading.Event()
    busy.set()
    monkeypatch.setattr(batches, "submit", lambda *args, **kw:
        dict(status="BUSY") if busy.is_set() else original(*args, **kw))
    checkpoint(sample)
    assert backend.started.wait(2)
    checkpoint(sample, "unit-2", "def route(user):\n    return second(user)\n")
    backend.release.set()
    wait_status(host, root, ref, lambda row: row["reviews"][0]["status"] == "PARENT_SUBMISSION_PENDING")
    busy.clear()
    value = host.status(root, ref)
    assert value["reviews"][0]["submission_accepted"]
    assert value["pending_checkpoint"] and len(backend.calls) == 1


def test_unavailable_pending_task_stops_dispatch_without_thread_exception(sample, monkeypatch):
    root, ref, _, batches, backend, host = sample
    checkpoint(sample)
    assert backend.started.wait(2)
    checkpoint(sample, "unit-2", "def route(user):\n    return second(user)\n")

    def unavailable(*_args, **_kwargs):
        raise ValueError("Do not copy private exception source into public status")

    monkeypatch.setattr(batches, "prepare", unavailable)
    backend.release.set()
    value = wait_status(host, root, ref, lambda row: not row["running"])
    assert value["disabled_reason"] and len(backend.calls) == 1
    assert "private exception" not in json.dumps(value)


def test_public_status_keeps_metadata_without_copying_canonical_findings(sample):
    root, ref, _, _, _, host = sample
    state = host._state(ref)
    state.rows.append(dict(job_id="display-only", batch_ref="tb1-" + "b" * 32,
        status="ACCEPTED", candidate_count=1, coverage="PARTIAL", findings=[
            dict(title="Canonical candidate", evidence_locations=[dict(numbered_lines=["private evidence text"])])]))
    value = host.status(root, ref)
    assert value["reviews"][0]["candidate_count"] == 1
    assert "findings" not in value["reviews"][0]
    saved = (host.directory / ref / "status.json").read_text(encoding="utf-8")
    assert "Canonical candidate" not in saved and "private evidence text" not in saved


def test_batch_schema_explains_exact_evidence_ids_without_changing_other_short_fields():
    module = importlib.import_module("experimental_batch_host")
    schema = module._batch_schema(dict(task_ref="task", batch_ref="batch", review_session="session"))
    fields = schema["properties"]["findings"]["items"]["properties"]
    for key in ("primary_evidence", "task_evidence"):
        assert fields[key]["pattern"] == r"^be1-[0-9a-f]{32}$"
        assert "identifier" in fields[key]["description"]
    assert fields["evidence_refs"]["items"]["pattern"] == fields["task_evidence"]["pattern"]
    assert "pattern" not in fields["title"] and "pattern" not in fields["category"]
