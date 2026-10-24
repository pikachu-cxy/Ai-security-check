"""Actual private-storage contention through an isolated closeout queue.

Sources, signed queue records and frozen queued inputs are real temp files.
The detector is the existing LedgerRuntime fixture; no native host/MCP task,
installed scanner, model call or detached worker is created.
"""
import copy
import os
import stat
import threading

import pytest

from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.queued_closeout import enqueue, execute_one, status
from security_runtime.tasks.queued_inputs import QueuedInputs
from security_runtime.tasks.security_state import TaskSecurityStore
from test_closeout_queue import setup
from test_private_state_writers import _directory_flock
from test_task_security import service  # noqa: F401
from test_review_metadata_compatibility import _encoded, _task_row


pytestmark = pytest.mark.skipif(os.name == "nt", reason="Real POSIX directory flock")


@pytest.fixture(autouse=True)
def private_dispatcher(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "isolated-dispatcher"))


def _queued(sample):
    task, root, ref = setup(sample, name="isolated-private-state-queue")
    baseline = copy.deepcopy(task.load(root, ref)["baseline"])
    (root / "routes.py").write_text("changed = True\n")
    enqueue(task, root, ref, launch=False)
    queue = CloseoutQueue(task.hooks, root, now=task.now)
    row = queue.read(ref)
    inputs = QueuedInputs(task.hooks, root, now=task.now)
    target = inputs.open(row["input_ref"])
    frozen = {str(path.relative_to(target)): path.read_bytes()
              for path in target.rglob("*") if path.is_file()}
    return task, root, ref, baseline, queue, row, inputs, frozen


def _assert_retry_original(task, root, ref, baseline, queue, original, inputs, frozen):
    current = queue.read(ref)
    assert current["state"] == "RETRY_WAIT"
    assert current["reason"] in {"BUSY", "OWNED_WORKSPACE_STORAGE_BUSY"}
    for key in ("task_ref", "job_ref", "owner", "baseline_digest", "end", "input_ref", "configuration"):
        assert current[key] == original[key]
    assert current["attempts"] == original["attempts"] + 1
    assert current["finished_at"] is None and current["lease_owner"] is None
    assert task.load(root, ref)["baseline"] == baseline
    target = inputs.open(original["input_ref"])
    assert {str(path.relative_to(target)): path.read_bytes()
            for path in target.rglob("*") if path.is_file()} == frozen


def _resume(task, root, ref, baseline, queue, original, inputs):
    # Advance only the signed queue scheduling cursor, never a task/evidence
    # ledger or source baseline. This avoids a wall-clock sleep in the test.
    with queue.transaction() as db:
        current = queue._get(db, ref)
        queue._put(db, ref, dict(current, next_attempt_at=0))
    assert execute_one(task, root, ref)
    current = queue.read(ref)
    assert current["state"] == "READY_FOR_REVIEW"
    for key in ("task_ref", "job_ref", "owner", "baseline_digest", "end", "input_ref"):
        assert current[key] == original[key]
    assert task.load(root, ref)["baseline"] == baseline
    assert status(task, root, ref)["status"] == "READY_FOR_REVIEW"
    # Successful terminal execution may now release the original raw inputs.
    assert inputs.read(original["input_ref"]) is None


def test_real_directory_lock_busy_preserves_frozen_inputs_and_resumes_same_task(service):
    task, root, ref, baseline, queue, row, inputs, frozen = _queued(service)
    with _directory_flock(task.store(root).path.parent):
        assert execute_one(task, root, ref)
        _assert_retry_original(task, root, ref, baseline, queue, row, inputs, frozen)
    assert service[2].calls == []
    _resume(task, root, ref, baseline, queue, row, inputs)
    assert len(service[2].calls) == 1


def test_real_task_save_admission_busy_is_retryable_without_rebuilding_sources(service, monkeypatch):
    from security_runtime.owned_workspace_storage import OwnedWorkspaceStorageError

    task, root, ref, baseline, queue, row, inputs, frozen = _queued(service)
    save, seen = TaskSecurityStore.save, []

    def contended_save(store, value, **kwargs):
        if not seen and value.get("task_ref") == ref:
            with _directory_flock(store.path.parent):
                try:
                    return save(store, value, **kwargs)
                except OwnedWorkspaceStorageError as error:
                    seen.append(error.reason_code)
                    raise
        return save(store, value, **kwargs)

    # The wrapper introduces an actual competing process only at the real save
    # boundary. The exception comes from the actual admission/flock operation.
    with monkeypatch.context() as scoped:
        scoped.setattr(TaskSecurityStore, "save", contended_save)
        assert execute_one(task, root, ref)
    assert seen == ["OWNED_WORKSPACE_STORAGE_BUSY"]
    _assert_retry_original(task, root, ref, baseline, queue, row, inputs, frozen)
    _resume(task, root, ref, baseline, queue, row, inputs)
    assert len(service[2].calls) == 1


def test_partial_real_fchmod_failure_preserves_frozen_inputs_spending_and_same_job(service, monkeypatch):
    from security_runtime.owned_workspace_storage import OwnedWorkspaceStorageError

    task, root, ref, baseline, queue, _, inputs, _ = _queued(service)
    assert execute_one(task, root, ref)
    assert queue.read(ref)["state"] == "READY_FOR_REVIEW"
    packet = task.prepare(root, ref)
    assert packet["review_session"]
    delivery = task.read(root, ref, packet["review_session"], "routes.py", 1, 1)
    assert delivery["evidence_id"] and delivery["lines"]
    spent = copy.deepcopy(task.load(root, ref)["review_ledger"])
    assert spent["total_bytes"] > 0 and spent["source_bytes"] > 0 and spent["reads"] > 0
    previous = queue.read(ref)
    (root / "routes.py").write_text("second_changed = True\n")
    enqueue(task, root, ref, launch=False, recovery_from=previous)
    row = queue.read(ref)
    assert row["job_ref"] != previous["job_ref"]
    target = inputs.open(row["input_ref"])
    frozen = {str(path.relative_to(target)): path.read_bytes()
              for path in target.rglob("*") if path.is_file()}
    original = copy.deepcopy(task.load(root, ref))
    raw = _task_row(task.store(root), ref)
    save, fchmod, seen = TaskSecurityStore.save, os.fchmod, []
    active_thread = threading.get_ident()

    def interrupted_save(store, value, **kwargs):
        if seen or value.get("task_ref") != ref:
            return save(store, value, **kwargs)
        directory = store.path.parent
        key = directory / "snapshot.key"
        directory.chmod(0o755)
        store.path.chmod(0o644)
        key.chmod(0o644)
        calls = []

        def fail_second(fd, mode):
            if threading.get_ident() == active_thread:
                calls.append(mode)
                if len(calls) == 2:
                    raise PermissionError("isolated second fchmod failure")
            return fchmod(fd, mode)

        with monkeypatch.context() as scoped:
            scoped.setattr(os, "fchmod", fail_second)
            try:
                return save(store, value, **kwargs)
            except OwnedWorkspaceStorageError as error:
                seen.append(dict(reason=error.reason_code, state=error.report["state"],
                    changed=list(error.report["changed"]), calls=calls,
                    directory_mode=stat.S_IMODE(directory.stat().st_mode),
                    database_mode=stat.S_IMODE(store.path.stat().st_mode),
                    key_mode=stat.S_IMODE(key.stat().st_mode)))
                raise

    with monkeypatch.context() as scoped:
        scoped.setattr(TaskSecurityStore, "save", interrupted_save)
        assert execute_one(task, root, ref)
    assert seen == [dict(reason="OWNED_WORKSPACE_STORAGE_UPGRADE_INCOMPLETE",
        state="UPGRADE_INCOMPLETE", changed=["."], calls=[0o700, 0o600],
        directory_mode=0o700, database_mode=0o644, key_mode=0o644)]
    # The first actual fchmod remains effective. A failed second attempt must
    # preserve the original queued input and every original task accounting row.
    current = queue.read(ref)
    assert current["state"] == "RETRY_WAIT"
    assert current["reason"] == "OWNED_WORKSPACE_STORAGE_UPGRADE_INCOMPLETE"
    assert current["finished_at"] is None and current["lease_owner"] is None
    assert current["attempts"] == row["attempts"] + 1
    for key in ("task_ref", "job_ref", "owner", "baseline_digest", "end", "input_ref", "configuration"):
        assert current[key] == row[key]
    assert _task_row(task.store(root), ref) == raw
    after_failure = task.load(root, ref)
    assert after_failure == original and after_failure["baseline"] == baseline
    assert _encoded(after_failure["review_ledger"]) == _encoded(spent)
    assert {str(path.relative_to(inputs.open(row["input_ref"]))): path.read_bytes()
            for path in target.rglob("*") if path.is_file()} == frozen
    assert len(service[2].calls) == 1
    _resume(task, root, ref, baseline, queue, row, inputs)
    recovered = task.load(root, ref)
    for key in ("source_bytes", "navigation_bytes", "control_bytes", "total_bytes", "reads"):
        assert recovered["review_ledger"][key] >= spent[key]
    assert recovered["review_ledger"]["limits"] == spent["limits"]
    assert len(service[2].calls) == 2
    assert stat.S_IMODE(task.store(root).path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(task.store(root).path.stat().st_mode) == 0o600
    assert stat.S_IMODE((task.store(root).path.parent / "snapshot.key").stat().st_mode) == 0o600


@pytest.mark.parametrize("failure", ["hardlink", "plain_value_error"])
def test_nonretryable_storage_or_plain_errors_are_not_promoted_to_busy(service, monkeypatch, failure):
    task, root, ref, baseline, queue, row, inputs, frozen = _queued(service)
    if failure == "hardlink":
        database = task.store(root).path
        os.link(database, root.parent / "isolated-task-db-link")
    else:
        def failed_finish(*args, **kwargs):
            raise ValueError("isolated nonretryable execution failure")
        monkeypatch.setattr(task, "_finish", failed_finish)
    assert execute_one(task, root, ref)
    current = queue.read(ref)
    assert current["state"] == "FAILED"
    assert current["reason"] == "TASK_EXECUTION_UNAVAILABLE"
    assert current["task_ref"] == row["task_ref"] and current["owner"] == row["owner"]
    assert task.load(root, ref)["baseline"] == baseline
    assert service[2].calls == []
    assert inputs.read(row["input_ref"]) is None
