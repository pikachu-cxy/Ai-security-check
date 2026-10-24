"""Real end publication/cleanup; detector is a fixture, not MCP acceptance.

No new-domain producer, native before proof, semantic proof or history pins.
The imported baseline helpers retain an actual old CAPACITY/nonzero ledger.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
import sqlite3
import threading
import tracemalloc

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.tasks.activity import ActivityStore, POLICY
from security_runtime.tasks.closeout_queue import CloseoutQueue
from security_runtime.tasks.frozen_end_context import (
    END_CONTEXT_FIELD, END_CONTRACT, END_PROFILE,
    FrozenEndBodyContextUnavailable, verify_end_context,
)
from security_runtime.tasks.frozen_body_context import FrozenBodyContextUnavailable
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.tasks.queued_closeout import enqueue, execute_one, cancel
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import MAX_RECORD_BYTES, TaskSecurityStore
from test_frozen_body_context_producer import (
    _sample as _baseline_sample, _row, _private_files, _canonical_source,
    _no_hydration, _assert_old_unchanged, isolated_optional_observations,
)
from test_task_security import LedgerRuntime
from test_private_state_writers import _directory_flock


def _new(tmp_path, *, baseline=True):
    sample = _baseline_sample(tmp_path, count=2, enabled=baseline)
    sample.engine = LedgerRuntime()
    sample.service = TaskSecurityService(sample.engine, sample.state.hooks, owner=sample.owner,
        now=lambda: sample.clock[0], frozen_body_contexts=baseline)
    sample.ref = sample.service.begin(sample.root, "end-producer", check_policy=POLICY)["task_ref"]
    sample.baseline = copy.deepcopy(sample.service.load(sample.root, sample.ref)["baseline"])
    return sample


def _finish(sample, value="end_one = 1\n"):
    sample.clock[0] += 1
    (sample.root / "module_0000.py").write_text(value)
    assert sample.service.finish(sample.root, sample.ref)["status"] == "READY"
    return sample.service.load(sample.root, sample.ref)["end"]


def _get(sample, end, **kwargs):
    args = dict(owner=sample.owner, expected_version_ref=end["version_ref"])
    args.update(kwargs)
    return sample.service.store(sample.root).get_frozen_end_body_context(sample.ref, **args)


def _error(suffix):
    return pytest.raises(FrozenEndBodyContextUnavailable,
        match="^FROZEN_END_BODY_CONTEXT_" + suffix + "$")


def _original(sample, end):
    reference = end["preimages"]["module_0000.py"]
    return sample.service.end_versions(sample.root).read(end["version_ref"], "module_0000.py",
        end["hashes"]["module_0000.py"], reference, strict_readonly=True)


def _preserved(sample):
    assert sample.service.load(sample.root, sample.ref)["baseline"] == sample.baseline
    _assert_old_unchanged(sample)


def test_real_finish_publishes_exact_end_context_with_original_reference_ttl(tmp_path):
    s = _new(tmp_path)
    end = _finish(s)
    packet = _get(s, end, expected_source=end["paged_entries"]["source"])
    payload = verify_end_context(s.state.hooks, s.root, packet, task_ref=s.ref,
        owner=s.owner, version_ref=end["version_ref"], now=lambda: s.clock[0])
    assert packet == end[END_CONTEXT_FIELD]
    assert payload["contract"] == END_CONTRACT and payload["profile"] == END_PROFILE
    assert payload["field"] == "end" and payload["preimage_namespace"] == "end"
    assert payload["task_ref"] == s.ref
    assert payload["preimage_task_ref"] == payload["version_ref"] == end["version_ref"] != s.ref
    assert payload["source"] == _canonical_source(end) == end["paged_entries"]["source"]
    reference = end["preimages"]["module_0000.py"]
    assert payload["created_at"] == reference["created_at"] == s.clock[0]
    assert payload["expires_at"] == reference["expires_at"] == s.clock[0] + 30 * 86400
    assert payload["consistency"] == "OBSERVED_ONLY"
    assert _original(s, end) == ["end_one = 1"]
    _preserved(s)


def test_unchanged_finish_reuses_same_context_version_and_expiry_without_writer(tmp_path, monkeypatch):
    s = _new(tmp_path)
    end = _finish(s)
    calls = len(s.engine.calls)
    s.clock[0] += 120
    def forbidden(*args, **kwargs):
        pytest.fail("Unchanged end must not create/re-sign a new body batch")
    with monkeypatch.context() as scoped:
        scoped.setattr(TaskPreimageStore, "writer", forbidden)
        assert s.service.finish(s.root, s.ref)["status"] == "READY"
    assert s.service.load(s.root, s.ref)["end"] == end
    assert _get(s, end) == end[END_CONTEXT_FIELD] and len(s.engine.calls) == calls
    _preserved(s)


def test_new_end_supersedes_exact_getter_but_never_aliases_old_body(tmp_path):
    s = _new(tmp_path)
    first = _finish(s)
    frozen = copy.deepcopy(first[END_CONTEXT_FIELD])
    second = _finish(s, "end_two = 2\n")
    assert first["version_ref"] != second["version_ref"]
    with _error("SUPERSEDED"):
        _get(s, first)
    assert _get(s, second) == second[END_CONTEXT_FIELD]
    assert first[END_CONTEXT_FIELD] == frozen
    with pytest.raises(TaskPreimageUnavailable) as error:
        _original(s, first)
    assert error.value.reason_code == "TASK_PREIMAGE_SOURCE_UNAVAILABLE"
    assert _original(s, second) == ["end_two = 2"]
    _preserved(s)


def test_flag_off_new_version_is_honestly_unavailable_and_does_not_reuse_old_context(tmp_path):
    s = _new(tmp_path)
    first = _finish(s)
    s.service.frozen_body_contexts = False
    second = _finish(s, "flag_off = 2\n")
    assert END_CONTEXT_FIELD not in second
    with _error("SUPERSEDED"):
        _get(s, first)
    with _error("UNAVAILABLE"):
        _get(s, second)
    _preserved(s)


def test_missing_baseline_profile_does_not_adopt_context_on_a_new_end(tmp_path):
    s = _new(tmp_path, baseline=False)
    s.service.frozen_body_contexts = True
    end = _finish(s)
    assert END_CONTEXT_FIELD not in end
    with _error("UNAVAILABLE"):
        _get(s, end)
    _preserved(s)


def test_old_unchanged_version_never_backfills_context_but_fresh_capture_can_publish(tmp_path):
    s = _new(tmp_path)
    s.service.frozen_body_contexts = False
    old = _finish(s)
    s.service.frozen_body_contexts = True
    assert s.service.finish(s.root, s.ref)["status"] == "READY"
    assert s.service.load(s.root, s.ref)["end"] == old and END_CONTEXT_FIELD not in old
    with _error("UNAVAILABLE"):
        _get(s, old)
    fresh = _finish(s, "fresh_new_capture = 2\n")
    assert _get(s, fresh) == fresh[END_CONTEXT_FIELD]
    _preserved(s)


@pytest.mark.parametrize("wrong", ["owner", "source"])
def test_getter_exact_scope_is_read_only_without_hydration(tmp_path, monkeypatch, wrong):
    s = _new(tmp_path)
    end = _finish(s)
    directory = s.state.path.parent
    directory.chmod(0o755)
    s.state.path.chmod(0o644)
    (directory / "snapshot.key").chmod(0o644)
    before = _private_files(directory)
    kwargs = (dict(owner=session_owner("codex", "foreign-end")) if wrong == "owner"
              else dict(expected_source="f" * 64))
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        packet = _get(s, end)
        packet["payload"]["source"] = "0" * 64
        assert _get(s, end) == end[END_CONTEXT_FIELD]
        with _error("OWNER_MISMATCH" if wrong == "owner" else "SOURCE_MISMATCH"):
            _get(s, end, **kwargs)
    assert _private_files(directory) == before
    _preserved(s)


@pytest.mark.parametrize("damage", ["context", "remove", "source"])
def test_same_version_context_or_canonical_source_cannot_change_in_task_cas(tmp_path, damage):
    s = _new(tmp_path)
    _finish(s)
    before = _row(s.state, s.ref)
    record = s.service.load(s.root, s.ref)
    if damage == "remove":
        record["end"].pop(END_CONTEXT_FIELD)
    elif damage == "context":
        record["end"][END_CONTEXT_FIELD]["payload"]["expires_at"] += 10
    else:
        record["end"]["hashes"]["module_0000.py"] = "e" * 64
    with pytest.raises(FrozenEndBodyContextUnavailable):
        s.service.store(s.root).save(record)
    assert _row(s.state, s.ref) == before
    _preserved(s)


def test_stale_task_generation_keeps_original_end_context_and_nonzero_ledger(tmp_path):
    s = _new(tmp_path)
    end = _finish(s)
    stale = s.service.load(s.root, s.ref)
    s.service.store(s.root).save(stale)
    committed = _row(s.state, s.ref)
    with pytest.raises(ValueError, match="changed concurrently"):
        s.service.store(s.root).save(stale)
    assert _row(s.state, s.ref) == committed and _get(s, end) == end[END_CONTEXT_FIELD]
    _preserved(s)


def test_real_sql_failure_keeps_old_end_and_cleans_unpublished_new_stage(tmp_path, monkeypatch):
    s = _new(tmp_path)
    first = _finish(s)
    from security_runtime.tasks import end_versions
    committed, attempted, connect = _row(s.state, s.ref), [], sqlite3.connect
    capture, originals = end_versions.capture_end, []
    def observed_capture(*args, **kwargs):
        end, staged = capture(*args, **kwargs)
        originals.append(copy.deepcopy(end))
        return end, staged
    class RejectNewEnd(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("INSERT OR REPLACE INTO security_tasks"):
                draft = json.loads(parameters[4])
                if draft.get("end", {}).get("version_ref") != first["version_ref"]:
                    attempted.append(draft["end"])
                    super().execute("CREATE TEMP TRIGGER refuse_new_end BEFORE INSERT ON main.security_tasks "
                        "BEGIN SELECT RAISE(ABORT, 'real-end-publication-failure'); END")
            return super().execute(sql, parameters)
    def failing(database, *args, **kwargs):
        if str(database) == str(s.state.path) and not kwargs.get("uri"):
            kwargs["factory"] = RejectNewEnd
        return connect(database, *args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, "connect", failing)
        scoped.setattr(end_versions, "capture_end", observed_capture)
        with pytest.raises(sqlite3.IntegrityError, match="real-end-publication-failure"):
            _finish(s, "rejected_end = 2\n")
    assert len(attempted) == 1 and _row(s.state, s.ref) == committed
    assert len(originals) == 1 and originals[0]["version_ref"] == attempted[0]["version_ref"]
    assert _get(s, first) == first[END_CONTEXT_FIELD] and _original(s, first) == ["end_one = 1"]
    with _error("SUPERSEDED"):
        _get(s, attempted[0])
    with pytest.raises(TaskPreimageUnavailable):
        _original(s, originals[0])
    _preserved(s)


@pytest.mark.parametrize("damage", ["giant", "bad-mac"])
def test_getter_rejects_damaged_actual_sql_head_with_bounded_python_memory(tmp_path, monkeypatch, damage):
    s = _new(tmp_path)
    end = _finish(s)
    with closing(sqlite3.connect(s.state.path)) as db, db:
        if damage == "giant":
            db.execute("UPDATE security_tasks SET data=CAST(zeroblob(?) AS TEXT) WHERE ref=?",
                (MAX_RECORD_BYTES * 4, s.ref))
        else:
            stored = json.loads(_row(s.state, s.ref)[0])
            stored["end"][END_CONTEXT_FIELD]["mac"] = "0" * 64
            db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
                (encode(stored).decode(), digest(s.state.key(), stored), s.ref))
    before = _private_files(s.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        tracemalloc.start()
        try:
            with _error("STATE_UNAVAILABLE" if damage == "giant" else "INVALID"):
                _get(s, end)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert peak < 2_000_000 and _private_files(s.state.path.parent) == before
    _assert_old_unchanged(s)


@pytest.mark.parametrize("target", ["task", "activity"])
def test_getter_wal_header_refuses_without_allocating_sidecars(tmp_path, monkeypatch, target):
    s = _new(tmp_path)
    end = _finish(s)
    path = s.state.path if target == "task" else ActivityStore(s.state.hooks, s.root).path
    with closing(sqlite3.connect(path)) as db, db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    assert path.read_bytes()[18:20] == b"\x02\x02"
    assert not path.with_name(path.name + "-wal").exists()
    before = _private_files(s.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with _error("STATE_UNAVAILABLE"):
            _get(s, end)
    assert _private_files(s.state.path.parent) == before


def test_shared_head_reader_keeps_legacy_baseline_malformed_state_error_read_only(tmp_path):
    s = _new(tmp_path)
    stored = json.loads(_row(s.state, s.ref)[0])
    stored["baseline"] = []
    with closing(sqlite3.connect(s.state.path)) as db, db:
        db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
            (encode(stored).decode(), digest(s.state.key(), stored), s.ref))
    before = _private_files(s.state.path.parent)
    with pytest.raises(FrozenBodyContextUnavailable, match="^FROZEN_BODY_CONTEXT_STATE_UNAVAILABLE$"):
        s.service.store(s.root).get_frozen_body_context(s.ref, owner=s.owner)
    assert _private_files(s.state.path.parent) == before
    _assert_old_unchanged(s)


def test_queue_carries_original_end_context_but_pending_is_not_current_task(tmp_path, monkeypatch):
    s = _new(tmp_path)
    (s.root / "module_0000.py").write_text("queued_end = 1\n")
    enqueue(s.service, s.root, s.ref, launch=False)
    queue = CloseoutQueue(s.state.hooks, s.root, now=lambda: s.clock[0])
    claim = queue.read(s.ref)
    end = claim["end"]
    assert END_CONTEXT_FIELD in end and claim["state"] == "QUEUED"
    with _error("UNAVAILABLE"):
        _get(s, end)
    real, seen = s.service._finish, []
    def observed(*args, **kwargs):
        seen.append(copy.deepcopy(kwargs["end"][END_CONTEXT_FIELD]))
        return real(*args, **kwargs)
    monkeypatch.setattr(s.service, "_finish", observed)
    assert execute_one(s.service, s.root, s.ref)
    assert queue.read(s.ref)["state"] == "READY_FOR_REVIEW"
    assert seen == [end[END_CONTEXT_FIELD]] and _get(s, end) == end[END_CONTEXT_FIELD]
    assert _original(s, end) == ["queued_end = 1"]
    _preserved(s)


def test_queue_dedup_and_cancel_never_publish_a_pending_context(tmp_path, monkeypatch):
    s = _new(tmp_path)
    (s.root / "module_0000.py").write_text("pending_end = 1\n")
    first = enqueue(s.service, s.root, s.ref, launch=False)
    queue = CloseoutQueue(s.state.hooks, s.root, now=lambda: s.clock[0])
    row = queue.read(s.ref)
    def no_capture(*args):
        pytest.fail("Pending queue dedup must not recapture or resign its end")
    monkeypatch.setattr("security_runtime.tasks.queued_closeout.capture_end", no_capture)
    assert enqueue(s.service, s.root, s.ref, launch=False)["job_ref"] == first["job_ref"]
    assert queue.read(s.ref)["end"] == row["end"]
    cancel(s.service, s.root, s.ref)
    assert not execute_one(s.service, s.root, s.ref)
    with _error("UNAVAILABLE"):
        _get(s, row["end"])
    assert s.engine.calls == []
    _preserved(s)


def test_late_finish_cleanup_cannot_delete_the_newer_current_end(tmp_path, monkeypatch):
    s = _new(tmp_path)
    published, release = threading.Event(), threading.Event()
    real = s.service._finish
    def paused(*args, **kwargs):
        result = real(*args, **kwargs)
        if not published.is_set():
            published.set()
            assert release.wait(15), "Second finish did not release the first cleanup"
        return result
    monkeypatch.setattr(s.service, "_finish", paused)
    (s.root / "module_0000.py").write_text("first_interleaved_end = 1\n")
    with ThreadPoolExecutor(max_workers=1) as worker:
        first = worker.submit(s.service.finish, s.root, s.ref)
        try:
            assert published.wait(15), "First finish did not commit its original end"
            earlier = s.service.load(s.root, s.ref)["end"]
            later = _finish(s, "second_interleaved_end = 2\n")
        finally:
            release.set()
        assert first.result(timeout=15)["status"] == "READY"
    with _error("SUPERSEDED"):
        _get(s, earlier)
    assert _get(s, later) == later[END_CONTEXT_FIELD]
    assert _original(s, later) == ["second_interleaved_end = 2"]
    _preserved(s)


def test_late_enqueue_cleanup_preserves_end_published_by_its_original_worker(tmp_path, monkeypatch):
    from security_runtime.tasks import end_versions

    s = _new(tmp_path)
    blocked, release = threading.Event(), threading.Event()
    target, decisions = [], []
    deciding = threading.Event()
    cleanup = end_versions.discard_unreferenced
    real_head = TaskSecurityStore._frozen_body_record
    real_read = CloseoutQueue.read
    def gated_cleanup(*args, **kwargs):
        observing = target and threading.get_ident() == target[0]
        if observing:
            blocked.set()  # Before the actual helper acquires the workspace lock.
            assert release.wait(15), "Original enqueue cleanup was not released"
            deciding.set()
        try:
            return cleanup(*args, **kwargs)
        finally:
            if observing:
                deciding.clear()
    def observed_head(store, *args, **kwargs):
        value = real_head(store, *args, **kwargs)
        if deciding.is_set() and threading.get_ident() == target[0]:
            decisions.append(("task", value["end"]["version_ref"]))
        return value
    def observed_queue(queue, *args, **kwargs):
        value = real_read(queue, *args, **kwargs)
        if deciding.is_set() and threading.get_ident() == target[0]:
            decisions.append(("queue", value["end"]["version_ref"]))
        return value
    def first_enqueue():
        target.append(threading.get_ident())
        return enqueue(s.service, s.root, s.ref, launch=False)
    monkeypatch.setattr(end_versions, "discard_unreferenced", gated_cleanup)
    monkeypatch.setattr(TaskSecurityStore, "_frozen_body_record", observed_head)
    monkeypatch.setattr(CloseoutQueue, "read", observed_queue)
    (s.root / "module_0000.py").write_text("queued_original_end = 1\n")
    with ThreadPoolExecutor(max_workers=1) as worker:
        pending = worker.submit(first_enqueue)
        try:
            assert blocked.wait(15), "First enqueue did not reach its real finally"
            queue = CloseoutQueue(s.state.hooks, s.root, now=lambda: s.clock[0])
            first = queue.read(s.ref)["end"]
            assert execute_one(s.service, s.root, s.ref)
            assert queue.read(s.ref)["state"] == "READY_FOR_REVIEW"
            assert _get(s, first) == first[END_CONTEXT_FIELD]
            assert _original(s, first) == ["queued_original_end = 1"]
            (s.root / "module_0000.py").write_text("queued_replacement_end = 2\n")
            enqueue(s.service, s.root, s.ref, launch=False)
            second = queue.read(s.ref)["end"]
            assert second["version_ref"] != first["version_ref"]
            assert s.service.load(s.root, s.ref)["end"]["version_ref"] == first["version_ref"]
        finally:
            release.set()
        pending.result(timeout=15)
    assert decisions == [("task", first["version_ref"]), ("queue", second["version_ref"])]
    assert _get(s, first) == first[END_CONTEXT_FIELD]
    assert _original(s, first) == ["queued_original_end = 1"]
    _preserved(s)


def test_foreground_superseded_end_remains_readable_while_real_pending_queue_references_it(tmp_path):
    s = _new(tmp_path)
    first = _finish(s)
    enqueue(s.service, s.root, s.ref, launch=False)  # Real unchanged end becomes a queue root.
    queue = CloseoutQueue(s.state.hooks, s.root, now=lambda: s.clock[0])
    assert queue.read(s.ref)["end"]["version_ref"] == first["version_ref"]
    second = _finish(s, "new_foreground_end = 2\n")
    pending = queue.read(s.ref)
    assert pending["state"] == "QUEUED" and pending["end"]["version_ref"] == first["version_ref"]
    with _error("SUPERSEDED"):
        _get(s, first)
    assert _get(s, second) == second[END_CONTEXT_FIELD]
    assert _original(s, first) == ["end_one = 1"]
    assert _original(s, second) == ["new_foreground_end = 2"]
    _preserved(s)


@pytest.mark.skipif(os.name == "nt", reason="Actual POSIX directory flock")
def test_cleanup_real_admission_lock_failure_keeps_stage_then_retries_after_release(tmp_path):
    from security_runtime.tasks.end_versions import capture_end, discard_unreferenced

    s = _new(tmp_path)
    first = _finish(s)
    (s.root / "module_0000.py").write_text("unpublished_stage = 2\n")
    stage, ref = capture_end(s.service, s.root, s.service.load(s.root, s.ref))
    assert ref == stage["version_ref"] != first["version_ref"]
    with _directory_flock(s.state.path.parent):
        discard_unreferenced(s.service, s.root, s.ref, ref)
    assert _original(s, stage) == ["unpublished_stage = 2"]
    assert _get(s, first) == first[END_CONTEXT_FIELD]
    discard_unreferenced(s.service, s.root, s.ref, ref)
    with pytest.raises(TaskPreimageUnavailable):
        _original(s, stage)
    assert _original(s, first) == ["end_one = 1"]
    _preserved(s)
