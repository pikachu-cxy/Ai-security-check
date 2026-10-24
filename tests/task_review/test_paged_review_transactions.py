"""Independent new-head transactions against real SQLite and sealed sources.

All heads and owner inputs are isolated test fixtures, not native host claims.
No coordinator, Runtime task, scanner or installation is invoked.
"""
from concurrent.futures import ThreadPoolExecutor
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataError, ReviewMetadataStore,
)
import security_runtime.task_review.metadata_store as metadata_store
from security_runtime.task_review.paged_task_store import CONTRACT, PagedReviewTaskStore
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY
import security_runtime.tasks.security_state as security_state
from paged_review_source_helpers import pack_review_sources
from test_review_metadata_compatibility import KEY, OWNER, _encoded, _legacy_fixture, _task_row


LIMITS = dict(source_bytes=100, navigation_bytes=0, control_bytes=0,
              total_bytes=100, reads=100)
CHARGE = dict(source_bytes=1, navigation_bytes=0, control_bytes=0,
              total_bytes=1, reads=1)


def _snapshot(label):
    return dict(hashes={"source.py": hashlib.sha256(label.encode()).hexdigest()},
                texts={"source.py": [label]}, inventory=["source.py"],
                read_priority=["source.py"], preimages={}, line_counts={"source.py": 1},
                text_truncations={}, text_unavailable={}, limitations=[],
                read_limitations=[], inventory_complete=True, redaction_version=3)


def _sample(tmp_path, *, capacity=False):
    state, root, legacy = _legacy_fixture(tmp_path, capacity=capacity)
    binding = ReviewMetadataBinding("ts1-" + "b" * 32, dict(OWNER), 1, "e" * 64, 3)
    template = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                    task_ref=binding.task_ref, task_owner=dict(OWNER),
                    baseline=_snapshot("original = 1"), end=_snapshot("updated = 2"))
    sources = pack_review_sources(state, template)
    return SimpleNamespace(state=state, root=root, legacy=legacy, binding=binding,
                           template=template, sources=sources, store=PagedReviewTaskStore(state),
                           old_row=_task_row(state, legacy["task_ref"]),
                           old_ledger=_encoded(state.get(legacy["task_ref"])["review_ledger"]))


@pytest.fixture
def sample(tmp_path):
    return _sample(tmp_path)


def _create(sample, *, limits=None, request_id="create-head"):
    return sample.store.create(sample.binding, task_key="internal-" + sample.binding.task_ref,
        baseline=sample.sources["baseline"], end=sample.sources["end"],
        limits=dict(LIMITS if limits is None else limits), request_id=request_id)


def _head(sample):
    return sample.store.get(sample.binding.task_ref, dict(OWNER))


def _mutate(sample, mutation, request_id, *, head=None, charge=None, current=None, binding=None):
    head = _head(sample) if head is None else head
    return (current or sample.store).mutate(binding or sample.binding, mutation,
        expected_generation=head["generation"],
        expected_metadata_generation=head["metadata_generation"],
        request_id=request_id, charge=charge)


def _plan(sample, *, limits=None):
    _create(sample, limits=limits)
    receipt = _mutate(sample, dict(kind="create", name="plan"), "create-plan")
    assert receipt["metadata"]["state"] == "STAGING"
    return receipt["metadata"]["ref"]


def _metadata(sample):
    return ReviewMetadataStore(sample.state.path, workspace_root=sample.root, key=KEY)


def _sql_state(sample):
    """Small raw row snapshot of all control tables, including legacy heads."""
    with sqlite3.connect(sample.state.path) as db:
        tables = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        assert all(name.replace("_", "").isalnum() for name in tables)
        return {table: db.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall()
                for table in tables}


def _assert_legacy_unchanged(sample):
    assert _task_row(sample.state, sample.legacy["task_ref"]) == sample.old_row
    assert _encoded(sample.state.get(sample.legacy["task_ref"])["review_ledger"]) == sample.old_ledger


def test_new_head_and_metadata_publish_in_one_real_commit_and_reopen(sample, monkeypatch):
    initial = _create(sample)
    head = _head(sample)
    assert head["contract"] == CONTRACT
    assert head["generation"] == head["metadata_generation"] == 1
    assert initial["head_generation"] == 1
    assert len(_encoded(head)) <= 32_768
    for field in ("baseline", "end"):
        assert head[field]["paged_entries"] == sample.sources[field]["paged_entries"]
    created = _mutate(sample, dict(kind="create", name="plan"), "create-plan")
    ref, previous = created["metadata"]["ref"], _head(sample)
    connect, commits = sqlite3.connect, []

    class CommitConnection(sqlite3.Connection):
        def commit(self):
            if self.total_changes:
                raw = self.execute("SELECT data FROM security_tasks WHERE ref=?",
                                   (sample.binding.task_ref,)).fetchone()[0]
                pending_head = json.loads(raw)
                ledger_generation = self.execute("SELECT generation FROM rm_ledgers WHERE task_ref=?",
                                                  (sample.binding.task_ref,)).fetchone()[0]
                receipt_count = self.execute("SELECT count(*) FROM rm_receipts WHERE task_ref=? AND request_id=?",
                    (sample.binding.task_ref, "append-once")).fetchone()[0]
                commits.append((pending_head["generation"], pending_head["metadata_generation"],
                                ledger_generation, receipt_count))
            return super().commit()

    def tracked_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=CommitConnection))

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata_store.sqlite3, "connect", tracked_connect)
        appended = _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}, {"value": 2}]),
                           "append-once", head=previous, charge=dict(CHARGE))
    assert commits == [(previous["generation"] + 1, previous["metadata_generation"] + 1,
                        previous["metadata_generation"] + 1, 1)]
    reopened = PagedReviewTaskStore(sample.state)
    current = reopened.get(sample.binding.task_ref, dict(OWNER))
    assert current["generation"] == appended["head_generation"] == previous["generation"] + 1
    assert current["metadata_generation"] == previous["metadata_generation"] + 1
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE
    sealed = _mutate(sample, dict(kind="seal", ref=ref, expected_items=2), "seal-plan")
    assert sealed["metadata"]["state"] == "SEALED"
    assert _metadata(sample).page(ref, sample.binding)["items"] == [{"value": 1}, {"value": 2}]
    _assert_legacy_unchanged(sample)


@pytest.mark.parametrize("stale", ["generation", "metadata_generation"])
def test_each_generation_is_an_independent_cas_fence(sample, stale):
    ref = _plan(sample)
    old = _head(sample)
    proposed = dict(old, **{stale: old[stale] - 1})
    before = _sql_state(sample)
    with pytest.raises(ReviewMetadataError) as conflict:
        _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                "stale-half", head=proposed, charge=dict(CHARGE))
    assert conflict.value.reason_code == "REVIEW_METADATA_CAS_CONFLICT"
    assert _sql_state(sample) == before
    assert _head(sample) == old
    _assert_legacy_unchanged(sample)


def test_original_request_replays_both_generations_and_cannot_change_payload(sample):
    ref = _plan(sample)
    old = _head(sample)
    mutation = dict(kind="append", ref=ref, items=[{"value": 1}])
    first = _mutate(sample, mutation, "original-request", head=old, charge=dict(CHARGE))
    before = _sql_state(sample)
    assert _mutate(sample, mutation, "original-request", head=old, charge=dict(CHARGE)) == first
    with pytest.raises(ReviewMetadataError) as conflict:
        _mutate(sample, dict(mutation, items=[{"value": 2}]), "original-request",
                head=old, charge=dict(CHARGE))
    assert conflict.value.reason_code == "REVIEW_METADATA_IDEMPOTENCY_CONFLICT"
    assert _sql_state(sample) == before
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE


def test_same_request_from_competing_connections_publishes_only_one_head_and_charge(sample):
    ref = _plan(sample)
    old, gate = _head(sample), threading.Barrier(2)

    def append():
        current = PagedReviewTaskStore(sample.state)
        gate.wait(timeout=10)
        return _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                       "same-request", head=old, charge=dict(CHARGE), current=current)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: append(), range(2)))
    assert results[0] == results[1]
    assert _head(sample)["generation"] == old["generation"] + 1
    assert _head(sample)["metadata_generation"] == old["metadata_generation"] + 1
    assert _metadata(sample).manifest(ref, sample.binding)["item_count"] == 1
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE
    _assert_legacy_unchanged(sample)


def test_competing_requests_cannot_spend_the_last_allowance_or_publish_half_a_head(sample):
    ref = _plan(sample, limits=dict(LIMITS, source_bytes=1, total_bytes=1, reads=1))
    old, gate = _head(sample), threading.Barrier(2)

    def append(index):
        current, expected = PagedReviewTaskStore(sample.state), old
        gate.wait(timeout=10)
        for _ in range(4):
            try:
                _mutate(sample, dict(kind="append", ref=ref, items=[{"value": index}]),
                        f"competing-{index}", head=expected, charge=dict(CHARGE), current=current)
                return "COMMITTED"
            except ReviewMetadataError as error:
                if error.reason_code == "REVIEW_METADATA_CAS_CONFLICT":
                    expected = current.get(sample.binding.task_ref, dict(OWNER))
                    continue
                assert error.reason_code == "REVIEW_METADATA_WAITING_CAPACITY"
                return error.reason_code
        pytest.fail("The bounded concurrent mutation did not resolve")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(append, [1, 2]))
    assert sorted(results) == ["COMMITTED", "REVIEW_METADATA_WAITING_CAPACITY"]
    assert _head(sample)["generation"] == old["generation"] + 1
    assert _head(sample)["metadata_generation"] == old["metadata_generation"] + 1
    assert _metadata(sample).manifest(ref, sample.binding)["item_count"] == 1
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE


@pytest.mark.parametrize("table", ["rm_pages", "rm_ledgers", "rm_receipts", "security_tasks"])
def test_actual_sql_error_after_dml_rolls_back_head_pages_receipt_charge_and_generations(sample, monkeypatch, table):
    ref, connect = _plan(sample), sqlite3.connect
    old, before, injected = _head(sample), _sql_state(sample), []

    class FaultConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            result = super().execute(sql, parameters)
            statement = sql.lstrip().upper()
            if not injected and table.upper() in statement and statement.startswith(("INSERT", "UPDATE")):
                injected.append(True)
                # Execute a genuinely invalid SQLite statement after the real
                # targeted mutation, rather than mocking a final API result.
                super().execute("INSERT INTO isolated_missing_fault_table VALUES(1)")
            return result

    def faulty_connect(*args, **kwargs):
        return connect(*args, **dict(kwargs, factory=FaultConnection))

    with monkeypatch.context() as scoped:
        scoped.setattr(metadata_store.sqlite3, "connect", faulty_connect)
        with pytest.raises(ReviewMetadataError) as failure:
            _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                    "faulted-append", head=old, charge=dict(CHARGE))
    assert injected, "The real requested write boundary was never reached"
    assert failure.value.reason_code == "REVIEW_METADATA_HISTORY_UNAVAILABLE"
    assert _sql_state(sample) == before
    assert PagedReviewTaskStore(sample.state).get(sample.binding.task_ref, dict(OWNER)) == old
    retried = _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                      "faulted-append", head=old, charge=dict(CHARGE))
    assert retried["head_generation"] == old["generation"] + 1
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE
    _assert_legacy_unchanged(sample)


@pytest.mark.parametrize("field", ["owner", "revision", "snapshot_id"])
def test_foreign_owner_or_original_snapshot_cannot_mutate_existing_head(sample, field):
    ref = _plan(sample)
    old, before = _head(sample), _sql_state(sample)
    replacements = dict(owner=dict(host="codex", session="d" * 64), revision=2, snapshot_id="f" * 64)
    foreign = replace(sample.binding, **{field: replacements[field]})
    with pytest.raises(ReviewMetadataError):
        _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                "foreign-append", head=old, binding=foreign, charge=dict(CHARGE))
    if field == "owner":
        with pytest.raises(ReviewMetadataError):
            sample.store.get(sample.binding.task_ref, foreign.owner)
    assert _sql_state(sample) == before
    _assert_legacy_unchanged(sample)


def test_another_root_cannot_rebind_the_original_shared_database(sample):
    _plan(sample)
    before = _sql_state(sample)
    other = sample.root.with_name("another-source")
    other.mkdir()
    wrong = copy.copy(sample.state)
    wrong.root = other  # Keep the original DB path, so this tests a real binding.
    with pytest.raises(ReviewMetadataError):
        PagedReviewTaskStore(wrong).get(sample.binding.task_ref, dict(OWNER))
    assert _sql_state(sample) == before
    _assert_legacy_unchanged(sample)


def test_new_head_success_and_failed_cas_keep_real_legacy_capacity_record_unchanged(tmp_path):
    sample = _sample(tmp_path, capacity=True)
    ref = _plan(sample)
    old = _head(sample)
    _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
            "new-work", head=old, charge=dict(CHARGE))
    with pytest.raises(ReviewMetadataError) as stale:
        _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 2}]),
                "stale-new-work", head=old, charge=dict(CHARGE))
    assert stale.value.reason_code == "REVIEW_METADATA_CAS_CONFLICT"
    _assert_legacy_unchanged(sample)
    legacy = sample.state.get(sample.legacy["task_ref"])
    assert legacy["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    assert legacy["review_ledger"]["total_bytes"] > 0


CHILD = r'''
import json, os, sqlite3, sys
from pathlib import Path
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import PagedReviewTaskStore
import security_runtime.task_review.metadata_store as metadata_store
hooks, root, encoded_binding, ref, generation, metadata_generation, phase = sys.argv[1:]
state = TaskSecurityStore(HookStateStore(Path(hooks)), Path(root), now=lambda: 100.0)
binding = ReviewMetadataBinding(**json.loads(encoded_binding))
connect, changed = sqlite3.connect, []
class CrashConnection(sqlite3.Connection):
    def execute(self, sql, parameters=()):
        result = super().execute(sql, parameters)
        statement = sql.lstrip().upper()
        if statement.startswith(('INSERT', 'UPDATE')) and 'RM_PAGES' in statement:
            changed.append(True)
            if phase == 'page':
                os._exit(31)
        if statement.startswith(('INSERT', 'UPDATE')) and 'SECURITY_TASKS' in statement and phase == 'head':
            os._exit(32)
        if statement.strip() == 'COMMIT' and changed and phase == 'after':
            os._exit(33)
        return result
    def commit(self):
        result = super().commit()
        if changed and phase == 'after':
            os._exit(33)
        return result
    def __exit__(self, kind, error, trace):
        result = super().__exit__(kind, error, trace)
        if kind is None and changed and phase == 'after':
            os._exit(33)
        return result
def tracked_connect(*args, **kwargs):
    return connect(*args, **dict(kwargs, factory=CrashConnection))
metadata_store.sqlite3.connect = tracked_connect
result = PagedReviewTaskStore(state).mutate(binding,
    dict(kind='append',ref=ref,items=[dict(value=1)]),
    expected_generation=int(generation),expected_metadata_generation=int(metadata_generation),
    request_id='crashing-append',
    charge=dict(source_bytes=1,navigation_bytes=0,control_bytes=0,total_bytes=1,reads=1))
print(json.dumps(result),flush=True)
'''


def _child_environment():
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    source = str(Path(__file__).resolve().parents[2] / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    return environment


@pytest.mark.parametrize("phase,exit_code", [("page", 31), ("head", 32), ("after", 33)])
def test_process_exit_at_real_write_or_commit_keeps_head_and_metadata_atomic(sample, phase, exit_code):
    ref = _plan(sample)
    old, before = _head(sample), _sql_state(sample)
    binding = dict(task_ref=sample.binding.task_ref, owner=sample.binding.owner,
                   revision=sample.binding.revision, snapshot_id=sample.binding.snapshot_id,
                   representation_version=sample.binding.representation_version)
    child = subprocess.run([
        sys.executable, "-c", CHILD, str(sample.state.hooks.directory), str(sample.root),
        json.dumps(binding), ref, str(old["generation"]), str(old["metadata_generation"]), phase,
    ], cwd=sample.root.parent, env=_child_environment(), capture_output=True, text=True, timeout=20)
    assert child.returncode == exit_code, child.stderr
    if phase != "after":
        # An explicit idempotent writer may recover SQLite's hot journal.  Do
        # not require a read-only diagnostic to change the database on disk.
        _create(sample)
        assert _sql_state(sample) == before
        assert _head(sample) == old
    current = PagedReviewTaskStore(sample.state)
    committed = _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                        "crashing-append", head=old, current=current, charge=dict(CHARGE))
    assert committed["head_generation"] == old["generation"] + 1
    head = current.get(sample.binding.task_ref, dict(OWNER))
    assert head["metadata_generation"] == old["metadata_generation"] + 1
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE
    assert _metadata(sample).manifest(ref, sample.binding)["item_count"] == 1
    once = _sql_state(sample)
    assert _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
                   "crashing-append", head=old, current=current, charge=dict(CHARGE)) == committed
    assert _sql_state(sample) == once
    _assert_legacy_unchanged(sample)


def _other_sample(sample):
    other = copy.copy(sample)
    other.binding = replace(sample.binding, task_ref="ts1-" + "c" * 32)
    template = dict(sample.template, task_ref=other.binding.task_ref)
    other.sources = pack_review_sources(sample.state, template)
    return other


def _seed_history(sample, *, created=100.0):
    """Authenticated historical row; no legacy execution or migration."""
    value = copy.deepcopy(sample.legacy)
    value.update(task_ref="ts1-" + "d" * 32, task_key="historical-read-only",
                 phase="COMPLETE", review_protocol=1, created_at=created)
    for name in ("review_plan", "review_ledger", "review_capacity", "review_session"):
        value.pop(name, None)
    with sqlite3.connect(sample.state.path) as db:
        db.execute("INSERT INTO security_tasks VALUES(?,?,?,?,?,?)",
            (value["task_ref"], value["task_key"], value["phase"], created,
             encode(value).decode(), digest(KEY, value)))
    return value, _task_row(sample.state, value["task_ref"])


def test_v3_slots_reject_new_head_without_charging_and_do_not_block_original_receipt(sample, monkeypatch):
    monkeypatch.setattr(security_state, "MAX_V3_RECORDS", 2)
    monkeypatch.setattr(security_state, "MAX_HISTORY_RECORDS", 4)
    ref = _plan(sample)  # One existing signed v3 row plus this new head fills 2.
    _mutate(sample, dict(kind="append", ref=ref, items=[{"value": 1}]),
            "spend-original", charge=dict(CHARGE))
    other, before = _other_sample(sample), _sql_state(sample)
    with pytest.raises(ReviewMetadataError) as full:
        _create(other)
    assert full.value.reason_code == "REVIEW_METADATA_WAITING_CAPACITY"
    assert _sql_state(sample) == before
    # Replaying a real existing receipt is not a new admission or allowance.
    original = _create(sample)
    assert original["head_generation"] == 1
    assert _sql_state(sample) == before
    assert _metadata(sample).ledger(sample.binding)["spent"] == CHARGE
    _assert_legacy_unchanged(sample)


def test_authenticated_old_protocol_history_does_not_consume_v3_slots_or_unpack(sample, monkeypatch):
    history, row = _seed_history(sample)
    monkeypatch.setattr(security_state, "MAX_V3_RECORDS", 2)
    monkeypatch.setattr(security_state, "MAX_HISTORY_RECORDS", 4)
    with monkeypatch.context() as scoped:
        scoped.setattr(sample.state, "decode", lambda *args: pytest.fail("Admission must authenticate heads, not unpack snapshots"))
        created = _create(sample)
    assert created["head_generation"] == 1
    assert _task_row(sample.state, history["task_ref"]) == row
    _assert_legacy_unchanged(sample)


def test_total_history_slots_preserve_expired_records_instead_of_pruning_for_admission(sample, monkeypatch):
    history, row = _seed_history(sample, created=1.0)
    monkeypatch.setattr(security_state, "MAX_V3_RECORDS", 8)
    monkeypatch.setattr(security_state, "MAX_HISTORY_RECORDS", 2)
    monkeypatch.setattr(security_state, "TTL", 50)
    assert sample.state.expired(history)
    before = _task_row(sample.state, sample.legacy["task_ref"])
    with pytest.raises(ReviewMetadataError) as full:
        _create(sample)
    assert full.value.reason_code == "REVIEW_METADATA_WAITING_CAPACITY"
    assert _task_row(sample.state, history["task_ref"]) == row
    assert _task_row(sample.state, sample.legacy["task_ref"]) == before
    with sqlite3.connect(sample.state.path) as db:
        assert db.execute("SELECT count(*) FROM security_tasks").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM rm_ledgers WHERE task_ref=?",
                          (sample.binding.task_ref,)).fetchone()[0] == 0
    _assert_legacy_unchanged(sample)


def test_malformed_existing_header_is_typed_history_failure_and_not_an_available_slot(sample):
    _create(sample)  # Allocate the domain before testing mutation rollback.
    other = _other_sample(sample)
    with sqlite3.connect(sample.state.path) as db:
        db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
                   (encode([]).decode(), digest(KEY, []), sample.legacy["task_ref"]))
    before = _sql_state(sample)
    with pytest.raises(ReviewMetadataError) as invalid:
        _create(other)
    assert invalid.value.reason_code == "REVIEW_METADATA_HISTORY_UNAVAILABLE"
    assert _sql_state(sample) == before


def test_missing_fenced_head_cannot_admit_a_different_task_or_change_its_ledger(sample):
    _create(sample)
    with sqlite3.connect(sample.state.path) as db:
        db.execute("DELETE FROM security_tasks WHERE ref=?", (sample.binding.task_ref,))
        assert db.execute("SELECT count(*) FROM rm_head_fences WHERE task_ref=?",
                          (sample.binding.task_ref,)).fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM rm_ledgers WHERE task_ref=?",
                          (sample.binding.task_ref,)).fetchone()[0] == 1
    # Genuine independently sealed sources do not make an orphaned control
    # domain available for unrelated work or silently reconstruct its head.
    other = _other_sample(sample)
    before = _sql_state(sample)
    with pytest.raises(ReviewMetadataError) as missing:
        _create(other)
    assert missing.value.reason_code == "REVIEW_METADATA_HISTORY_UNAVAILABLE"
    assert _sql_state(sample) == before
    assert sample.binding.task_ref not in {
        row[0] for row in before["security_tasks"]}
    _assert_legacy_unchanged(sample)


LEGACY_PYTHON_ENV = "SECURITY_RUNTIME_REVIEW_LEGACY_PYTHON"
LEGACY_SHA256 = "0c7f2b7387cafebbff8548c79728575db4117a60e63207f52abb8d571403ac43"
LEGACY_CHILD = r'''
from pathlib import Path
import hashlib, json, sqlite3, sys
import security_runtime.task_review.metadata_store as old
python, root, database, encoded_binding, ref, generation, expected_sha = sys.argv[1:]
installation = Path(python).absolute().parents[2].resolve()
module_file = Path(old.__file__).resolve()
assert module_file.is_relative_to(installation), str(module_file)
source_sha = hashlib.sha256(module_file.read_bytes()).hexdigest()
assert source_sha == expected_sha, source_sha
with sqlite3.connect(database) as db:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'rm_%'")}
assert tables == set(old.TABLES) | {'rm_head_fences'}, tables
key = (Path(database).parent/'snapshot.key').read_bytes()
store = old.ReviewMetadataStore(Path(database),workspace_root=Path(root),key=key)
binding = old.ReviewMetadataBinding(**json.loads(encoded_binding))
try:
    store.append(ref,binding,[dict(value=9)],expected_generation=int(generation),
        request_id='actual-old-writer',
        charge=dict(source_bytes=1,navigation_bytes=0,control_bytes=0,total_bytes=1,reads=1))
except old.ReviewMetadataError as error:
    assert error.reason_code == 'REVIEW_METADATA_HISTORY_UNAVAILABLE', error.reason_code
    print(json.dumps(dict(module_file=str(module_file),source_sha256=source_sha,
                         reason=error.reason_code,extra_table='rm_head_fences')),flush=True)
else:
    raise AssertionError('The actual old writer accepted a head-bound domain')
'''


@pytest.mark.skipif(not os.getenv(LEGACY_PYTHON_ENV),
                    reason=f"Set {LEGACY_PYTHON_ENV} to the isolated installed 4409a3c interpreter")
def test_actual_installed_old_metadata_writer_rejects_new_head_domain_without_changing_rows(sample):
    python = Path(os.environ[LEGACY_PYTHON_ENV]).absolute()
    assert python.is_file()
    ref = _plan(sample)
    old, before = _head(sample), _sql_state(sample)
    binding = dict(task_ref=sample.binding.task_ref, owner=sample.binding.owner,
                   revision=sample.binding.revision, snapshot_id=sample.binding.snapshot_id,
                   representation_version=sample.binding.representation_version)
    child = subprocess.run([str(python), "-I", "-c", LEGACY_CHILD, str(python), str(sample.root),
        str(sample.state.path), json.dumps(binding), ref, str(old["metadata_generation"]), LEGACY_SHA256],
        cwd=sample.root.parent, capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert result["source_sha256"] == LEGACY_SHA256
    assert result["reason"] == "REVIEW_METADATA_HISTORY_UNAVAILABLE"
    assert _sql_state(sample) == before
    assert _head(sample) == old
    _assert_legacy_unchanged(sample)


LEGACY_TASK_CHILD = r'''
from pathlib import Path
import hashlib, json, sqlite3, sys
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security_state import TaskSecurityStore
import security_runtime.tasks.snapshot_gc as old_gc
import security_runtime.task_review.metadata_store as old_metadata
python, hooks, root, mode, encoded_record, expected_sha = sys.argv[1:]
installation = Path(python).absolute().parents[2].resolve()
for module in (old_gc, old_metadata):
    assert Path(module.__file__).resolve().is_relative_to(installation), module.__file__
assert hashlib.sha256(Path(old_metadata.__file__).read_bytes()).hexdigest() == expected_sha
state = TaskSecurityStore(HookStateStore(Path(hooks)), Path(root), now=lambda:100.0)
if mode == 'collect':
    result = old_gc.collect_pages(state)
    assert result['collected_captures'] == result['released_logical_bytes'] == 0, result
    print(json.dumps(dict(mode=mode,result=result,old_gc_module=old_gc.__file__)),flush=True)
elif mode == 'collect-rejected':
    try:
        old_gc.collect_pages(state)
    except ValueError as error:
        assert str(error) == 'Task state cannot be verified', str(error)
        print(json.dumps(dict(mode=mode,error=str(error))),flush=True)
    else:
        raise AssertionError('Actual old collector accepted a new-contract head')
elif mode == 'write':
    try:
        state.save(json.loads(encoded_record),new=True)
    except ValueError as error:
        assert str(error) == 'Task state cannot be verified', str(error)
        print(json.dumps(dict(mode=mode,error=str(error))),flush=True)
    else:
        raise AssertionError('Actual old task writer accepted a new-contract head')
else:
    raise AssertionError(mode)
'''


def _run_legacy_task(sample, mode, record=None):
    python = Path(os.environ[LEGACY_PYTHON_ENV]).absolute()
    assert python.is_file()
    child = subprocess.run([str(python), "-I", "-B", "-c", LEGACY_TASK_CHILD,
        str(python), str(sample.state.hooks.directory), str(sample.root), mode,
        json.dumps(record), LEGACY_SHA256], cwd=sample.root.parent,
        capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout)


@pytest.mark.skipif(not os.getenv(LEGACY_PYTHON_ENV),
                    reason=f"Set {LEGACY_PYTHON_ENV} to the isolated installed 4409a3c interpreter")
def test_actual_old_task_writer_rejects_new_contract_without_replacing_its_head(sample):
    _create(sample)
    old, before = _head(sample), _sql_state(sample)
    record = dict(sample.legacy, task_ref=sample.binding.task_ref, generation=0)
    assert _run_legacy_task(sample, "write", record)["error"] == "Task state cannot be verified"
    assert _sql_state(sample) == before
    assert _head(sample) == old
    _assert_legacy_unchanged(sample)


@pytest.mark.skipif(not os.getenv(LEGACY_PYTHON_ENV),
                    reason=f"Set {LEGACY_PYTHON_ENV} to the isolated installed 4409a3c interpreter")
@pytest.mark.parametrize("head_lost", [False, True])
def test_actual_old_gc_cannot_delete_new_domain_sources_with_or_without_task_head(sample, head_lost):
    from security_runtime.task_review.paged_task_store import SOURCE_RETENTION_DOMAIN, source_binding
    from security_runtime.tasks.snapshot_pages import _store

    _create(sample)
    head = _head(sample)
    store = _store(sample.state)
    bindings = {field: source_binding(sample.binding, field, head[field]["paged_entries"]["source"])
                for field in ("baseline", "end")}
    assert {binding.retention_domain for binding in bindings.values()} == {SOURCE_RETENTION_DOMAIN}
    assert SOURCE_RETENTION_DOMAIN != "TASK_PAGES_GC_V1"
    for field, binding in bindings.items():
        assert store.resume(head[field]["paged_entries"]["ref"], binding)["state"] == "SEALED"
    with sqlite3.connect(store.path) as db:
        before_pages = {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                        for table in ("captures", "entries", "objects", "usage")}
    with sqlite3.connect(sample.state.path) as db:
        if head_lost:
            db.execute("DELETE FROM security_tasks WHERE ref=?", (sample.binding.task_ref,))
        assert db.execute("SELECT count(*) FROM rm_head_fences WHERE task_ref=?",
                          (sample.binding.task_ref,)).fetchone()[0] == 1
    before_control = _sql_state(sample)
    if head_lost:
        result = _run_legacy_task(sample, "collect")["result"]
        assert result["collected_captures"] == result["released_logical_bytes"] == 0
        assert result["logical_bytes_after"] == result["logical_bytes_before"] > 0
    else:
        assert _run_legacy_task(sample, "collect-rejected")["error"] == "Task state cannot be verified"
    assert _sql_state(sample) == before_control
    with sqlite3.connect(store.path) as db:
        after_pages = {table: db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                       for table in before_pages}
    assert after_pages == before_pages
    for field, binding in bindings.items():
        assert store.resume(head[field]["paged_entries"]["ref"], binding)["state"] == "SEALED"
    _assert_legacy_unchanged(sample)
