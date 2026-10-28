"""Real opt-in baseline production and bounded context recovery.

Only ordinary owned closeout begin is exercised. Files, body seals, original
task CAS and old nonzero review accounting are real isolated stores. No MCP,
scanner, native-before proof, end producer or new-domain publisher is used.
"""
from __future__ import annotations

import copy
from contextlib import closing
import hashlib
import json
import sqlite3
import stat
import time
import tracemalloc
from types import SimpleNamespace

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.closeout_state import digest, encode, readonly_uri
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.activity import ActivityStore, POLICY, IDLE_TTL, HARD_TTL
from security_runtime.tasks.frozen_body_context import (
    CONTEXT_FIELD, MAX_CONTEXT_BYTES, PROFILE, FrozenBodyContextUnavailable,
    verify_context,
)
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import PAGED_CONTRACT
from security_runtime.tasks.preimages import TaskPreimageUnavailable
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import MAX_RECORD_BYTES, TaskSecurityStore
from security_runtime.tasks.snapshot_pages import LISTS, MAPS, _binding, _store
from test_review_metadata_compatibility import _legacy_fixture
from test_native_repair_intent import sample as native_intent_sample, ready as ready_native_intent


@pytest.fixture(autouse=True)
def isolated_optional_observations(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "isolated-observation-state"))
    # Optional postcommit observation is outside this producer transaction and
    # must not introduce a global DB writer into the SQL fault/readonly checks.
    monkeypatch.setattr("security_runtime.product_metrics.task_record_observed", lambda *a, **k: None)
    monkeypatch.setattr("security_runtime.observation.bind_product", lambda *a, **k: None)


class NoScanner:
    def __init__(self):
        self.calls = []

    def scan(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        pytest.fail("Baseline/context production must not run a scanner")


def _row(state, ref):
    with closing(sqlite3.connect(readonly_uri(state.path), uri=True)) as db:
        return db.execute("SELECT data,mac FROM security_tasks WHERE ref=?", (ref,)).fetchone()


def _private_files(directory):
    result = {}
    for path in [directory, *sorted(directory.rglob("*"))]:
        info = path.lstat()
        body = None
        if path.is_file():
            checksum = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    checksum.update(chunk)
            body = checksum.hexdigest()
        result[str(path.relative_to(directory))] = (
            stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_size, body)
    return result


def _canonical_source(snapshot):
    return hashlib.sha256(encode(dict(
        maps={name: snapshot.get(name, {}) for name in MAPS},
        lists={name: snapshot.get(name, []) for name in LISTS}))).hexdigest()


def _sample(tmp_path, *, count=3, enabled=True, name="producer"):
    state, root, old = _legacy_fixture(tmp_path, capacity=True)
    originals = {}
    for number in range(count):
        name_on_disk = f"module_{number:04d}.py"
        raw = f"original_value_{number} = {number}\n".encode()
        (root / name_on_disk).write_bytes(raw)
        originals[name_on_disk] = raw
    clock = [100.0]
    engine = NoScanner()
    owner = session_owner("codex", name)
    service = TaskSecurityService(engine, state.hooks, owner=owner,
        now=lambda: clock[0], frozen_body_contexts=enabled)
    old_row = _row(state, old["task_ref"])
    old_ledger = encode(state.get(old["task_ref"])["review_ledger"])
    assert json.loads(old_ledger)["total_bytes"] > 0
    assert old["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    return SimpleNamespace(state=state, root=root, old=old, old_row=old_row,
        old_ledger=old_ledger, originals=originals, clock=clock, engine=engine,
        owner=owner, service=service)


def _assert_old_unchanged(sample):
    assert _row(sample.state, sample.old["task_ref"]) == sample.old_row
    recovered = sample.state.get(sample.old["task_ref"])
    assert recovered["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    assert encode(recovered["review_ledger"]) == sample.old_ledger


def _begin(sample, key="real-baseline"):
    response = sample.service.begin(sample.root, key, check_policy=POLICY)
    assert response["task_ref"] != sample.old["task_ref"]
    assert response.get("scanner_run") is not True
    assert sample.engine.calls == []
    return response["task_ref"]


def _packet(sample, ref):
    return sample.service.store(sample.root).get_frozen_body_context(ref, owner=sample.owner)


def _assert_reason(error, suffix):
    assert error.value.reason_code == "FROZEN_BODY_CONTEXT_" + suffix


def _no_hydration(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Context recovery must not unpack snapshots or read live files")
    monkeypatch.setattr("security_runtime.tasks.snapshot_pages.unpack", forbidden)
    monkeypatch.setattr("security_runtime.local_evidence.WorkspaceReader.read", forbidden)


def test_1001_real_files_produce_one_original_sealed_baseline_context(tmp_path, record_testsuite_property):
    sample = _sample(tmp_path, count=1001)
    started = time.perf_counter()
    ref = _begin(sample)
    elapsed = time.perf_counter() - started
    record = sample.service.load(sample.root, ref)
    baseline = record["baseline"]
    assert baseline["inventory"] == sorted(sample.originals)
    assert len(baseline["hashes"]) == len(baseline["preimages"]) == 1001
    assert baseline["capture_stats"]["hash_complete"] is True
    assert baseline["capture_stats"]["body_complete"] is True
    assert record["frozen_body_profile"] == PROFILE
    packet = _packet(sample, ref)
    payload = verify_context(sample.state.hooks, sample.root, packet,
        task_ref=ref, owner=sample.owner, now=lambda: sample.clock[0])
    assert packet == baseline[CONTEXT_FIELD]
    assert len(encode(packet)) <= MAX_CONTEXT_BYTES
    assert payload["field"] == "baseline"
    assert payload["source"] == _canonical_source(baseline)
    assert payload["source"] == baseline["paged_entries"]["source"]
    assert payload["preimage_namespace"] == "closeout"
    assert payload["preimage_task_ref"] == ref
    assert payload["preimage_contract"] == PAGED_CONTRACT
    assert payload["created_at"] == record["created_at"] == 100.0
    assert payload["ttl_seconds"] == 30 * 86400
    assert payload["expires_at"] == 100.0 + 30 * 86400
    assert payload["consistency"] == "OBSERVED_ONLY"
    assert payload["representation_version"] == baseline["redaction_version"]
    assert payload["capture_completeness"] == {
        key: baseline["capture_stats"][key]
        for key in ("inventory_count_complete", "hash_complete", "body_requested", "body_complete")}
    info = sample.root.stat()
    assert payload["root_identity"] == [info.st_dev, info.st_ino]
    raw_store = _store(sample.state)
    binding = _binding(record, "baseline", payload["source"])
    assert binding.retention_domain == "TASK_PAGES_GC_V1"
    header = raw_store.resume(baseline["paged_entries"]["ref"], binding)
    assert header["state"] == "SEALED" and header["entry_count"] == 1001
    for name, original in sample.originals.items():
        reference = baseline["preimages"][name]
        assert baseline["hashes"][name] == hashlib.sha256(original).hexdigest()
        assert reference["raw_sha256"] == baseline["hashes"][name]
        assert reference["task_ref"] == ref
        assert reference["created_at"] == payload["created_at"]
        assert reference["expires_at"] == payload["expires_at"]
    bodies = sample.service.preimages(sample.root, record)
    for name in (min(sample.originals), max(sample.originals)):
        assert bodies.read(ref, name, baseline["hashes"][name], baseline["preimages"][name]) == [
            sample.originals[name].decode().rstrip("\n")]
    _assert_old_unchanged(sample)
    assert sample.engine.calls == []
    record_testsuite_property("producer_real_file_count", 1001)
    record_testsuite_property("producer_seconds", elapsed)
    record_testsuite_property("task_db_bytes", sample.state.path.stat().st_size)
    record_testsuite_property("source_db_bytes", raw_store.path.stat().st_size)


def test_reopened_getter_uses_exact_owner_without_hydration_or_private_writes(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    packet = _packet(sample, ref)
    # Explicitly relaxed legacy modes must not trigger a writer upgrade.
    directory = sample.state.path.parent
    directory.chmod(0o755)
    sample.state.path.chmod(0o644)
    (directory / "snapshot.key").chmod(0o644)
    before = _private_files(directory)
    reopened = TaskSecurityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        recovered = reopened.get_frozen_body_context(ref, owner=sample.owner)
        assert recovered == packet
        recovered["payload"]["source"] = "0" * 64
        assert reopened.get_frozen_body_context(ref, owner=sample.owner) == packet
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            reopened.get_frozen_body_context(ref, owner=session_owner("codex", "other-owner"))
        _assert_reason(error, "OWNER_MISMATCH")
    assert _private_files(directory) == before
    _assert_old_unchanged(sample)


def test_later_task_save_and_activity_keep_context_original_source_and_body_expiry(tmp_path):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    original = sample.service.load(sample.root, ref)
    packet = copy.deepcopy(_packet(sample, ref))
    reference = copy.deepcopy(original["baseline"]["preimages"]["module_0000.py"])
    sample.clock[0] += 120.0
    ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0]).record(
        sample.owner, event_id="later-real-activity", paths=("module_0000.py",))
    saved = sample.service.store(sample.root).save(original)
    assert saved["generation"] == original["generation"] + 1
    assert _packet(sample, ref) == packet
    assert saved["baseline"]["paged_entries"] == original["baseline"]["paged_entries"]
    assert saved["baseline"]["preimages"]["module_0000.py"] == reference
    assert packet["payload"]["expires_at"] == reference["expires_at"]
    assert sample.engine.calls == []
    _assert_old_unchanged(sample)


def test_actual_partial_capture_keeps_original_incomplete_counts_in_context(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    monkeypatch.setattr("security_runtime.tasks.security.MAX_READ_BYTES", 1)
    ref = _begin(sample)
    baseline = sample.service.load(sample.root, ref)["baseline"]
    assert baseline["capture_stats"]["hash_complete"] is False
    assert baseline["capture_stats"]["body_complete"] is False
    packet = _packet(sample, ref)
    payload = packet["payload"]
    assert payload["source"] == _canonical_source(baseline)
    assert payload["capture_completeness"] == {
        key: baseline["capture_stats"][key]
        for key in ("inventory_count_complete", "hash_complete", "body_requested", "body_complete")}
    assert payload["capture_completeness"]["body_complete"] is False
    assert not baseline["preimages"]
    _assert_old_unchanged(sample)


def test_normal_activity_uses_original_idle_expiry_without_legacy_reads_or_writes(tmp_path, monkeypatch):
    from security_runtime.tasks.lifecycle import expires_at

    sample = _sample(tmp_path)
    ref = _begin(sample)
    original = sample.service.load(sample.root, ref)
    packet = _packet(sample, ref)
    sample.clock[0] += 6 * 86400
    activity = ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    activity.record(sample.owner, event_id="actual-idle-extension", paths=("module_0000.py",))
    expected = expires_at(original, sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    assert expected == min(original["created_at"] + HARD_TTL, sample.clock[0] + IDLE_TTL)
    sample.clock[0] += 2 * 86400
    before = _private_files(sample.state.path.parent)

    def no_legacy_activity(*args, **kwargs):
        pytest.fail("Frozen context TTL must not use the legacy activity connection")

    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        scoped.setattr(ActivityStore, "read", no_legacy_activity)
        assert _packet(sample, ref) == packet
        sample.clock[0] = expected + 0.1
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            _packet(sample, ref)
        _assert_reason(error, "UNAVAILABLE")
    assert _private_files(sample.state.path.parent) == before
    assert packet["payload"]["expires_at"] == 100.0 + 30 * 86400
    _assert_old_unchanged(sample)


def test_existing_activity_wal_header_cannot_create_sidecars_on_context_read(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    activity = ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    with closing(sqlite3.connect(activity.path)) as db, db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
    assert activity.path.read_bytes()[18:20] == b"\x02\x02"
    assert not activity.path.with_name(activity.path.name + "-wal").exists()
    assert not activity.path.with_name(activity.path.name + "-shm").exists()
    before = _private_files(sample.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            _packet(sample, ref)
        _assert_reason(error, "STATE_UNAVAILABLE")
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("journal", ["rollback", "wal"])
def test_actual_activity_journal_or_wal_is_busy_without_recovery_or_mutation(tmp_path, monkeypatch, journal):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    packet = _packet(sample, ref)
    activity = ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    writer = sqlite3.connect(activity.path)
    try:
        if journal == "wal":
            assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
            sample.clock[0] += 1
            # Attach this live connection to the WAL by performing the real
            # signed write on it. A PRAGMA-only connection does not keep WAL
            # files alive after a separate writer closes its last handle.
            writer.execute("BEGIN IMMEDIATE")
            current = activity._get(writer, "task:" + ref)
            activity._put(writer, "task:" + ref, dict(current, last_activity=sample.clock[0]))
            writer.commit()
            assert activity.path.with_name(activity.path.name + "-wal").stat().st_size > 0
            assert activity.path.with_name(activity.path.name + "-shm").stat().st_size > 0
        else:
            writer.execute("BEGIN IMMEDIATE")
            current = activity._get(writer, "task:" + ref)
            activity._put(writer, "task:" + ref, dict(current, last_activity=sample.clock[0] + 1))
            assert activity.path.with_name(activity.path.name + "-journal").stat().st_size > 0
        before = _private_files(sample.state.path.parent)
        with monkeypatch.context() as scoped:
            _no_hydration(scoped)
            with pytest.raises(FrozenBodyContextUnavailable) as error:
                _packet(sample, ref)
            _assert_reason(error, "BUSY")
        assert _private_files(sample.state.path.parent) == before
    finally:
        writer.rollback()
        writer.close()
    if journal == "rollback":
        assert _packet(sample, ref) == packet
    _assert_old_unchanged(sample)


def test_missing_activity_database_uses_original_empty_summary_without_recreating_it(tmp_path):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    packet = _packet(sample, ref)
    activity = ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    retained = activity.path.with_name(activity.path.name + ".caller-retained")
    activity.path.rename(retained)
    try:
        before = _private_files(sample.state.path.parent)
        assert _packet(sample, ref) == packet
        assert not activity.path.exists()
        assert _private_files(sample.state.path.parent) == before
    finally:
        retained.rename(activity.path)
    _assert_old_unchanged(sample)


def test_missing_activity_schema_maps_real_sql_failure_without_writing(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    activity = ActivityStore(sample.state.hooks, sample.root, now=lambda: sample.clock[0])
    with closing(sqlite3.connect(activity.path)) as db, db:
        db.execute("DROP TABLE activity")
    before = _private_files(sample.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            _packet(sample, ref)
        _assert_reason(error, "STATE_UNAVAILABLE")
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


def test_stale_original_task_cas_cannot_publish_a_changed_context(tmp_path):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    original = sample.service.load(sample.root, ref)
    packet = copy.deepcopy(_packet(sample, ref))
    sample.service.store(sample.root).save(original)
    committed = _row(sample.state, ref)
    stale = copy.deepcopy(original)
    stale["limitations"].append({"reason": "STALE_CANDIDATE_MUST_NOT_COMMIT"})
    with pytest.raises(ValueError, match="changed concurrently"):
        sample.service.store(sample.root).save(stale)
    assert _row(sample.state, ref) == committed
    assert _packet(sample, ref) == packet
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("damage", ["remove-profile", "remove-context", "change-context", "change-source"])
def test_current_generation_writer_cannot_remove_or_replace_original_context(tmp_path, damage):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    original = _row(sample.state, ref)
    candidate = sample.service.load(sample.root, ref)
    if damage == "remove-profile":
        candidate.pop("frozen_body_profile")
    elif damage == "remove-context":
        candidate["baseline"].pop(CONTEXT_FIELD)
    elif damage == "change-context":
        candidate["baseline"][CONTEXT_FIELD]["payload"]["expires_at"] += 100
    else:
        candidate["baseline"]["hashes"]["module_0000.py"] = "e" * 64
    with pytest.raises(ValueError):
        sample.service.store(sample.root).save(candidate)
    assert _row(sample.state, ref) == original
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("reserved", ["profile-none", "context-none"])
def test_old_task_reserved_fields_cannot_be_added_even_as_null(tmp_path, reserved):
    sample = _sample(tmp_path)
    candidate = sample.state.get(sample.old["task_ref"])
    if reserved == "profile-none":
        candidate["frozen_body_profile"] = None
    else:
        candidate["baseline"][CONTEXT_FIELD] = None
    with pytest.raises(FrozenBodyContextUnavailable) as error:
        sample.state.save(candidate)
    _assert_reason(error, "INVALID")
    _assert_old_unchanged(sample)


def test_old_task_writer_cannot_adopt_a_new_context_or_reset_its_accounting(tmp_path):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    candidate = sample.state.get(sample.old["task_ref"])
    candidate["frozen_body_profile"] = PROFILE
    candidate["baseline"][CONTEXT_FIELD] = _packet(sample, ref)
    with pytest.raises(ValueError):
        sample.state.save(candidate)
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("policy,connector", [(POLICY, False), ("PER_EDIT_V1", False), (POLICY, True)])
def test_existing_key_and_nonprofile_paths_never_gain_a_context(tmp_path, monkeypatch, policy, connector):
    sample = _sample(tmp_path, enabled=False)
    kwargs = {"_owner": sample.owner} if connector else {}
    first = sample.service.begin(sample.root, "old-key", check_policy=policy, **kwargs)
    ref = first["task_ref"]
    record = sample.service.load(sample.root, ref)
    assert "frozen_body_profile" not in record
    assert CONTEXT_FIELD not in record["baseline"]
    row = _row(sample.state, ref)
    upgraded_service = TaskSecurityService(sample.engine, sample.state.hooks,
        owner=sample.owner, now=lambda: sample.clock[0], frozen_body_contexts=True)
    assert upgraded_service.begin(sample.root, "old-key", check_policy=policy, **kwargs)["task_ref"] == ref
    assert _row(sample.state, ref) == row
    before = _private_files(sample.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            upgraded_service.store(sample.root).get_frozen_body_context(ref, owner=sample.owner)
        _assert_reason(error, "UNAVAILABLE")
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


def test_opt_in_does_not_change_per_edit_capture_profile(tmp_path):
    sample = _sample(tmp_path, enabled=True)
    ref = sample.service.begin(sample.root, "nonordinary", check_policy="PER_EDIT_V1")["task_ref"]
    record = sample.service.load(sample.root, ref)
    assert "frozen_body_profile" not in record
    assert CONTEXT_FIELD not in record["baseline"]
    with pytest.raises(FrozenBodyContextUnavailable) as error:
        _packet(sample, ref)
    _assert_reason(error, "UNAVAILABLE")
    assert sample.engine.calls == []


def test_ordinary_owned_connector_can_publish_the_explicit_new_capture_profile(tmp_path):
    sample = _sample(tmp_path, enabled=True)
    ref = sample.service.begin(sample.root, "ordinary-connector", check_policy=POLICY,
        _owner=sample.owner)["task_ref"]
    packet = _packet(sample, ref)
    assert packet["payload"]["owner"] == sample.owner
    assert sample.service.load(sample.root, ref)["frozen_body_profile"] == PROFILE
    _assert_old_unchanged(sample)


def test_opt_in_cannot_publish_an_unowned_closeout_context(tmp_path):
    sample = _sample(tmp_path, enabled=True)
    unowned = TaskSecurityService(sample.engine, sample.state.hooks,
        now=lambda: sample.clock[0], frozen_body_contexts=True)
    with pytest.raises(ValueError, match="explicit owner"):
        unowned.begin(sample.root, "unowned", check_policy=POLICY)
    _assert_old_unchanged(sample)


def test_opt_in_does_not_add_context_to_the_existing_native_intent_fixture(native_intent_sample):
    # The existing test's local signed intent is a policy-exclusion fixture.
    # It does not attest a native host, before-image or repair authorization.
    tasks, _, root, preparation = native_intent_sample
    ready_native_intent(native_intent_sample)
    enabled = TaskSecurityService(tasks.runtime, tasks.hooks, owner=tasks.owner,
        now=tasks.now, frozen_body_contexts=True)
    ref = enabled.begin(root, "native-policy-exclusion", check_policy=POLICY,
        _native_preparation=preparation)["task_ref"]
    record = enabled.load(root, ref)
    assert record["native_repair"] == preparation
    assert "frozen_body_profile" not in record
    assert CONTEXT_FIELD not in record["baseline"]
    with pytest.raises(FrozenBodyContextUnavailable) as error:
        enabled.store(root).get_frozen_body_context(ref, owner=tasks.owner)
    _assert_reason(error, "UNAVAILABLE")


def test_missing_state_and_exact_missing_ref_are_read_only_unavailable(tmp_path, monkeypatch):
    root = tmp_path / "source"
    root.mkdir()
    hooks = HookStateStore(tmp_path / "private")
    state = TaskSecurityStore(hooks, root, now=lambda: 100.0)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            state.get_frozen_body_context("ts1-" + "1" * 32,
                owner=session_owner("codex", "missing"))
        _assert_reason(error, "UNAVAILABLE")
    assert not hooks.directory.exists()


def test_root_replacement_rejects_context_without_changing_private_history(tmp_path):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    before = _private_files(sample.state.path.parent)
    old = sample.root.with_name("original-root-moved-aside")
    sample.root.rename(old)
    sample.root.mkdir()
    try:
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            _packet(sample, ref)
        _assert_reason(error, "ROOT_MISMATCH")
        assert _private_files(sample.state.path.parent) == before
    finally:
        sample.root.rmdir()
        old.rename(sample.root)
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("damage", ["mac", "wrong-task", "wrong-field"])
def test_getter_rejects_bad_context_inside_an_authentic_original_task_row(tmp_path, damage):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    raw, _ = _row(sample.state, ref)
    stored = json.loads(raw)
    packet = stored["baseline"][CONTEXT_FIELD]
    if damage == "mac":
        packet["mac"] = "0" * 64
    elif damage == "wrong-task":
        packet["payload"]["task_ref"] = "ts1-" + "f" * 32
    else:
        packet["payload"]["field"] = "end"
    # Re-authenticate only the enclosing legacy task. The producer's separate
    # context MAC must still be checked instead of trusting that outer MAC.
    with closing(sqlite3.connect(sample.state.path)) as db, db:
        db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
            (encode(stored).decode(), digest(sample.state.key(), stored), ref))
    before = _private_files(sample.state.path.parent)
    with pytest.raises(FrozenBodyContextUnavailable):
        _packet(sample, ref)
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


def test_getter_rejects_signed_task_pointer_source_mismatch_without_hydration(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    raw, _ = _row(sample.state, ref)
    stored = json.loads(raw)
    original_context = copy.deepcopy(stored["baseline"][CONTEXT_FIELD])
    stored["baseline"]["paged_entries"]["source"] = "f" * 64
    with closing(sqlite3.connect(sample.state.path)) as db, db:
        db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
            (encode(stored).decode(), digest(sample.state.key(), stored), ref))
    assert stored["baseline"][CONTEXT_FIELD] == original_context
    before = _private_files(sample.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            _packet(sample, ref)
        _assert_reason(error, "INVALID")
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


@pytest.mark.parametrize("column", ["data", "mac"])
def test_oversized_sql_task_columns_are_rejected_before_python_materialization(tmp_path, column, monkeypatch):
    sample = _sample(tmp_path)
    ref = _begin(sample)
    with closing(sqlite3.connect(sample.state.path)) as db, db:
        db.execute(f"UPDATE security_tasks SET {column}=CAST(zeroblob(?) AS TEXT) WHERE ref=?",
            (MAX_RECORD_BYTES * 4, ref))
    before = _private_files(sample.state.path.parent)
    with monkeypatch.context() as scoped:
        _no_hydration(scoped)
        tracemalloc.start()
        try:
            with pytest.raises(FrozenBodyContextUnavailable):
                _packet(sample, ref)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert peak < 2_000_000, f"oversized {column} was materialized: {peak} Python bytes"
    assert _private_files(sample.state.path.parent) == before
    _assert_old_unchanged(sample)


def test_real_sql_task_insert_failure_does_not_publish_context_after_body_seal(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    real_connect = sqlite3.connect
    attempted = []

    class RejectTaskInsert(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("INSERT OR REPLACE INTO security_tasks"):
                attempted.append(json.loads(parameters[4]))
                super().execute("CREATE TEMP TRIGGER reject_context_publication BEFORE INSERT ON main.security_tasks "
                    "BEGIN SELECT RAISE(ABORT, 'actual-context-publication-failure'); END")
            return super().execute(sql, parameters)

    def connect(database, *args, **kwargs):
        if str(database) == str(sample.state.path) and not kwargs.get("uri"):
            kwargs["factory"] = RejectTaskInsert
        return real_connect(database, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, "connect", connect)
        with pytest.raises(sqlite3.IntegrityError, match="actual-context-publication-failure"):
            _begin(sample)
    assert len(attempted) == 1
    draft = attempted[0]
    ref = draft["task_ref"]
    packet = draft["baseline"][CONTEXT_FIELD]
    assert packet["payload"]["preimage_task_ref"] == ref
    assert _row(sample.state, ref) is None
    with pytest.raises(FrozenBodyContextUnavailable) as error:
        _packet(sample, ref)
    _assert_reason(error, "UNAVAILABLE")
    # Cross-database publication is not atomic: the original body was already
    # committed and sealed. It keeps its old reference/expiry as bounded orphan
    # data; no successful task context is manufactured after this SQL failure.
    bodies = sample.service.preimages(sample.root, draft)
    with closing(real_connect(readonly_uri(bodies.path), uri=True)) as db:
        seal = db.execute("SELECT sealed FROM task_preimage_seals WHERE task_ref=?", (ref,)).fetchone()
    assert seal == (1,)
    with pytest.raises(ValueError, match="Original task unavailable; never reconstruct"):
        sample.service.begin(sample.root, "real-baseline", check_policy=POLICY)
    _assert_old_unchanged(sample)
    assert sample.engine.calls == []


def test_actual_body_seal_sql_failure_never_reaches_task_context_publication(tmp_path, monkeypatch):
    sample = _sample(tmp_path)
    real_connect = sqlite3.connect
    body_path = sample.service.preimages(sample.root, {"check_policy": POLICY}).path
    rejected = []

    class RejectBodySeal(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if sql.startswith("UPDATE task_preimage_seals SET sealed=1"):
                rejected.append(parameters[-1])
                super().execute("CREATE TEMP TRIGGER reject_original_seal BEFORE UPDATE ON main.task_preimage_seals "
                    "BEGIN SELECT RAISE(ABORT, 'actual-body-seal-failure'); END")
            return super().execute(sql, parameters)

    def connect(database, *args, **kwargs):
        if str(database) == str(body_path) and not kwargs.get("uri"):
            kwargs["factory"] = RejectBodySeal
        return real_connect(database, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(sqlite3, "connect", connect)
        with pytest.raises(TaskPreimageUnavailable) as error:
            _begin(sample)
        assert error.value.reason_code == "TASK_PREIMAGE_STORE_UNAVAILABLE"
    assert len(rejected) == 1
    assert _row(sample.state, rejected[0]) is None
    with pytest.raises(FrozenBodyContextUnavailable) as error:
        _packet(sample, rejected[0])
    _assert_reason(error, "UNAVAILABLE")
    _assert_old_unchanged(sample)
    assert sample.engine.calls == []
