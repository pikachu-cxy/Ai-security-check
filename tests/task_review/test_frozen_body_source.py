"""Consume real opt-in task-start bodies through an explicit typed bridge.

The bridge independently freezes original metadata in the new raw domain for
this test consumer. It is neither a production publisher nor a review proof.
All source/state/body IO is confined to pytest's temporary directory.
"""
import copy
from dataclasses import replace
import hashlib
import sqlite3
import stat
from types import SimpleNamespace

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.closeout_state import encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotStore
from security_runtime.task_review.frozen_body_source import FrozenBodySource, FrozenBodySourceError
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import source_binding
from security_runtime.task_review.snapshot_source import TypedSnapshotSource, TypedSnapshotSourceError
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.frozen_body_context import FrozenBodyContextUnavailable
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import MAX_FILE_BODY_BYTES, TaskPreimageStore, TaskPreimageUnavailable
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.snapshot_pages import LISTS, MAPS


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail("Original body consumption must not run a scanner")


def fingerprint(directory):
    values = {}
    for path in [directory, *sorted(directory.rglob("*"))]:
        info = path.lstat()
        values[str(path.relative_to(directory))] = (
            stat.S_IMODE(info.st_mode), info.st_ino, info.st_size, info.st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
    return values


def bridge(sample, *, snapshot=None, binding=None, field="baseline", root=None):
    """Write the genuine baseline maps/lists, without relabelling old pages."""
    snapshot = sample.baseline if snapshot is None else snapshot
    binding = sample.binding if binding is None else binding
    logical = dict(maps={name: snapshot.get(name, {}) for name in MAPS},
                   lists={name: snapshot.get(name, []) for name in LISTS})
    source = hashlib.sha256(encode(logical)).hexdigest()
    positions = {name: {path: index for index, path in enumerate(paths)}
                 for name, paths in logical["lists"].items()}
    paths = sorted(set().union(*(set(value) for value in
                                 [*logical["maps"].values(), *logical["lists"].values()])))
    rows = [(path, encode(dict(
        maps={name: values[path] for name, values in logical["maps"].items() if path in values},
        positions={name: values[path] for name, values in positions.items() if path in values})))
        for path in paths]
    number = sample.bridges
    sample.bridges += 1
    store = SnapshotStore(sample.temporary / f"typed-domain-{number}",
                          workspace_root=root or sample.root, key=sample.key)
    claim = source_binding(binding, field, source)
    ref = store.create(claim)["ref"]
    store.append_page(ref, claim, list(reversed(rows)), expected_cursor=None, cursor="1")
    store.seal(ref, claim, expected_files=len(rows), inventory_complete=True)
    scratch = sample.temporary / f"scratch-{number}"
    scratch.mkdir(mode=0o700)
    return TypedSnapshotSource(store, dict(ref=ref, source=source),
        review_binding=binding, field=field, scratch_directory=scratch)


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "runtime-state"))
    root = (tmp_path / "project").resolve()
    root.mkdir()
    originals = {"ordinary.py": ["first_value=1", "middle_value=2", "last_value=3"],
                 "中文.py": ["first_value=1", "message='中文😀'", "last_value=2"],
                 "large.py": [f"value_{number:05d}=1" for number in range(6000)]}
    for name, lines in originals.items():
        (root / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Genuine capture gaps: metadata knows these paths, but has no usable body.
    (root / "unreadable.py").write_bytes(b"value=\xff\n")
    (root / ".env").write_text("VALUE=1\n")
    hooks = HookStateStore(tmp_path / "private-state")
    clock = [100.0]
    owner = session_owner("codex", "frozen-body-contract")
    service = TaskSecurityService(NoScanner(), hooks, owner=owner,
        now=lambda: clock[0], frozen_body_contexts=True)
    response = service.begin(root, "original-start", check_policy=POLICY)
    assert response["status"] == "ACTIVE"
    ref = response["task_ref"]
    record = service.load(root, ref)
    state = service.store(root)
    packet = state.get_frozen_body_context(ref, owner=owner)
    baseline = record["baseline"]
    assert "unreadable.py" in baseline["inventory"] and "unreadable.py" not in baseline["hashes"]
    assert ".env" in baseline["hashes"] and ".env" not in baseline["preimages"]
    assert baseline["preimages"]["large.py"]["body_bytes"] > 65536
    return SimpleNamespace(root=root, temporary=tmp_path, hooks=hooks, clock=clock,
        now=lambda: clock[0], service=service, state=state, ref=ref, owner=owner,
        record=record, baseline=baseline, packet=packet, originals=originals,
        key=state.key(), bridges=0, binding=ReviewMetadataBinding(ref, owner, 1, "fixture-review", 3))


def locator(sample, typed, *, packet=None, root=None):
    return FrozenBodySource(sample.hooks, root or sample.root,
        sample.packet if packet is None else packet, typed_source=typed, now=sample.now)


def forbid_fallbacks(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Frozen bodies must not use live, end, inline or semantic-proof fallbacks")
    monkeypatch.setattr("security_runtime.local_evidence.WorkspaceReader.read", forbidden)
    monkeypatch.setattr(TaskSecurityService, "before_lines", forbidden)
    monkeypatch.setattr(TaskSecurityService, "end_lines", forbidden)
    monkeypatch.setattr(TaskPreimageStore, "read_semantic_proof", forbidden)


def test_live_edits_and_deletes_keep_original_lines_without_source_or_proof_fallback(sample, monkeypatch):
    (sample.root / "ordinary.py").write_text("replacement_value=9\n")
    (sample.root / "中文.py").unlink()
    forbid_fallbacks(monkeypatch)
    before = fingerprint(sample.hooks.directory)
    with bridge(sample) as typed:
        raw_before = fingerprint(typed.store.directory)
        assert typed.summary["project_coverage"] == "UNKNOWN"
        assert typed.summary["external_bodies_available"] is False
        with locator(sample, typed) as source:
            for name in ("ordinary.py", "中文.py"):
                assert source.read_lines(name) == sample.originals[name]
            detached = source.read_lines("ordinary.py")
            detached[0] = "caller_mutation=1"
            assert source.read_lines("ordinary.py") == sample.originals["ordinary.py"]
        assert typed.entry("ordinary.py") is not None  # Caller still owns its typed view.
        assert fingerprint(typed.store.directory) == raw_before
    assert fingerprint(sample.hooks.directory) == before


def test_independent_raw_ref_and_later_review_scope_can_use_same_original_context(sample):
    first = bridge(sample)
    later = bridge(sample, binding=replace(sample.binding, revision=4, snapshot_id="later-review"))
    scopes = []
    for typed in (first, later):
        with typed, locator(sample, typed) as source:
            scopes.append(typed.scope)
            assert source.read_lines("ordinary.py") == sample.originals["ordinary.py"]
    assert scopes[0]["ref"] != scopes[1]["ref"]
    assert scopes[0]["review_revision"] == 1 and scopes[1]["review_revision"] == 4
    assert scopes[0]["source"] == scopes[1]["source"] == sample.packet["payload"]["source"]


def test_context_and_active_scope_are_detached_and_closed_handles_reject(sample):
    typed = bridge(sample)
    with pytest.raises(TypedSnapshotSourceError) as error:
        typed.scope
    assert error.value.reason_code == "TYPED_SOURCE_CLOSED"
    with typed:
        packet = copy.deepcopy(sample.packet)
        source = locator(sample, typed, packet=packet)
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "FROZEN_BODY_CLOSED"
        packet["payload"]["source"] = "0" * 64
        packet["payload"]["owner"]["session"] = "0" * 64
        scope = typed.scope
        scope["owner"]["session"] = "0" * 64
        scope["root_identity"][0] = -1
        with source:
            assert typed.scope["owner"] == sample.owner
            assert source.read_lines("ordinary.py") == sample.originals["ordinary.py"]
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "FROZEN_BODY_CLOSED"
    with pytest.raises(TypedSnapshotSourceError) as error:
        typed.scope
    assert error.value.reason_code == "TYPED_SOURCE_CLOSED"


@pytest.mark.parametrize("kind,reason", [
    ("owner", "FROZEN_BODY_CONTEXT_OWNER_MISMATCH"),
    ("task", "FROZEN_BODY_CONTEXT_TASK_MISMATCH"),
    ("field", "FROZEN_BODY_SCOPE_MISMATCH"),
    ("representation", "FROZEN_BODY_SCOPE_MISMATCH"),
    ("source", "FROZEN_BODY_SCOPE_MISMATCH"),
    ("root", "FROZEN_BODY_SCOPE_MISMATCH"),
])
def test_real_typed_scope_must_match_original_signed_context(sample, kind, reason):
    binding, field, snapshot, root = sample.binding, "baseline", None, None
    if kind == "owner":
        binding = replace(binding, owner=session_owner("codex", "other-owner"))
    elif kind == "task":
        binding = replace(binding, task_ref="ts1-" + "f" * 32)
    elif kind == "field":
        field = "end"
    elif kind == "representation":
        binding = replace(binding, representation_version=2)
    elif kind == "source":
        snapshot = copy.deepcopy(sample.baseline)
        snapshot["hashes"]["ordinary.py"] = "0" * 64
    elif kind == "root":
        root = sample.temporary / "other-project"
        root.mkdir()
    with bridge(sample, binding=binding, field=field, snapshot=snapshot, root=root) as typed:
        with pytest.raises((FrozenBodySourceError, FrozenBodyContextUnavailable)) as error:
            with locator(sample, typed):
                pytest.fail("Mismatched scope must not enter a body source")
        assert error.value.reason_code == reason


@pytest.mark.parametrize("path", ["unreadable.py", ".env", "never-observed.py"])
def test_missing_hash_reference_or_path_remains_unavailable_without_live_fallback(sample, monkeypatch, path):
    forbid_fallbacks(monkeypatch)
    with bridge(sample) as typed, locator(sample, typed) as source:
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines(path)
        assert error.value.reason_code == "FROZEN_BODY_SOURCE_UNAVAILABLE"


@pytest.mark.parametrize("fault,reason", [
    ("seal", "TASK_PREIMAGE_SOURCE_UNAVAILABLE"),
    ("row", "TASK_PREIMAGE_SOURCE_UNAVAILABLE"),
    ("blob", "TASK_PREIMAGE_CONTENT_UNVERIFIED"),
    ("body", "TASK_PREIMAGE_CONTENT_UNVERIFIED"),
])
def test_original_store_damage_preserves_preimage_failure_without_reconstruction(sample, monkeypatch, fault, reason):
    store = TaskPreimageStore(sample.hooks, sample.root, namespace="closeout", now=sample.now)
    body_sha = sample.baseline["preimages"]["ordinary.py"]["body_sha256"]
    with sqlite3.connect(store.path) as db:
        if fault == "seal":
            db.execute("UPDATE task_preimage_seals SET sealed=0 WHERE task_ref=?", (sample.ref,))
        elif fault == "row":
            db.execute("DELETE FROM task_preimages WHERE task_ref=? AND path='ordinary.py'", (sample.ref,))
        elif fault == "blob":
            db.execute("DELETE FROM task_preimage_blobs WHERE sha256=?", (body_sha,))
        else:
            db.execute("UPDATE task_preimage_blobs SET body=zeroblob(length(body)) WHERE sha256=?", (body_sha,))
    before = fingerprint(sample.hooks.directory)
    forbid_fallbacks(monkeypatch)
    with bridge(sample) as typed, locator(sample, typed) as source:
        with pytest.raises(TaskPreimageUnavailable) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == reason
    assert fingerprint(sample.hooks.directory) == before


def test_body_budget_checks_signed_length_before_body_sql_and_explicit_budget_is_complete(sample, monkeypatch):
    calls = []
    native_connect = sqlite3.connect
    def traced_connect(*args, **kwargs):
        db = native_connect(*args, **kwargs)
        db.set_trace_callback(calls.append)
        return db
    with bridge(sample) as typed, locator(sample, typed) as source:
        monkeypatch.setattr(sqlite3, "connect", traced_connect)
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("large.py")
        assert error.value.reason_code == "FROZEN_BODY_WAITING_BODY_BUDGET"
        assert not any("from task_preimage" in sql.lower() for sql in calls)
        body_bytes = sample.baseline["preimages"]["large.py"]["body_bytes"]
        actual = source.read_lines("large.py", max_bytes=body_bytes)
        assert actual == sample.originals["large.py"]
        assert actual[0] == "value_00000=1" and actual[-1] == "value_05999=1"
        assert any("from task_preimage_blobs" in sql.lower() for sql in calls)


@pytest.mark.parametrize("maximum", [True, 0, -1, 1.5, None, MAX_FILE_BODY_BYTES + 1])
def test_invalid_budget_does_not_read_any_body(sample, monkeypatch, maximum):
    with bridge(sample) as typed, locator(sample, typed) as source:
        monkeypatch.setattr(TaskPreimageStore, "read", lambda *a, **k: pytest.fail("Invalid request read body"))
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("ordinary.py", max_bytes=maximum)
        assert error.value.reason_code == "FROZEN_BODY_INVALID_ARGUMENT"


def test_expired_original_context_is_not_refreshed_from_current_files(sample, monkeypatch):
    sample.clock[0] = sample.packet["payload"]["expires_at"]
    before = fingerprint(sample.hooks.directory)
    forbid_fallbacks(monkeypatch)
    with bridge(sample) as typed:
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            with locator(sample, typed):
                pytest.fail("Expired original context entered")
        assert error.value.reason_code == "FROZEN_BODY_CONTEXT_EXPIRED"
    assert fingerprint(sample.hooks.directory) == before


def test_bad_context_mac_is_not_repaired_or_replaced(sample):
    packet = copy.deepcopy(sample.packet)
    packet["mac"] = "0" * 64 if packet["mac"] != "0" * 64 else "1" * 64
    before = fingerprint(sample.hooks.directory)
    with bridge(sample) as typed:
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            with locator(sample, typed, packet=packet):
                pytest.fail("Unauthenticated context entered")
        assert error.value.reason_code == "FROZEN_BODY_CONTEXT_INVALID"
    assert fingerprint(sample.hooks.directory) == before


@pytest.mark.parametrize("fault,reason", [
    ("replace", "FROZEN_BODY_CONTEXT_INVALID"),
    ("missing", "FROZEN_BODY_CONTEXT_STATE_UNAVAILABLE"),
])
def test_original_key_is_required_and_never_created_from_the_typed_store(sample, fault, reason):
    # The independently verified raw view keeps its own original signing key.
    with bridge(sample) as typed:
        path = sample.state.path.parent / "snapshot.key"
        if fault == "replace":
            path.write_bytes(b"q" * 32 if sample.key != b"q" * 32 else b"r" * 32)
        else:
            path.unlink()
        before = fingerprint(sample.hooks.directory)
        with pytest.raises(FrozenBodyContextUnavailable) as error:
            with locator(sample, typed):
                pytest.fail("Missing or wrong original key entered a body source")
        assert error.value.reason_code == reason
        assert fingerprint(sample.hooks.directory) == before
        if fault == "missing":
            assert not path.exists()


@pytest.mark.parametrize("path", ["../ordinary.py", "/ordinary.py", "", None])
def test_invalid_path_does_not_reach_original_body_reader(sample, monkeypatch, path):
    with bridge(sample) as typed, locator(sample, typed) as source:
        monkeypatch.setattr(TaskPreimageStore, "read", lambda *a, **k: pytest.fail("Invalid path read body"))
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines(path)
        assert error.value.reason_code == "FROZEN_BODY_INVALID_ARGUMENT"


def test_caller_closing_typed_view_cannot_leave_a_readable_body_locator(sample):
    with bridge(sample) as typed, locator(sample, typed) as source:
        typed.close()
        with pytest.raises(TypedSnapshotSourceError) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "TYPED_SOURCE_CLOSED"


@pytest.mark.parametrize("journal", ["wal-header", "wal-active", "rollback-active"])
def test_body_journal_states_are_rejected_without_sqlite_side_effects(sample, journal):
    """A real writer establishes each state; compare only after its writes."""
    body = TaskPreimageStore(sample.hooks, sample.root, namespace="closeout", now=sample.now)
    with bridge(sample) as typed, locator(sample, typed) as source:
        writer = sqlite3.connect(body.path)
        try:
            if journal.startswith("wal"):
                assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
            else:
                assert writer.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",)
            if journal == "wal-header":
                writer.close()
                writer = None
                assert body.path.read_bytes()[18:20] == b"\x02\x02"
                assert not body.path.with_name(body.path.name + "-wal").exists()
                assert not body.path.with_name(body.path.name + "-shm").exists()
            else:
                writer.execute("BEGIN IMMEDIATE")
                writer.execute("UPDATE task_preimage_batches SET expires=expires+1 WHERE task_ref=?",
                               (sample.ref,))
                suffixes = ("-wal", "-shm") if journal == "wal-active" else ("-journal",)
                assert all(body.path.with_name(body.path.name + suffix).exists() for suffix in suffixes)
            before = fingerprint(sample.hooks.directory)
            with pytest.raises(TaskPreimageUnavailable) as error:
                source.read_lines("ordinary.py")
            assert error.value.reason_code == "TASK_PREIMAGE_STORE_UNAVAILABLE"
            assert fingerprint(sample.hooks.directory) == before
        finally:
            if writer is not None:
                writer.rollback()
                writer.close()
