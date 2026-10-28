"""Real current-end capture and consumption; detector results remain fixtures.

The new-domain bridge freezes only original end metadata for this consumer.
It is not a production publisher, host attestation, semantic proof or pin.
"""
import copy
from dataclasses import replace
import sqlite3
from types import SimpleNamespace

import pytest
import os

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Opt-in capture publication requires POSIX private-state guarantees")

from security_runtime.hook_state import HookStateStore
from security_runtime.task_review.frozen_body_source import FrozenBodySource, FrozenBodySourceError
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.snapshot_source import TypedSnapshotSourceError
from security_runtime.tasks.activity import POLICY
from security_runtime.tasks.frozen_end_context import (
    END_CONTEXT_FIELD, END_CONTRACT, FrozenEndBodyContextUnavailable, verify_end_context,
)
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.preimages import TaskPreimageUnavailable
from security_runtime.tasks.security import TaskSecurityService
from test_frozen_body_source import bridge, fingerprint, forbid_fallbacks
from test_task_security import LedgerRuntime


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "runtime-state"))
    root = (tmp_path / "project").resolve()
    root.mkdir()
    paths = ("ordinary.py", "中文.py", "large.py")
    for name in paths:
        (root / name).write_text("value_a=1\n", encoding="utf-8")
    (root / ".env").write_text("VALUE=1\n")
    hooks = HookStateStore(tmp_path / "private-state")
    clock, engine = [100.0], LedgerRuntime()
    owner = session_owner("codex", "frozen-end-contract")
    service = TaskSecurityService(engine, hooks, owner=owner,
        now=lambda: clock[0], frozen_body_contexts=True)
    started = service.begin(root, "original-start", check_policy=POLICY)
    assert started["status"] == "ACTIVE" and engine.calls == []
    originals = {"ordinary.py": ["first_b=2", "middle_b=2", "last_b=2"],
                 "中文.py": ["first_b=2", "message='中文😀'", "last_b=2"],
                 "large.py": [f"value_b_{number:05d}=2" for number in range(6000)]}
    for name, lines in originals.items():
        (root / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    clock[0] += 1
    finished = service.finish(root, started["task_ref"])
    assert finished["status"] == "READY" and len(engine.calls) == 1
    record = service.load(root, started["task_ref"])
    state, end = service.store(root), record["end"]
    packet = state.get_frozen_end_body_context(record["task_ref"], owner=owner,
                                              expected_version_ref=end["version_ref"])
    assert packet == end[END_CONTEXT_FIELD]
    payload = packet["payload"]
    assert payload["contract"] == END_CONTRACT
    assert payload["task_ref"] == record["task_ref"] != end["version_ref"]
    assert payload["version_ref"] == payload["preimage_task_ref"] == end["version_ref"]
    assert payload["field"] == payload["preimage_namespace"] == "end"
    assert ".env" in end["hashes"] and ".env" not in end["preimages"]
    assert end["preimages"]["large.py"]["body_bytes"] > 65536
    return SimpleNamespace(root=root, temporary=tmp_path, hooks=hooks, clock=clock,
        now=lambda: clock[0], engine=engine, service=service, ref=record["task_ref"],
        owner=owner, state=state, baseline=record["baseline"], end=end, packet=packet,
        originals=originals, key=state.key(), bridges=0,
        binding=ReviewMetadataBinding(record["task_ref"], owner, 1, "fixture-end-review", 3))


def end_view(sample, *, end=None, binding=None, root=None, field="end"):
    return bridge(sample, snapshot=sample.end if end is None else end,
                  binding=binding, root=root, field=field)


def locator(sample, typed, packet=None):
    return FrozenBodySource(sample.hooks, sample.root,
        sample.packet if packet is None else packet, typed_source=typed, now=sample.now)


def test_live_c_and_deletion_never_replace_frozen_end_b(sample, monkeypatch):
    (sample.root / "ordinary.py").write_text("live_c=3\n")
    (sample.root / "中文.py").unlink()
    forbid_fallbacks(monkeypatch)
    before = fingerprint(sample.hooks.directory)
    with end_view(sample) as typed:
        assert typed.scope["field"] == "end"
        assert typed.summary["project_coverage"] == "UNKNOWN"
        assert typed.summary["external_bodies_available"] is False
        with locator(sample, typed) as source:
            for name in ("ordinary.py", "中文.py"):
                assert source.read_lines(name) == sample.originals[name]
        assert typed.entry("ordinary.py") is not None
    assert fingerprint(sample.hooks.directory) == before
    assert len(sample.engine.calls) == 1  # Only the fixture finish ran detectors.


def test_identical_canonical_end_in_another_raw_ref_and_review_scope_is_valid(sample):
    scopes = []
    for binding in (sample.binding, replace(sample.binding, revision=3, snapshot_id="later-review")):
        with end_view(sample, binding=binding) as typed, locator(sample, typed) as source:
            scopes.append(typed.scope)
            assert source.read_lines("ordinary.py") == sample.originals["ordinary.py"]
    assert scopes[0]["ref"] != scopes[1]["ref"]
    assert scopes[0]["review_revision"] == 1 and scopes[1]["review_revision"] == 3
    assert scopes[0]["source"] == scopes[1]["source"] == sample.packet["payload"]["source"]


def test_superseded_end_neither_matches_new_metadata_nor_recovers_discarded_bodies(sample, monkeypatch):
    original_end, original_packet = copy.deepcopy(sample.end), copy.deepcopy(sample.packet)
    (sample.root / "ordinary.py").write_text("live_c=3\n")
    sample.clock[0] += 1
    assert sample.service.finish(sample.root, sample.ref)["status"] == "READY"
    current = sample.service.load(sample.root, sample.ref)["end"]
    assert current["version_ref"] != original_end["version_ref"]
    assert len(sample.engine.calls) == 2
    with pytest.raises(FrozenEndBodyContextUnavailable) as error:
        sample.state.get_frozen_end_body_context(sample.ref, owner=sample.owner,
            expected_version_ref=original_end["version_ref"])
    assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_SUPERSEDED"
    forbid_fallbacks(monkeypatch)
    before = fingerprint(sample.hooks.directory)
    with end_view(sample, end=current) as typed:
        with pytest.raises(FrozenBodySourceError) as error:
            with locator(sample, typed, original_packet):
                pytest.fail("E1 context must not bind E2 metadata")
        assert error.value.reason_code == "FROZEN_BODY_SCOPE_MISMATCH"
    with end_view(sample, end=original_end) as typed, locator(sample, typed, original_packet) as source:
        with pytest.raises(TaskPreimageUnavailable) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "TASK_PREIMAGE_SOURCE_UNAVAILABLE"
    assert fingerprint(sample.hooks.directory) == before


@pytest.mark.parametrize("kind,reason", [
    ("owner", "FROZEN_END_BODY_CONTEXT_OWNER_MISMATCH"),
    ("task", "FROZEN_END_BODY_CONTEXT_TASK_MISMATCH"),
    ("root", "FROZEN_BODY_SCOPE_MISMATCH"),
    ("representation", "FROZEN_BODY_SCOPE_MISMATCH"),
])
def test_end_context_requires_original_task_owner_root_and_representation(sample, kind, reason):
    binding, root = sample.binding, None
    if kind == "owner":
        binding = replace(binding, owner=session_owner("codex", "different-owner"))
    elif kind == "task":
        binding = replace(binding, task_ref="ts1-" + "f" * 32)
    elif kind == "representation":
        binding = replace(binding, representation_version=2)
    else:
        root = sample.temporary / "other-project"
        root.mkdir()
    with end_view(sample, binding=binding, root=root) as typed:
        with pytest.raises((FrozenEndBodyContextUnavailable, FrozenBodySourceError)) as error:
            with locator(sample, typed):
                pytest.fail("Mismatched end scope entered")
        assert error.value.reason_code == reason


@pytest.mark.parametrize("fault", ["mac", "version"])
def test_bad_end_mac_or_repointed_version_is_not_resigned(sample, fault):
    packet = copy.deepcopy(sample.packet)
    if fault == "mac":
        packet["mac"] = "0" * 64 if packet["mac"] != "0" * 64 else "1" * 64
    else:
        packet["payload"]["version_ref"] = "ts1-" + "f" * 32
        packet["payload"]["preimage_task_ref"] = packet["payload"]["version_ref"]
    before = fingerprint(sample.hooks.directory)
    with end_view(sample) as typed:
        with pytest.raises(FrozenEndBodyContextUnavailable) as error:
            with locator(sample, typed, packet):
                pytest.fail("Unverified end context entered")
        assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_INVALID"
    assert fingerprint(sample.hooks.directory) == before


def test_expected_current_pointer_is_explicit_and_getter_returns_a_copy(sample):
    wrong = "ts1-" + "f" * 32
    with pytest.raises(FrozenEndBodyContextUnavailable) as error:
        sample.state.get_frozen_end_body_context(sample.ref, owner=sample.owner, expected_version_ref=wrong)
    assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_SUPERSEDED"
    with pytest.raises(FrozenEndBodyContextUnavailable) as error:
        sample.state.get_frozen_end_body_context(sample.ref, owner=sample.owner,
            expected_version_ref=sample.end["version_ref"], expected_source="0" * 64)
    assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_SOURCE_MISMATCH"
    with pytest.raises(FrozenEndBodyContextUnavailable) as error:
        verify_end_context(sample.hooks, sample.root, sample.packet,
                           version_ref=wrong, now=sample.now)
    assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_VERSION_MISMATCH"
    detached = sample.state.get_frozen_end_body_context(sample.ref, owner=sample.owner,
        expected_version_ref=sample.end["version_ref"])
    detached["payload"]["version_ref"] = wrong
    assert sample.state.get_frozen_end_body_context(sample.ref, owner=sample.owner,
        expected_version_ref=sample.end["version_ref"]) == sample.packet


def test_end_and_baseline_contexts_cannot_be_interchanged(sample):
    before_packet = sample.state.get_frozen_body_context(sample.ref, owner=sample.owner)
    with end_view(sample) as typed:
        with pytest.raises(FrozenBodySourceError) as error:
            with locator(sample, typed, before_packet):
                pytest.fail("Baseline locator entered an end view")
        assert error.value.reason_code == "FROZEN_BODY_SCOPE_MISMATCH"
    with end_view(sample, field="baseline") as typed:
        with pytest.raises(FrozenBodySourceError) as error:
            with locator(sample, typed):
                pytest.fail("End locator entered a baseline view")
        assert error.value.reason_code == "FROZEN_BODY_SCOPE_MISMATCH"


def test_expired_end_context_does_not_refresh_from_current_source(sample, monkeypatch):
    sample.clock[0] = sample.packet["payload"]["expires_at"]
    forbid_fallbacks(monkeypatch)
    before = fingerprint(sample.hooks.directory)
    with end_view(sample) as typed:
        with pytest.raises(FrozenEndBodyContextUnavailable) as error:
            with locator(sample, typed):
                pytest.fail("Expired end context entered")
        assert error.value.reason_code == "FROZEN_END_BODY_CONTEXT_EXPIRED"
    assert fingerprint(sample.hooks.directory) == before


@pytest.mark.parametrize("fault,reason", [
    ("seal", "TASK_PREIMAGE_SOURCE_UNAVAILABLE"),
    ("blob", "TASK_PREIMAGE_CONTENT_UNVERIFIED"),
])
def test_end_body_damage_preserves_original_reader_errors(sample, monkeypatch, fault, reason):
    body = sample.service.end_versions(sample.root)
    with sqlite3.connect(body.path) as db:
        if fault == "seal":
            db.execute("UPDATE task_preimage_seals SET sealed=0 WHERE task_ref=?",
                       (sample.end["version_ref"],))
        else:
            db.execute("DELETE FROM task_preimage_blobs WHERE sha256=?",
                       (sample.end["preimages"]["ordinary.py"]["body_sha256"],))
    before = fingerprint(sample.hooks.directory)
    forbid_fallbacks(monkeypatch)
    with end_view(sample) as typed, locator(sample, typed) as source:
        with pytest.raises(TaskPreimageUnavailable) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == reason
    assert fingerprint(sample.hooks.directory) == before


def test_hash_without_retained_end_body_stays_unavailable(sample, monkeypatch):
    forbid_fallbacks(monkeypatch)
    with end_view(sample) as typed, locator(sample, typed) as source:
        assert "hashes" in typed.entry(".env")["maps"]
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines(".env")
        assert error.value.reason_code == "FROZEN_BODY_SOURCE_UNAVAILABLE"


def test_end_body_budget_precedes_body_sql_and_explicit_budget_returns_every_line(sample, monkeypatch):
    calls, connect = [], sqlite3.connect
    def traced(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(calls.append)
        return db
    with end_view(sample) as typed, locator(sample, typed) as source:
        monkeypatch.setattr(sqlite3, "connect", traced)
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("large.py")
        assert error.value.reason_code == "FROZEN_BODY_WAITING_BODY_BUDGET"
        assert not any("from task_preimage" in sql.lower() for sql in calls)
        lines = source.read_lines("large.py", max_bytes=sample.end["preimages"]["large.py"]["body_bytes"])
        assert lines == sample.originals["large.py"]
        assert lines[0] == "value_b_00000=2" and lines[-1] == "value_b_05999=2"
        assert any("from task_preimage_blobs" in sql.lower() for sql in calls)


def test_end_reader_rejects_real_wal_header_without_creating_sidecars(sample):
    body = sample.service.end_versions(sample.root)
    with end_view(sample) as typed, locator(sample, typed) as source:
        writer = sqlite3.connect(body.path)
        try:
            assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        finally:
            writer.close()
        assert body.path.read_bytes()[18:20] == b"\x02\x02"
        assert not body.path.with_name(body.path.name + "-wal").exists()
        assert not body.path.with_name(body.path.name + "-shm").exists()
        before = fingerprint(sample.hooks.directory)
        with pytest.raises(TaskPreimageUnavailable) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "TASK_PREIMAGE_STORE_UNAVAILABLE"
        assert fingerprint(sample.hooks.directory) == before


def test_end_context_detaches_inputs_and_never_outlives_its_typed_view(sample):
    with end_view(sample) as typed:
        packet = copy.deepcopy(sample.packet)
        source = locator(sample, typed, packet)
        packet["payload"]["version_ref"] = "ts1-" + "f" * 32
        scope = typed.scope
        scope["owner"]["session"] = "0" * 64
        with source:
            assert source.read_lines("ordinary.py") == sample.originals["ordinary.py"]
            typed.close()
            with pytest.raises(TypedSnapshotSourceError) as error:
                source.read_lines("ordinary.py")
            assert error.value.reason_code == "TYPED_SOURCE_CLOSED"
        with pytest.raises(FrozenBodySourceError) as error:
            source.read_lines("ordinary.py")
        assert error.value.reason_code == "FROZEN_BODY_CLOSED"
