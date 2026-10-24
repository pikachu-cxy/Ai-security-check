"""Capture-scoped canonical views over real sealed raw records, without review IDs.

These fixtures write raw metadata directly. They do not publish a task, migrate
an old source, attest a native before-image, or exercise a production publisher.
"""
import builtins
from dataclasses import asdict, replace
import gc
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
import tracemalloc
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import encode
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError
from security_runtime.task_review.capture_source_binding import (
    CaptureSourceBinding, CaptureSourceBindingError, SOURCE_RETENTION_DOMAIN,
    raw_source_binding, source_descriptor, validate_descriptor,
)
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import source_binding
from security_runtime.task_review.snapshot_source import (
    CaptureCanonicalView, TypedSnapshotSource, TypedSourceBudget, TypedSnapshotSourceError,
)
from security_runtime.tasks.snapshot_pages import LISTS, MAPS
from test_typed_snapshot_source import (
    expected_entries, fingerprint, path_rows, rich_snapshot, source_digest,
)


pytestmark = pytest.mark.skipif(os.name == "nt", reason="Explicit POSIX private scratch")
KEY = b"c" * 32
OWNER = dict(host="codex", session="a" * 64)
TASK = "ts1-" + "a" * 32
SCALE_ENV = "SECURITY_RUNTIME_CAPTURE_SOURCE_SCALE_TEST"


@pytest.fixture
def sample(tmp_path):
    root, scratch = tmp_path / "project", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir(mode=0o700)
    keep = scratch / "caller-owned.txt"
    keep.write_bytes(b"unrelated caller bytes")
    keep.chmod(0o640)
    return SimpleNamespace(root=root, scratch=scratch, keep=keep,
        store=SnapshotStore(tmp_path / "raw", workspace_root=root, key=KEY),
        binding=CaptureSourceBinding(TASK, dict(OWNER), "baseline", TASK, 3))


def write_raw(sample, snapshot, *, binding=None, rows=None, source=None):
    binding = binding or sample.binding
    source = source or source_digest(snapshot)
    rows = path_rows(snapshot) if rows is None else rows
    claim = raw_source_binding(binding, source)
    header = sample.store.create(claim)
    assert header["entry_count"] == 0
    for offset in range(0, len(rows), 128):
        batch = rows[offset:offset + 128]
        header = sample.store.append_page(header["ref"], claim, batch,
            expected_cursor=header["cursor"], cursor=str(offset + len(batch)))
        assert header["state"] != "WAITING_CAPACITY"
    sample.store.seal(header["ref"], claim, expected_files=len(rows), inventory_complete=True)
    return source_descriptor(binding, header["ref"], source)


def view(sample, descriptor, *, binding=None, budget=None):
    return CaptureCanonicalView(sample.store, descriptor,
        capture_binding=binding or sample.binding, scratch_directory=sample.scratch,
        budget=budget or TypedSourceBudget())


def clean_scratch(sample):
    assert not (sample.scratch / "typed-source-v1.job").exists()
    assert sample.keep.read_bytes() == b"unrelated caller bytes"
    assert stat.S_IMODE(sample.keep.stat().st_mode) == 0o640
    assert stat.S_IMODE(sample.scratch.stat().st_mode) == 0o700
    for path in sample.scratch.iterdir():
        if path != sample.keep:
            assert path.is_file() and not path.is_symlink()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600


def reject(sample, descriptor, reason, **kwargs):
    before = fingerprint(sample.store.directory)
    with pytest.raises(TypedSnapshotSourceError) as error:
        with view(sample, descriptor, **kwargs):
            pytest.fail("An invalid capture was exposed as VERIFIED")
    assert error.value.reason_code == "TYPED_SOURCE_" + reason
    assert fingerprint(sample.store.directory) == before
    clean_scratch(sample)


def test_three_domains_same_canonical_share_one_database_without_relabelling(sample):
    snapshot = rich_snapshot()
    source, rows = source_digest(snapshot), path_rows(snapshot)
    old_claim = SnapshotBinding(TASK + ":baseline:" + source, dict(OWNER), source, 3,
        kind="TASK_BEFORE_EDIT", captured_before_edit=True, retention_domain="TASK_PAGES_GC_V1")
    # V1's existing slot is intentionally unchanged; use its own real raw task.
    legacy = ReviewMetadataBinding("ts1-" + "b" * 32, dict(OWNER), 1, "fixture-only-review", 3)
    claims = [old_claim, source_binding(legacy, "baseline", source)]
    refs = []
    for claim in claims:
        header = sample.store.create(claim)
        sample.store.append_page(header["ref"], claim, rows, expected_cursor=None, cursor="done")
        sample.store.seal(header["ref"], claim, expected_files=len(rows), inventory_complete=True)
        refs.append(header["ref"])
    descriptor = write_raw(sample, snapshot)
    inner = validate_descriptor(sample.binding, descriptor)
    assert len({*refs, inner["ref"]}) == 3
    assert raw_source_binding(sample.binding, source).task_ref != old_claim.task_ref
    with sqlite3.connect(sample.store.path) as db:
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 3
        assert db.execute("SELECT count(*) FROM objects").fetchone()[0] == len(rows)
    with view(sample, descriptor) as reader:
        assert reader.entry("Z.py") == expected_entries(snapshot)["Z.py"]
        assert reader.scope["source_domain"] == SOURCE_RETENTION_DOMAIN
        for packet in (reader.summary, reader.scope):
            assert not {"review_revision", "snapshot_id", "review_session"} & packet.keys()
    with TypedSnapshotSource(sample.store, dict(ref=refs[1], source=source),
            review_binding=legacy, field="baseline", scratch_directory=sample.scratch) as original:
        assert original.scope["snapshot_id"] == "fixture-only-review"
        assert original.entry("Z.py") == expected_entries(snapshot)["Z.py"]
    for claim, ref in zip(claims, refs):
        with sample.store.sealed_reader(ref, claim) as original:
            assert original.read_content("Z.py") == dict(rows)["Z.py"]
    # A non-vacuous old-domain collection removes its own orphan, not V1/V2.
    result = sample.store.collect_unreferenced(set())
    assert result["collected_captures"] == 1
    with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_HISTORY_UNAVAILABLE$"):
        sample.store.resume(refs[0], old_claim)
    assert sample.store.resume(refs[1], claims[1])["state"] == "SEALED"
    with view(sample, descriptor) as reader:
        assert reader.summary["source_digest_verified"] is True
    clean_scratch(sample)


def test_same_canonical_distinct_end_versions_and_cursors_remain_separate(sample):
    snapshot = rich_snapshot()
    first = replace(sample.binding, field="end", capture_ref="ts1-" + "c" * 32)
    second = replace(first, capture_ref="ts1-" + "d" * 32)
    one, two = write_raw(sample, snapshot, binding=first), write_raw(sample, snapshot, binding=second)
    assert one["capture_source"]["source"] == two["capture_source"]["source"]
    assert one["capture_source"]["ref"] != two["capture_source"]["ref"]
    with view(sample, one, binding=first) as reader:
        token = reader.entries_page(limit_items=1)["next_cursor"]
        assert reader.scope["capture_ref"] == first.capture_ref
    with view(sample, one, binding=first) as resumed:
        assert resumed.entries_page(cursor=token, limit_items=2)["entries"]
    with view(sample, two, binding=second) as other:
        assert other.scope["capture_ref"] == second.capture_ref
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CURSOR_INVALID$"):
            other.entries_page(cursor=token)
    clean_scratch(sample)


def test_v1_and_v2_same_parent_field_and_sha_coexist_in_the_original_database(sample):
    snapshot = rich_snapshot()
    source, rows = source_digest(snapshot), path_rows(snapshot)
    legacy = ReviewMetadataBinding(TASK, dict(OWNER), 1, "fixture-only-original-v1", 3)
    claim = source_binding(legacy, "baseline", source)
    header = sample.store.create(claim)
    sample.store.append_page(header["ref"], claim, rows, expected_cursor=None, cursor="done")
    sample.store.seal(header["ref"], claim, expected_files=len(rows), inventory_complete=True)
    descriptor = write_raw(sample, snapshot)
    assert descriptor["capture_source"]["task_ref"] == legacy.task_ref == sample.binding.task_ref
    assert descriptor["capture_source"]["source"] == source
    assert descriptor["capture_source"]["ref"] != header["ref"]
    assert raw_source_binding(sample.binding, source).task_ref != claim.task_ref
    with sqlite3.connect(sample.store.path) as db:
        assert db.execute("SELECT count(*) FROM captures").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM objects").fetchone()[0] == len(rows)
    with TypedSnapshotSource(sample.store, dict(ref=header["ref"], source=source),
            review_binding=legacy, field="baseline", scratch_directory=sample.scratch) as original:
        assert original.entry("Z.py") == expected_entries(snapshot)["Z.py"]
    with view(sample, descriptor) as current:
        assert current.entry("Z.py") == expected_entries(snapshot)["Z.py"]
    assert sample.store.resume(header["ref"], claim)["state"] == "SEALED"
    clean_scratch(sample)


@pytest.mark.parametrize("case", ["outer_extra", "legacy_pointer", "inner_extra", "schema_boolean", "wrong_domain",
                                  "bad_ref", "bad_source", "bad_owner"])
def test_descriptor_is_exact_and_cannot_weaken_capture_identity(sample, case):
    descriptor = write_raw(sample, rich_snapshot())
    inner = descriptor["capture_source"]
    if case == "outer_extra":
        descriptor["paged_entries"] = dict(ref=inner["ref"], source=inner["source"])
    elif case == "legacy_pointer":
        descriptor = dict(ref=inner["ref"], source=inner["source"])
    elif case == "inner_extra":
        inner["snapshot_id"] = "invented-review"
    elif case == "schema_boolean":
        inner["schema_version"] = True
    else:
        name, value = {"wrong_domain": ("retention_domain", "TASK_PAGED_REVIEW_V1"),
            "bad_ref": ("ref", "ws2-invalid"), "bad_source": ("source", "f" * 63),
            "bad_owner": ("owner", dict(host="codex", session="invalid"))}[case]
        inner[name] = value
    with pytest.raises(CaptureSourceBindingError) as error:
        view(sample, descriptor)
    assert error.value.reason_code == "CAPTURE_SOURCE_BINDING_INVALID"


@pytest.mark.parametrize("case", ["owner", "task", "field", "representation"])
def test_valid_descriptor_from_another_scope_is_not_adopted(sample, case):
    descriptor = write_raw(sample, rich_snapshot())
    if case == "owner":
        other = replace(sample.binding, owner=dict(host="cursor", session="b" * 64))
    elif case == "task":
        other = replace(sample.binding, task_ref="ts1-" + "b" * 32, capture_ref="ts1-" + "b" * 32)
    elif case == "field":
        other = replace(sample.binding, field="end", capture_ref="ts1-" + "b" * 32)
    else:
        other = replace(sample.binding, representation_version=4)
    with pytest.raises(CaptureSourceBindingError) as error:
        view(sample, descriptor, binding=other)
    assert error.value.reason_code == "CAPTURE_SOURCE_BINDING_SCOPE_MISMATCH"


def test_well_formed_descriptor_cannot_rebind_a_foreign_signed_raw_ref(sample):
    first = write_raw(sample, rich_snapshot())
    other = replace(sample.binding, task_ref="ts1-" + "b" * 32, capture_ref="ts1-" + "b" * 32)
    foreign = write_raw(sample, rich_snapshot(), binding=other)
    first["capture_source"]["ref"] = foreign["capture_source"]["ref"]
    with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_BINDING_MISMATCH$"):
        with view(sample, first):
            pytest.fail("A structural descriptor was mistaken for a signed publication")
    clean_scratch(sample)


@pytest.mark.parametrize("case", ["digest", "duplicate_key", "duplicate_position", "position_gap", "position_bool"])
def test_raw_signature_does_not_replace_canonical_json_and_list_validation(sample, case):
    snapshot = dict(hashes={"a.py": "a" * 64, "b.py": "b" * 64}, inventory=["a.py", "b.py"])
    rows, digest, reason = path_rows(snapshot), None, "POSITION_INVALID"
    if case == "digest":
        digest, reason = "f" * 64, "SOURCE_MISMATCH"
    elif case == "duplicate_key":
        rows[0] = ("a.py", b'{"maps":{},"maps":{"hashes":"' + b'a' * 64 + b'"},"positions":{"inventory":0}}')
        reason = "INVALID_PAYLOAD"
    else:
        value = json.loads(rows[1][1])
        value["positions"]["inventory"] = {"duplicate_position": 0, "position_gap": 2,
                                            "position_bool": True}[case]
        rows[1] = ("b.py", encode(value))
    reject(sample, write_raw(sample, snapshot, rows=rows, source=digest), reason)


def test_constructor_is_pure_and_detaches_descriptor_and_owner(sample, monkeypatch):
    descriptor = write_raw(sample, rich_snapshot())
    model = CaptureSourceBinding(TASK, dict(OWNER), "baseline", TASK, 3)
    before = fingerprint(sample.store.directory)
    def forbidden(*args, **kwargs):
        pytest.fail("Capture constructor performed filesystem or SQLite IO")
    with monkeypatch.context() as scoped:
        for name in ("open", "stat", "lstat", "mkdir", "chmod", "listdir", "scandir"):
            scoped.setattr(os, name, forbidden)
        scoped.setattr(builtins, "open", forbidden)
        scoped.setattr(Path, "open", forbidden)
        scoped.setattr(sqlite3, "connect", forbidden)
        scoped.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, forbidden})
        scoped.setattr(os, "supports_follow_symlinks", {*os.supports_follow_symlinks, forbidden})
        reader = view(sample, descriptor, binding=model)
    descriptor["capture_source"]["owner"]["session"] = "b" * 64
    descriptor["capture_source"]["source"] = "b" * 64
    with reader:
        assert reader.scope["owner"] == OWNER
        assert reader.entry("Z.py")["maps"]["hashes"] == rich_snapshot()["hashes"]["Z.py"]
    assert fingerprint(sample.store.directory) == before
    clean_scratch(sample)


@pytest.mark.parametrize("case", ["body", "entry", "source", "scratch"])
def test_representative_core_budgets_do_not_yield_a_verified_prefix(sample, case):
    snapshot = dict(texts={"large.py": ["x" * 70000]}, inventory=["large.py"])
    descriptor = write_raw(sample, snapshot)
    budget, reason = {"body": (TypedSourceBudget(), "WAITING_BODY_BUDGET"),
        "entry": (TypedSourceBudget(body_bytes=80000), "WAITING_ENTRY_BUDGET"),
        "source": (TypedSourceBudget(source_bytes=1), "WAITING_SOURCE_BUDGET"),
        "scratch": (TypedSourceBudget(scratch_bytes=4096), "WAITING_SCRATCH_CAPACITY")}[case]
    reject(sample, descriptor, reason, budget=budget)
    with view(sample, descriptor, budget=TypedSourceBudget(body_bytes=80000, entry_bytes=80000)) as reader:
        assert reader.entry("large.py")["maps"]["texts"] == snapshot["texts"]["large.py"]
    clean_scratch(sample)


def test_private_scratch_detached_results_and_closed_api(sample):
    descriptor = write_raw(sample, rich_snapshot())
    before = fingerprint(sample.store.directory)
    sample.scratch.chmod(0o755)
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_SCRATCH_UNSAFE$"):
        with view(sample, descriptor):
            pytest.fail("A nonprivate scratch parent was silently upgraded")
    assert stat.S_IMODE(sample.scratch.stat().st_mode) == 0o755
    sample.scratch.chmod(0o700)  # Explicit fixture repair, never done by the reader.
    with view(sample, descriptor) as reader:
        scope = reader.scope
        scope["owner"]["session"] = "b" * 64
        assert reader.scope["owner"] == OWNER
        summary = reader.summary
        summary["map_counts"]["hashes"] = 999
        assert reader.summary["map_counts"]["hashes"] == 2
        item = reader.entry("Z.py")
        item["maps"]["texts"].append("caller edit")
        assert reader.entry("Z.py")["maps"]["texts"] == rich_snapshot()["texts"]["Z.py"]
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_PAGE_BYTE_BUDGET$"):
            reader.entries_page(limit_bytes=1)
    for call in (lambda: reader.summary, lambda: reader.scope, lambda: reader.entry("Z.py"),
                 lambda: reader.entries_page()):
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CLOSED$"):
            call()
    assert fingerprint(sample.store.directory) == before
    clean_scratch(sample)


@pytest.mark.parametrize("count", [1001, pytest.param(10001, marks=pytest.mark.skipif(
    os.getenv(SCALE_ENV) != "1", reason=f"Explicit 10001-record run: {SCALE_ENV}=1"))])
def test_complete_canonical_and_all_original_paths_without_review_identity(sample, monkeypatch, count):
    started = time.perf_counter()
    names = [f"modules/source_{index:05d}.py" for index in range(count)]
    maps = {name: {} for name in MAPS}
    for index, name in enumerate(names):
        maps["hashes"][name] = hashlib.sha256(f"original={index}\n".encode()).hexdigest()
        maps["texts"][name], maps["line_counts"][name] = [f"original={index}"], 1
    snapshot = dict(**maps, inventory=names, read_priority=list(reversed(names)))
    descriptor = write_raw(sample, snapshot)
    fixture_seconds = time.perf_counter() - started
    raw_before = fingerprint(sample.store.directory)
    budget = TypedSourceBudget(elapsed_seconds=600 if count == 10001 else 120)
    def forbidden_live(*args, **kwargs):
        pytest.fail("Capture metadata must never read the live project")
    monkeypatch.setattr("security_runtime.local_evidence.WorkspaceReader.read", forbidden_live)
    def guard_open(original):
        def guarded(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(path)).absolute()
                if candidate != sample.root and candidate.is_relative_to(sample.root):
                    forbidden_live()
            return original(path, *args, **kwargs)
        return guarded
    for module in (builtins, io, os):
        monkeypatch.setattr(module, "open", guard_open(module.open))
    gc.collect()
    tracemalloc.start()
    started, seen, pages, digest = time.perf_counter(), 0, 0, hashlib.sha256()
    try:
        with view(sample, descriptor, budget=budget) as reader:
            assert reader.summary["entry_count"] == count
            assert reader.summary["source_digest_verified"] is True
            assert reader.summary["project_coverage"] == "UNKNOWN"
            assert reader.summary["external_bodies_available"] is False
            assert not {"review_revision", "snapshot_id"} & reader.scope.keys()
            cursor = None
            while True:
                page = reader.entries_page(cursor=cursor, limit_items=128)
                assert page["entries"] and len(encode(page)) <= 65536
                for entry in page["entries"]:
                    name = names[seen]
                    assert entry == dict(path=name, maps={key: values[name] for key, values in maps.items()
                        if name in values}, positions=dict(inventory=seen, read_priority=count - seen - 1))
                    digest.update(encode(entry) + b"\n")
                    seen += 1
                pages += 1
                if page["complete"]:
                    assert page["next_cursor"] is None
                    break
                assert page["next_cursor"] and page["next_cursor"] != cursor
                cursor = page["next_cursor"]
            assert seen == count and pages == (count + 127) // 128
            assert reader.entry(names[-1])["maps"]["texts"] == [f"original={count - 1}"]
            assert reader.entry("never-observed.py") is None
        _, peak = tracemalloc.get_traced_memory()
        seconds = time.perf_counter() - started
    finally:
        tracemalloc.stop()
    assert peak < 4_000_000
    assert fingerprint(sample.store.directory) == raw_before
    clean_scratch(sample)
    with view(sample, descriptor, budget=budget) as reopened:
        assert reopened.summary["entry_count"] == count
        assert reopened.entry(names[-1])["positions"] == dict(inventory=count - 1, read_priority=0)
    print(json.dumps(dict(scope="internal-capture-canonical-view-only", records=count,
        fixture_seconds=fixture_seconds, reader_seconds=seconds, python_peak_bytes=peak,
        all_entries_sha256=digest.hexdigest(), source=descriptor["capture_source"]["source"],
        raw_database_bytes=sample.store.path.stat().st_size, budget=asdict(budget),
        complete_paths_verified=True, publisher_exercised=False, review_identity_invented=False,
        measurement="tracemalloc covers verification/traversal/close, excludes fixture and reopen"), sort_keys=True))
