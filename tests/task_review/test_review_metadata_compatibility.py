"""Independent paged metadata checks; not coordinator or host acceptance.

Legacy heads use the real signed task store and the existing v3 planner.  No
scanner, TaskSecurityService lifecycle, Runtime connection or installation is
used here.  Large collections are verified a page at a time without collecting
their contents into another Python dictionary.
"""
from __future__ import annotations

import gc
import hashlib
import json
import os
import sqlite3
import time
import tracemalloc

import pytest

from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_contract import development_capabilities
from security_runtime.task_review.metadata_store import (
    ReviewMetadataBinding, ReviewMetadataBudget, ReviewMetadataError, ReviewMetadataStore,
)
from security_runtime.task_review.plan import build_plan, charge_packet
from security_runtime.tasks.security_state import CONTRACT, MAX_RECORD_BYTES, TaskSecurityStore
from test_task_review_plan import task


KEY = b"m" * 32
OWNER = dict(host="codex", session="c" * 64)
SCALE_ENV = "SECURITY_RUNTIME_REVIEW_METADATA_SCALE_TEST"
LIMITS = dict(source_bytes=6_000_000, navigation_bytes=3_000_000,
              control_bytes=3_000_000, reads=100_000, total_bytes=12_000_000)
APPEND_CHARGE = dict(source_bytes=0, navigation_bytes=123, control_bytes=19,
                     reads=1, total_bytes=142)


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def _unit(index, *, windows=24):
    """Real-shaped required-window metadata rather than one oversized blob."""
    path = f"modules/模块_{index:06d}.py"
    sha = hashlib.sha256(f"immutable-source-{index}".encode()).hexdigest()
    return dict(
        unit_id=f"tu1-{index:032x}", path=path, change="MODIFIED",
        batch_id=f"tb3-{index // 8:024x}", status="PENDING", submitted_at=None,
        required_windows=[dict(
            path=path, file_sha256=sha,
            location_version="BEFORE_TASK" if number % 2 else "CURRENT_TASK_END",
            start_line=number * 100 + 1, end_line=number * 100 + 80)
            for number in range(windows)],
        evidence_gaps=[], limitations=[])


def _legacy_fixture(tmp_path, *, capacity=False):
    """Persist an old-contract fixture without asking Runtime to create work."""
    root = (tmp_path / "source").resolve()
    root.mkdir()
    hooks = HookStateStore((tmp_path / "private").resolve())
    state = TaskSecurityStore(hooks, root, now=lambda: 100.0)
    state.path.parent.mkdir(parents=True)
    state.path.parent.chmod(0o700)
    key_path = state.path.parent / "snapshot.key"
    key_path.write_bytes(KEY)
    key_path.chmod(0o600)
    if capacity:
        record = task({}, {"huge.py": ["original retained elsewhere"]},
                      [dict(path="huge.py", change="ADDED")])
        # This is the planner's genuine unavailable-body estimate and resource
        # rejection, not a manufactured CAPACITY_REQUIRED response.
        record["end"]["texts"] = {}
        record["end"]["line_counts"] = {"huge.py": 100_000}
    else:
        record = task()
    plan = build_plan(record, now=100.0)
    charge_packet(record, dict(navigation="one real accounting event"),
                  category="navigation", now=100.0)
    record.update(contract=CONTRACT, workspace=str(root), generation=0,
                  task_key="legacy-capacity" if capacity else "legacy-review",
                  phase="REVIEWING", created_at=100.0, task_owner=dict(OWNER),
                  review_session="tr1-" + "d" * 32)
    if capacity:
        assert plan["capacity"]["status"] == "CAPACITY_REQUIRED"
        record["review_capacity"] = dict(plan["capacity"])
    original = state.save(record, new=True)
    state.path.chmod(0o600)
    return state, root, original


def _task_row(state, ref):
    with sqlite3.connect(state.path) as db:
        row = db.execute("SELECT data,mac FROM security_tasks WHERE ref=?", (ref,)).fetchone()
    assert row is not None
    return row


def _binding():
    # Internal foundation data for new work.  This deliberately does not claim
    # that its ledger inherits or can replace the existing legacy task ledger.
    return ReviewMetadataBinding(
        "ts1-" + "b" * 32, dict(OWNER), 1, "e" * 64, 3)


def _store(state, root):
    return ReviewMetadataStore(state.path, workspace_root=root, key=KEY)


def _write(current, binding, *, name, count, batch, factory, progress=False):
    header = current.create(binding, name, limits=dict(LIMITS),
                            request_id=f"create-{name}")
    encoded_bytes, calls, source_digest = 0, 0, hashlib.sha256()
    for offset in range(0, count, batch):
        items = [factory(index) for index in range(offset, min(offset + batch, count))]
        for item in items:
            raw = _encoded(item)
            encoded_bytes += len(raw)
            source_digest.update(raw + b"\n")
        header = current.append(
            header["ref"], binding, items,
            expected_generation=header["generation"],
            request_id=f"append-{name}-{offset}", charge=dict(APPEND_CHARGE))
        calls += 1
        assert header["item_count"] == offset + len(items)
        if progress and (calls % 64 == 0 or header["item_count"] == count):
            print(json.dumps(dict(phase="write", items=header["item_count"],
                                  pages=header["page_count"]), sort_keys=True), flush=True)
    sealed = current.seal(
        header["ref"], binding, expected_generation=header["generation"],
        expected_items=count, request_id=f"seal-{name}")
    assert sealed["state"] == "SEALED"
    assert sealed["item_count"] == count and sealed["page_count"] >= calls
    spent = current.ledger(binding)["spent"]
    assert spent == {key: value * calls for key, value in APPEND_CHARGE.items()}
    return dict(header=sealed, encoded_bytes=encoded_bytes, pages=sealed["page_count"],
                append_calls=calls,
                digest=source_digest.hexdigest())


def _read_all(current, binding, expected, factory, *, progress=False):
    """Verify all actual values and order, retaining only the current page."""
    cursor, seen, pages, source_digest = 0, 0, 0, hashlib.sha256()
    # Authentication happens before the first public page.  Traversal then
    # stays in that same read-only SQL snapshot instead of revalidating the
    # whole collection for every page or retaining all pages in memory.
    with current.reader(expected["header"]["ref"], binding) as reader:
        while True:
            page = reader.page(after_page=cursor)
            pages += 1
            assert page["page_seq"] == pages
            assert page["manifest"]["state"] == "SEALED"
            assert page["manifest"]["item_count"] == expected["header"]["item_count"]
            assert page["items"]
            for item in page["items"]:
                assert item == factory(seen)
                source_digest.update(_encoded(item) + b"\n")
                seen += 1
            if progress and (pages % 64 == 0 or page["next_cursor"] is None):
                print(json.dumps(dict(phase="read", items=seen, pages=pages),
                                 sort_keys=True), flush=True)
            if page["next_cursor"] is None:
                break
            assert page["next_cursor"] == page["page_seq"] and page["next_cursor"] > cursor
            cursor = page["next_cursor"]
    assert seen == expected["header"]["item_count"]
    assert pages == expected["pages"]
    assert source_digest.hexdigest() == expected["digest"]
    return seen, pages


def _private_files(directory):
    """Hash incrementally; measuring this helper must not inflate read peaks."""
    result = {}
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        sha = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65_536), b""):
                sha.update(chunk)
        info = path.stat()
        result[str(path.relative_to(directory))] = (info.st_size, info.st_mtime_ns, sha.hexdigest())
    return result


@pytest.fixture(scope="module")
def large_collection(tmp_path_factory):
    state, root, legacy = _legacy_fixture(tmp_path_factory.mktemp("review-metadata-large"))
    old_row = _task_row(state, legacy["task_ref"])
    old_ledger = _encoded(state.get(legacy["task_ref"])["review_ledger"])
    binding, current = _binding(), _store(state, root)
    gc.collect()
    started = time.perf_counter()
    tracemalloc.start()
    try:
        written = _write(current, binding, name="units", count=1001, batch=12, factory=_unit)
        write_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return dict(state=state, root=root, legacy=legacy, old_row=old_row,
                old_ledger=old_ledger, binding=binding, written=written,
                write_peak=write_peak, write_seconds=time.perf_counter() - started)


def test_more_than_four_megabytes_reopens_and_returns_every_real_metadata_page(large_collection):
    sample = large_collection
    state, root, binding, written = (sample[key] for key in ("state", "root", "binding", "written"))
    assert written["encoded_bytes"] > MAX_RECORD_BYTES
    assert written["pages"] > 1 and written["header"]["item_count"] == 1001
    reopened = _store(state, root)
    assert reopened.manifest(written["header"]["ref"], binding) == written["header"]
    before_files = _private_files(state.path.parent)
    before_ledger = _encoded(reopened.ledger(binding))
    # Keep the conservative independent-page API covered alongside the efficient
    # full traversal.  A fresh instance must return the exact stored last page.
    last = _store(state, root).page(written["header"]["ref"], binding,
                                    after_page=written["pages"] - 1)
    assert last["next_cursor"] is None
    assert last["items"][-1] == _unit(1000)
    assert _read_all(reopened, binding, written, _unit) == (1001, written["pages"])
    assert _encoded(reopened.ledger(binding)) == before_ledger
    assert _private_files(state.path.parent) == before_files
    assert _task_row(state, sample["legacy"]["task_ref"]) == sample["old_row"]
    assert _encoded(state.get(sample["legacy"]["task_ref"])["review_ledger"]) == sample["old_ledger"]


def test_large_collection_write_and_page_reads_keep_small_python_allocations(large_collection):
    sample = large_collection
    state, root = sample["state"], sample["root"]
    current = _store(state, root)
    gc.collect()
    tracemalloc.start()
    try:
        _read_all(current, sample["binding"], sample["written"], _unit)
        read_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    # The collection contains >4.6 MB of encoded metadata and substantially
    # more decoded objects.  These bounds reject loading the entire collection;
    # they describe Python allocations, not SQLite native cache or process RSS.
    assert sample["write_peak"] < 3_000_000
    assert read_peak < 3_000_000
    print(json.dumps(dict(scope="internal-review-metadata-only", items=1001,
                          encoded_bytes=sample["written"]["encoded_bytes"],
                          pages=sample["written"]["pages"],
                          write_seconds=round(sample["write_seconds"], 3),
                          write_python_peak=sample["write_peak"], read_python_peak=read_peak),
                     sort_keys=True))


@pytest.mark.parametrize("capacity", [False, True], ids=["legacy-review", "legacy-capacity"])
def test_new_metadata_does_not_rewrite_old_signed_head_or_reset_old_allowances(tmp_path, capacity):
    state, root, legacy = _legacy_fixture(tmp_path, capacity=capacity)
    row = _task_row(state, legacy["task_ref"])
    before = state.get(legacy["task_ref"])
    old_ledger = _encoded(before["review_ledger"])
    assert before["review_ledger"]["total_bytes"] > 0
    binding, current = _binding(), _store(state, root)
    written = _write(current, binding, name="new-units", count=27, batch=3, factory=_unit)
    _read_all(_store(state, root), binding, written, _unit)
    after = state.get(legacy["task_ref"])
    assert _task_row(state, legacy["task_ref"]) == row
    assert after == before
    assert _encoded(after["review_ledger"]) == old_ledger
    assert after["review_ledger"]["limits"] == before["review_ledger"]["limits"]
    if capacity:
        assert after["review_capacity"]["status"] == "CAPACITY_REQUIRED"
    assert development_capabilities()["paged_review_storage"] is False


@pytest.mark.parametrize("missing_page", [2, 4], ids=["missing-middle", "missing-last"])
def test_deleted_middle_or_last_page_is_rejected_without_silent_completion(tmp_path, missing_page):
    state, root, legacy = _legacy_fixture(tmp_path)
    binding, current = _binding(), _store(state, root)
    written = _write(current, binding, name="complete-unit-set", count=12, batch=3, factory=_unit)
    assert written["pages"] == 4
    old_row = _task_row(state, legacy["task_ref"])
    with sqlite3.connect(state.path) as db:
        deleted = db.execute("DELETE FROM rm_pages WHERE ref=? AND page_seq=?",
                             (written["header"]["ref"], missing_page)).rowcount
    assert deleted == 1
    damaged = _private_files(state.path.parent)
    reopened = _store(state, root)

    def enter_reader():
        with reopened.reader(written["header"]["ref"], binding) as reader:
            reader.page(after_page=0)

    for operation in (
            lambda: reopened.manifest(written["header"]["ref"], binding),
            lambda: reopened.page(written["header"]["ref"], binding, after_page=0),
            lambda: reopened.page(written["header"]["ref"], binding, after_page=3),
            enter_reader):
        with pytest.raises(ReviewMetadataError) as caught:
            operation()
        assert caught.value.reason_code in {
            "REVIEW_METADATA_HISTORY_UNAVAILABLE", "REVIEW_METADATA_INVALID"}
    assert _private_files(state.path.parent) == damaged
    assert _task_row(state, legacy["task_ref"]) == old_row


def _scale_evidence(index):
    return dict(evidence_id=f"te3-{index:032x}", path=f"modules/source_{index:06d}.py",
                file_sha256=hashlib.sha256(str(index).encode()).hexdigest(),
                location_version="CURRENT_TASK_END", start_line=index + 1, end_line=index + 1,
                start_char=1, end_char=3, line_chars=8)


@pytest.mark.skipif(os.getenv(SCALE_ENV) != "1", reason=f"Opt in with {SCALE_ENV}=1; metadata foundation only")
def test_100000_real_metadata_items_write_reopen_and_page_with_default_quotas(tmp_path):
    budget = ReviewMetadataBudget()
    assert (budget.page_items, budget.page_bytes, budget.logical_bytes,
            budget.database_bytes, budget.journal_bytes) == (
                256, 65_536, 96_000_000, 128_000_000, 128_000_000)
    assert (budget.request_items, budget.request_bytes) == (4096, 1_048_576)
    state, root, legacy = _legacy_fixture(tmp_path)
    old_row = _task_row(state, legacy["task_ref"])
    old_ledger = _encoded(state.get(legacy["task_ref"])["review_ledger"])
    binding, current = _binding(), _store(state, root)
    count, started = 100_000, time.perf_counter()
    gc.collect()
    tracemalloc.start()
    try:
        written = _write(current, binding, name="issued-metadata", count=count, batch=128,
                         factory=_scale_evidence, progress=True)
        write_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    write_seconds = time.perf_counter() - started
    assert written["encoded_bytes"] > MAX_RECORD_BYTES
    gc.collect()
    read_started = time.perf_counter()
    tracemalloc.start()
    try:
        reopened = _store(state, root)
        before_ledger = _encoded(reopened.ledger(binding))
        seen, pages = _read_all(reopened, binding, written, _scale_evidence, progress=True)
        read_peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert seen == count
    assert _encoded(reopened.ledger(binding)) == before_ledger
    assert _task_row(state, legacy["task_ref"]) == old_row
    assert _encoded(state.get(legacy["task_ref"])["review_ledger"]) == old_ledger
    assert write_peak < 3_000_000 and read_peak < 3_000_000
    report = dict(scope="internal-review-metadata-only", source_files_created=0,
                  coordinator_enabled=False, items=seen, encoded_bytes=written["encoded_bytes"],
                  pages=pages, write_seconds=round(write_seconds, 3),
                  read_seconds=round(time.perf_counter() - read_started, 3),
                  elapsed_seconds=round(time.perf_counter() - started, 3),
                  write_python_peak=write_peak, read_python_peak=read_peak,
                  database_bytes=state.path.stat().st_size,
                  default_quotas_unchanged=True)
    print(json.dumps(report, sort_keys=True))

