"""Raw sealed-store acceptance; no task pointer, live capture, host or scanner.

The scale cases create every ordinary source file and ingest its original bytes.
Reader memory measurements start after file creation and capture have finished.
"""
import gc
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import tracemalloc

try:
    import resource
except ImportError:  # No POSIX process high-water counter on Windows.
    resource = None

import pytest

import security_runtime
from security_runtime.snapshot_contract import CaptureBatchBudget
from security_runtime.snapshot_store import (
    SnapshotBinding, SnapshotStore, SnapshotStoreError, TASK_PAGES_GC_DOMAIN,
)


KEY = b"s" * 32
OWNER = dict(host="codex", session="c" * 64)
PACKAGE_PARENT = str(Path(security_runtime.__file__).resolve().parent.parent)


def _name(index):
    return f"files/file_{index:05d}.py"


def _raw(index):
    return f"# sealed raw source {index}\nvalue = {index}\n".encode()


def _new_store(tmp_path, **kwargs):
    root = tmp_path / "source"
    root.mkdir()
    store = SnapshotStore(tmp_path / "private", workspace_root=root, key=KEY, **kwargs)
    binding = SnapshotBinding("raw-reader-task", OWNER, "raw-reader-source", 3,
                              retention_domain=TASK_PAGES_GC_DOMAIN)
    return store, binding


def _seal(store, binding, entries):
    header = store.create(binding)
    header = store.append_page(header["ref"], binding, entries,
                               expected_cursor=None, cursor="source-complete")
    assert header["state"] == "CAPTURING"
    return store.seal(header["ref"], binding, expected_files=len(entries),
                      inventory_complete=True)["ref"]


def _tables(store):
    with sqlite3.connect(store.path) as db:
        return {table: db.execute("SELECT * FROM " + table + " ORDER BY rowid").fetchall()
                for table in ("captures", "entries", "objects", "usage")}


def _measured(operation):
    gc.collect()
    assert not tracemalloc.is_tracing()
    tracemalloc.start()
    started = time.perf_counter()
    try:
        result = operation()
        current, peak = tracemalloc.get_traced_memory()
        return result, dict(seconds=time.perf_counter() - started,
                            python_current_bytes=current, python_peak_bytes=peak)
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("count", [1001, pytest.param(10001, marks=pytest.mark.skipif(
    os.getenv("SECURITY_RUNTIME_SNAPSHOT_READER_SCALE_TEST") != "1",
    reason="Opt in with SECURITY_RUNTIME_SNAPSHOT_READER_SCALE_TEST=1; real 10001 raw files",
))])
def test_real_files_all_paths_and_original_bodies_cross_pages_and_reopen(tmp_path, count):
    store, binding = _new_store(tmp_path, batch_budget=CaptureBatchBudget(files=128))
    (store.root / "files").mkdir()
    started = time.perf_counter()
    for index in range(count):
        (store.root / _name(index)).write_bytes(_raw(index))
    create_seconds = time.perf_counter() - started
    started = time.perf_counter()
    header = store.create(binding)
    ref, cursor, writes = header["ref"], None, 0
    for offset in range(0, count, 128):
        stop = min(offset + 128, count)
        # The seq order deliberately differs from the required BINARY path order.
        entries = [(_name(index), (store.root / _name(index)).read_bytes(),
                    {"raw_sha256": hashlib.sha256(_raw(index)).hexdigest()})
                   for index in reversed(range(offset, stop))]
        header = store.append_page(ref, binding, entries, expected_cursor=cursor,
                                   cursor=f"captured-{stop}")
        assert header["state"] == "CAPTURING" and header["entry_count"] == stop
        cursor = header["cursor"]
        writes += 1
    sealed = store.seal(ref, binding, expected_files=count, inventory_complete=True)
    capture_seconds = time.perf_counter() - started
    assert sealed["coverage_complete"] and sealed["state"] == "SEALED"
    assert sealed["binding"]["consistency"] == "OBSERVED_ONLY"
    assert not sealed["binding"]["captured_before_edit"]
    assert store.quota == store.database_quota == 128_000_000

    (store.root / _name(0)).write_bytes(b"edited after sealing\n")
    (store.root / _name(count - 1)).unlink()
    reopened = SnapshotStore(store.directory, workspace_root=store.root, key=KEY)

    def traverse():
        seen, pages, digest, cursor = 0, 0, hashlib.sha256(), None
        with reopened.sealed_reader(ref, binding) as reader:
            assert reader.header == sealed
            while True:
                page = reader.entries_page(cursor=cursor, limit_items=128, limit_bytes=65536)
                assert page["entries"]
                if not pages:
                    assert page["entries"][0]["seq"] != 1
                for entry in page["entries"]:
                    assert entry["path"] == _name(seen)
                    expected_hash = hashlib.sha256(_raw(seen)).hexdigest()
                    assert entry["sha256"] == entry["metadata"]["raw_sha256"] == expected_hash
                    assert entry["size"] == len(_raw(seen))
                    digest.update(entry["path"].encode() + entry["sha256"].encode())
                    seen += 1
                pages += 1
                if page["complete"]:
                    assert page["next_cursor"] is None
                    break
                assert page["next_cursor"] and page["next_cursor"] != cursor
                cursor = page["next_cursor"]
            assert reader.entry(_name(count - 1))["path"] == _name(count - 1)
        return dict(entries=seen, pages=pages, digest=digest.hexdigest())

    traversal, reader_metrics = _measured(traverse)
    assert traversal["entries"] == count
    assert traversal["pages"] == (count + 127) // 128

    def bodies():
        seen, digest = 0, hashlib.sha256()
        with reopened.sealed_reader(ref, binding) as reader:
            for index in range(count):
                raw = reader.read_content(_name(index), max_bytes=1024)
                assert raw == _raw(index)
                digest.update(_name(index).encode() + hashlib.sha256(raw).hexdigest().encode())
                seen += 1
        return dict(entries=seen, digest=digest.hexdigest())

    all_bodies, object_metrics = _measured(bodies)
    assert all_bodies["entries"] == count
    assert all_bodies["digest"] == traversal["digest"]
    # A hydrated 10001-entry inventory cannot hide within a one-page allowance.
    assert reader_metrics["python_peak_bytes"] < 4_000_000
    assert object_metrics["python_peak_bytes"] < 4_000_000
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM entries WHERE ref=?", (ref,)).fetchone()[0] == count
    assert store.path.stat().st_size <= store.database_quota
    rss_native = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource else None
    print(json.dumps(dict(scope="raw-snapshot-store-real-files-only", files=count,
        create_seconds=create_seconds, capture_seconds=capture_seconds, write_pages=writes,
        reader=reader_metrics, per_object=object_metrics, all_paths_and_bodies_verified=True,
        database_bytes=store.path.stat().st_size, database_quota=128_000_000,
        process_peak_rss_bytes=(None if rss_native is None else
            rss_native if sys.platform == "darwin" else rss_native * 1024),
        rss_scope="whole-process-high-water-including-fixture-not-reader-only",
        task_typed_pointer_or_preimage_or_host_coverage=False), sort_keys=True))


def test_original_large_body_budget_is_rejected_before_object_sql(tmp_path, monkeypatch):
    store, binding = _new_store(tmp_path)
    raw = b"large original body\n" * 8192
    ref = _seal(store, binding, [("large.py", raw)])
    connect, statements = sqlite3.connect, []

    def observe(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", observe)
    with store.sealed_reader(ref, binding) as reader:
        statements.clear()
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_CONTENT_BYTE_BUDGET$"):
            reader.read_content("large.py", max_bytes=1024)
        assert not any("objects" in sql.lower() for sql in statements)
        for invalid in (0, True, 8_000_001):
            statements.clear()
            with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_PAGE_REQUEST_INVALID$"):
                reader.read_content("large.py", max_bytes=invalid)
            assert statements == []
        assert reader.read_content("large.py", max_bytes=len(raw)) == raw


COLLECT_CHILD = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from security_runtime.snapshot_store import SnapshotStore,SnapshotStoreError
store=SnapshotStore(sys.argv[2],workspace_root=sys.argv[3],key=b's'*32)
original=store._set_usage
def after_deletes(db,used):
    assert db.execute('SELECT count(*) FROM captures').fetchone()[0]==0
    assert db.execute('SELECT count(*) FROM entries').fetchone()[0]==0
    print(json.dumps(dict(stage='DELETES_EXECUTED')),flush=True)
    return original(db,used)
store._set_usage=after_deletes
try:
    result=store.collect_unreferenced(set())
except SnapshotStoreError as error:
    print(json.dumps(dict(reason=error.reason_code)),flush=True)
else:
    print(json.dumps(dict(result=result)),flush=True)
'''


def test_read_transaction_blocks_real_gc_commit_and_preserves_all_original_rows(tmp_path, monkeypatch):
    store, binding = _new_store(tmp_path)
    ref = _seal(store, binding, [("z.py", b"original z"), ("a.py", b"original a")])
    before = _tables(store)
    connect, connections = sqlite3.connect, []

    def observe(*args, **kwargs):
        db = connect(*args, **kwargs)
        connections.append(db)
        return db

    monkeypatch.setattr(sqlite3, "connect", observe)
    with store.sealed_reader(ref, binding) as reader:
        assert len(connections) == 1 and connections[0].in_transaction
        active = connections[0]
        first = reader.entries_page(limit_items=1)
        assert first["entries"][0]["path"] == "a.py" and not first["complete"]
        child = subprocess.run([sys.executable, "-I", "-B", "-c", COLLECT_CHILD,
            PACKAGE_PARENT, str(store.directory), str(store.root)],
            capture_output=True, text=True, cwd=tmp_path, timeout=10)
        assert child.returncode == 0, child.stderr
        assert [json.loads(line) for line in child.stdout.splitlines()] == [
            dict(stage="DELETES_EXECUTED"), dict(reason="SNAPSHOT_STORAGE_UNAVAILABLE")]
        assert _tables(store) == before
        assert active.in_transaction
        tail = reader.entries_page(cursor=first["next_cursor"], limit_items=1)
        assert tail["complete"] and tail["entries"][0]["path"] == "z.py"
        assert reader.read_content("a.py") == b"original a"
        assert reader.read_content("z.py") == b"original z"
    with pytest.raises(sqlite3.ProgrammingError):
        active.execute("SELECT 1")
    result = store.collect_unreferenced(set())
    assert result["collected_captures"] == 1 and result["logical_bytes_after"] == 0


def test_exception_exit_closes_actual_connection_and_releases_gc_lock(tmp_path, monkeypatch):
    store, binding = _new_store(tmp_path)
    ref = _seal(store, binding, [("one.py", b"original")])
    connect, connections = sqlite3.connect, []

    def observe(*args, **kwargs):
        db = connect(*args, **kwargs)
        connections.append(db)
        return db

    monkeypatch.setattr(sqlite3, "connect", observe)
    with pytest.raises(RuntimeError, match="explicit reader caller failure"):
        with store.sealed_reader(ref, binding) as reader:
            assert reader.read_content("one.py") == b"original"
            assert len(connections) == 1 and connections[0].in_transaction
            active = connections[0]
            raise RuntimeError("explicit reader caller failure")
    with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_READER_CLOSED$"):
        reader.entry("one.py")
    with pytest.raises(sqlite3.ProgrammingError):
        active.execute("SELECT 1")
    assert store.collect_unreferenced(set())["collected_captures"] == 1


def test_active_reader_rejects_replaced_root_without_using_live_replacement(tmp_path):
    store, binding = _new_store(tmp_path)
    ref = _seal(store, binding, [("one.py", b"sealed original")])
    moved = tmp_path / "original-source"
    with store.sealed_reader(ref, binding) as reader:
        store.root.rename(moved)
        store.root.mkdir()
        (store.root / "one.py").write_bytes(b"replacement must not become history")
        try:
            for operation in (lambda: reader.entries_page(), lambda: reader.entry("one.py"),
                              lambda: reader.read_content("one.py")):
                with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_ROOT_REPLACED$"):
                    operation()
        finally:
            (store.root / "one.py").unlink()
            store.root.rmdir()
            moved.rename(store.root)
        assert reader.read_content("one.py") == b"sealed original"


READER_CHILD = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from security_runtime.snapshot_store import SnapshotStore,SnapshotBinding
from security_runtime.snapshot_contract import SourceConsistency
store=SnapshotStore(sys.argv[2],workspace_root=sys.argv[3],key=b's'*32)
payload=json.loads(sys.argv[5])
payload['consistency']=SourceConsistency(payload['consistency'])
binding=SnapshotBinding(**payload)
with store.sealed_reader(sys.argv[4],binding) as reader:
    assert reader.read_content('one.py')==b'original'
    print('READER_READY',flush=True)
    sys.stdin.readline()
print('READER_CLOSED',flush=True)
'''


@pytest.mark.parametrize("exit_kind", ["normal", "terminate"])
@pytest.mark.skipif(os.name == "nt", reason="Real POSIX pipe/select/process lifecycle")
def test_real_reader_process_exit_releases_held_snapshot_lock(tmp_path, exit_kind):
    import select

    store, binding = _new_store(tmp_path)
    ref = _seal(store, binding, [("one.py", b"original")])
    before = _tables(store)
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", READER_CHILD,
        PACKAGE_PARENT, str(store.directory), str(store.root), ref, json.dumps(dict(
            task_ref=binding.task_ref, owner=dict(binding.owner), source_ref=binding.source_ref,
            representation_version=binding.representation_version,
            kind=binding.kind, consistency=binding.consistency,
            captured_before_edit=binding.captured_before_edit,
            retention_domain=binding.retention_domain))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=tmp_path)
    try:
        readable, _, _ = select.select([child.stdout], [], [], 5)
        assert readable and child.stdout.readline().strip() == "READER_READY"
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_STORAGE_UNAVAILABLE$"):
            store.collect_unreferenced(set())
        assert _tables(store) == before
        if exit_kind == "terminate":
            child.terminate()
            child.communicate(timeout=5)
            assert child.returncode != 0
        else:
            output, error = child.communicate("close\n", timeout=5)
            assert child.returncode == 0, error
            assert output.strip() == "READER_CLOSED"
        assert store.collect_unreferenced(set())["collected_captures"] == 1
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)
