"""Sealed byte-reader contracts on isolated SQLite stores.

These are opaque snapshot bytes, not a maps-pointer digest, source scanner,
native host claim, or a task-before reconstruction from the current tree.
"""
from contextlib import closing
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tracemalloc
from types import SimpleNamespace

import pytest

from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError


KEY = b"k" * 32
OWNER = dict(host="codex", session="a" * 64)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    store = SnapshotStore(tmp_path / "private", workspace_root=root, key=KEY)
    binding = SnapshotBinding("reader-task", OWNER, "opaque-source", 3)
    return SimpleNamespace(root=root, store=store, binding=binding, temporary=tmp_path)


def seal(store, binding, entries=None):
    entries = entries if entries is not None else [
        ("z.py", b"value=1\n", {"label": ["ordinary"]}),
        ("中文/乙.py", b"value=2\n", {}),
        ("a.py", b"value=3\n", {}),
        ("Z.py", b"value=4\n", {}),
        ("中文/甲.py", b"value=5\n", {}),
    ]
    ref = store.create(binding)["ref"]
    cursor = None
    for offset in range(0, len(entries), 2):
        next_cursor = str(offset + len(entries[offset:offset + 2]))
        store.append_page(ref, binding, entries[offset:offset + 2],
                          expected_cursor=cursor, cursor=next_cursor)
        cursor = next_cursor
    store.seal(ref, binding, expected_files=len(entries), inventory_complete=True)
    return ref, entries


def fingerprint(directory):
    """Names, bytes and relevant metadata; never follow links or open SQLite."""
    result = {}
    for current, directories, files in os.walk(directory, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in directories + files)]:
            info = path.lstat()
            value = dict(mode=stat.S_IMODE(info.st_mode), kind=stat.S_IFMT(info.st_mode),
                         device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                         links=info.st_nlink, size=info.st_size, mtime=info.st_mtime_ns)
            if stat.S_ISREG(info.st_mode):
                value["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            elif stat.S_ISLNK(info.st_mode):
                value["link"] = os.readlink(path)
            result[str(path.relative_to(directory))] = value
    return result


def rejected_open(store, ref, binding, reason):
    with pytest.raises(SnapshotStoreError) as error:
        with store.sealed_reader(ref, binding):
            pytest.fail("An invalid capture was exposed as a sealed reader")
    assert error.value.reason_code == reason


def test_binary_path_order_complete_tail_detached_metadata_and_readonly_bytes(sample):
    ref, entries = seal(sample.store, sample.binding)
    before = fingerprint(sample.temporary)
    expected = {name: body for name, body, _ in entries}
    paths, cursor = [], None
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        header = reader.header
        assert header["state"] == "SEALED" and header["coverage_complete"]
        assert header["binding"]["source_ref"] == "opaque-source"
        header["binding"]["owner"]["session"] = "b" * 64
        assert reader.header["binding"]["owner"] == OWNER
        while True:
            page = reader.entries_page(cursor=cursor, limit_items=2, limit_bytes=4096)
            assert 0 < len(page["entries"]) <= 2
            paths.extend(item["path"] for item in page["entries"])
            for item in page["entries"]:
                assert set(item) == {"ref", "seq", "path", "sha256", "size", "metadata"}
                assert item["ref"] == ref
                assert reader.read_content(item["path"]) == expected[item["path"]]
                original_metadata = reader.entry(item["path"])["metadata"]
                item["metadata"]["caller_only"] = True
                assert reader.entry(item["path"])["metadata"] == original_metadata
            if page["complete"]:
                assert page["next_cursor"] is None
                break
            assert isinstance(page["next_cursor"], str)
            assert page["next_cursor"] != cursor
            cursor = page["next_cursor"]
        item = reader.entry("z.py")
        item["metadata"]["label"].append("caller mutation")
        assert reader.entry("z.py")["metadata"] == {"label": ["ordinary"]}
        assert reader.entry(paths[-1])["path"] == paths[-1]
    assert paths == sorted(expected, key=lambda path: path.encode("utf-8"))
    assert len(paths) == len(set(paths)) == 5
    assert fingerprint(sample.temporary) == before


def test_empty_complete_seal_is_distinct_from_missing_history(sample):
    ref = sample.store.create(sample.binding)["ref"]
    sample.store.seal(ref, sample.binding, expected_files=0, inventory_complete=True)
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        assert reader.header["entry_count"] == 0
        assert reader.entries_page() == dict(entries=[], next_cursor=None, complete=True)
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_HISTORY_UNAVAILABLE$"):
            reader.entry("missing.py")


@pytest.mark.parametrize("state", ["CAPTURING", "WAITING_CAPACITY", "SEALED_GAP", "SEALED_UNKNOWN"])
def test_only_complete_sealed_capture_can_open(sample, state):
    current = sample.store
    if state == "WAITING_CAPACITY":
        current = SnapshotStore(current.directory, workspace_root=sample.root, key=KEY,
                                max_storage_bytes=80_000)
    ref = current.create(sample.binding)["ref"]
    current.append_page(ref, sample.binding, [("a.py", b"value=1")],
                        expected_cursor=None, cursor="one")
    if state == "WAITING_CAPACITY":
        assert current.append_page(ref, sample.binding, [("b.py", b"x" * 100_000)],
            expected_cursor="one", cursor="two")["state"] == state
    elif state.startswith("SEALED"):
        current.seal(ref, sample.binding,
                     expected_files=1 if state == "SEALED_GAP" else None,
                     inventory_complete=state == "SEALED_GAP",
                     gap_count=1 if state == "SEALED_GAP" else 0)
    before = fingerprint(sample.temporary)
    rejected_open(current, ref, sample.binding, "SNAPSHOT_COVERAGE_INCOMPLETE"
                  if state.startswith("SEALED") else "SNAPSHOT_NOT_SEALED")
    assert fingerprint(sample.temporary) == before


@pytest.mark.parametrize("change", [dict(owner=dict(host="cursor", session="b" * 64)),
                                     dict(source_ref="other-source"), dict(task_ref="other-task")])
def test_wrong_binding_is_readonly_and_never_adopted(sample, change):
    ref, _ = seal(sample.store, sample.binding)
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, replace(sample.binding, **change), "SNAPSHOT_BINDING_MISMATCH")
    assert fingerprint(sample.temporary) == before


def test_cursor_is_opaque_bound_to_capture_and_accepts_valid_budget_changes(sample):
    first, _ = seal(sample.store, sample.binding)
    other_binding = replace(sample.binding, task_ref="second-task", source_ref="second-source",
                            owner=dict(host="cursor", session="b" * 64))
    second, _ = seal(sample.store, other_binding)
    with sample.store.sealed_reader(first, sample.binding) as reader:
        token = reader.entries_page(limit_items=2, limit_bytes=4096)["next_cursor"]
        for invalid in ("not-a-cursor", token[:-1], token + "x"):
            with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_CURSOR_INVALID$"):
                reader.entries_page(cursor=invalid, limit_items=2, limit_bytes=4096)
        smaller = reader.entries_page(cursor=token, limit_items=1, limit_bytes=8192)
        assert [item["path"] for item in smaller["entries"]] == ["z.py"]
        for options in (dict(limit_items=0, limit_bytes=4096), dict(limit_items=True, limit_bytes=4096),
                        dict(limit_items=2, limit_bytes=0), dict(limit_items=2, limit_bytes=False)):
            with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_PAGE_REQUEST_INVALID$"):
                reader.entries_page(cursor=token, **options)
    with sample.store.sealed_reader(second, other_binding) as reader:
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_CURSOR_INVALID$"):
            reader.entries_page(cursor=token, limit_items=2, limit_bytes=4096)
    with sample.store.sealed_reader(first, sample.binding) as reopened:
        assert reopened.entries_page(cursor=token, limit_items=1)["entries"][0]["path"] == "z.py"


def test_one_metadata_item_cannot_be_silently_cut_to_fit_response(sample):
    ref, _ = seal(sample.store, sample.binding)
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_PAGE_BYTE_BUDGET$"):
            reader.entries_page(limit_items=1, limit_bytes=1)
        for value in (0, -1, False, "65536"):
            with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_PAGE_REQUEST_INVALID$"):
                reader.read_content("a.py", max_bytes=value)


def test_closed_reader_cannot_reuse_header_entry_page_or_body(sample):
    ref, _ = seal(sample.store, sample.binding)
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        assert reader.entry("a.py")["path"] == "a.py"
    for operation in (lambda: reader.header, lambda: reader.entry("a.py"),
                      lambda: reader.entries_page(), lambda: reader.read_content("a.py")):
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_READER_CLOSED$"):
            operation()


@pytest.mark.parametrize("corruption", ["indexed_path", "indexed_seq", "entry_mac", "capture_mac", "capture_task"])
def test_authenticated_sql_indexes_and_mac_are_checked_before_open(sample, corruption):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        if corruption == "indexed_path":
            db.execute("UPDATE entries SET path='other.py' WHERE ref=? AND seq=1", (ref,))
        elif corruption == "indexed_seq":
            db.execute("UPDATE entries SET seq=99 WHERE ref=? AND seq=1", (ref,))
        elif corruption == "entry_mac":
            db.execute("UPDATE entries SET mac=? WHERE ref=? AND seq=1", ("0" * 64, ref))
        elif corruption == "capture_mac":
            db.execute("UPDATE captures SET mac=? WHERE ref=?", ("0" * 64, ref))
        else:
            db.execute("UPDATE captures SET task='foreign-index' WHERE ref=?", (ref,))
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_RECORD_INVALID")
    assert fingerprint(sample.temporary) == before


@pytest.mark.parametrize("missing", ["middle", "tail", "object"])
def test_missing_original_member_or_object_is_rejected_at_reader_open(sample, missing):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        if missing == "object":
            db.execute("DELETE FROM objects WHERE hash=?", (hashlib.sha256(b"value=1\n").hexdigest(),))
        else:
            db.execute("DELETE FROM entries WHERE ref=? AND seq=?", (ref, 3 if missing == "middle" else 5))
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_HISTORY_UNAVAILABLE")
    assert fingerprint(sample.temporary) == before


def test_corrupt_same_length_body_is_hashed_only_on_explicit_read(sample):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        db.execute("UPDATE objects SET body=? WHERE hash=?",
                   (b"value=9\n", hashlib.sha256(b"value=1\n").hexdigest()))
    before = fingerprint(sample.temporary)
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        assert reader.entry("z.py")["size"] == 8
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_CONTENT_UNAVAILABLE$"):
            reader.read_content("z.py")
    assert fingerprint(sample.temporary) == before


def test_only_bound_paths_can_read_objects_not_foreign_entries_or_bare_sha(sample):
    ref, _ = seal(sample.store, sample.binding)
    other = replace(sample.binding, task_ref="foreign-task", source_ref="foreign-source")
    other_ref, _ = seal(sample.store, other, [("foreign.py", b"value=2\n", {})])
    with sample.store.sealed_reader(other_ref, other) as foreign:
        foreign_entry = foreign.entry("foreign.py")
    with sample.store.sealed_reader(ref, sample.binding) as reader:
        for name in ("foreign.py", foreign_entry["sha256"]):
            with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_HISTORY_UNAVAILABLE$"):
                reader.read_content(name)
        # Authority comes from the bound path lookup, never a caller-supplied
        # entry with a shared object hash and an otherwise plausible ref.
        with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_PAGE_REQUEST_INVALID$"):
            reader.read_content(dict(foreign_entry, ref=ref, path="z.py"))
        assert reader.read_content("z.py") == b"value=1\n"


@pytest.mark.parametrize("table", ["captures", "entries"])
def test_oversized_sql_blob_is_rejected_without_loading_it_into_python(sample, table):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        db.execute(f"UPDATE {table} SET data=zeroblob(8000000) WHERE ref=?"
                   + (" AND seq=1" if table == "entries" else ""), (ref,))
    before = fingerprint(sample.temporary)
    tracemalloc.start()
    try:
        rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_RECORD_INVALID")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2_000_000, f"Corrupt 8MB SQL value was materialized: Python peak={peak}"
    assert fingerprint(sample.temporary) == before


@pytest.mark.parametrize("condition", ["absent", "missing_db", "missing_marker", "wrong_key", "wrong_root", "bad_marker"])
def test_readonly_missing_or_invalid_storage_never_initializes_or_repairs(sample, condition):
    if condition == "absent":
        ref = "ws2-" + "b" * 32
        reason = "SNAPSHOT_HISTORY_UNAVAILABLE"
    else:
        ref, _ = seal(sample.store, sample.binding)
        reason = "SNAPSHOT_KEY_OR_WORKSPACE_MISMATCH"
        if condition == "missing_db":
            sample.store.path.unlink()
            reason = "SNAPSHOT_HISTORY_UNAVAILABLE"
        elif condition == "missing_marker":
            sample.store.marker.unlink()
            reason = "SNAPSHOT_HISTORY_UNAVAILABLE"
        elif condition == "wrong_key":
            sample.store = SnapshotStore(sample.store.directory, workspace_root=sample.root, key=b"z" * 32)
        elif condition == "wrong_root":
            root = sample.temporary / "different-root"
            root.mkdir()
            sample.store = SnapshotStore(sample.store.directory, workspace_root=root, key=KEY)
        elif condition == "bad_marker":
            sample.store.marker.write_bytes(b"broken")
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, sample.binding, reason)
    assert fingerprint(sample.temporary) == before


HOT_JOURNAL_CHILD = r"""
import os,sqlite3,sys
db=sqlite3.connect(sys.argv[1])
db.execute('PRAGMA cache_size=1')
db.execute('PRAGMA synchronous=FULL')
db.execute('BEGIN IMMEDIATE')
db.execute("UPDATE objects SET body=?",(b'2'*131072,))
os._exit(37)
"""


def test_hot_rollback_journal_is_rejected_before_sqlite_can_recover_it(sample):
    ref, _ = seal(sample.store, sample.binding, [("large.py", b"1" * 131072, {})])
    child = subprocess.run([sys.executable, "-I", "-B", "-c", HOT_JOURNAL_CHILD,
                            str(sample.store.path)], capture_output=True, text=True, timeout=15)
    assert child.returncode == 37, child.stderr
    journal = Path(str(sample.store.path) + "-journal")
    assert journal.stat().st_size > 512 and journal.read_bytes()[:8] != b"\0" * 8
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_READER_JOURNAL_BUSY")
    assert fingerprint(sample.temporary) == before


def test_persisted_wal_header_is_explicitly_unsupported_and_zero_write(sample):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    for suffix in ("-wal", "-shm"):
        assert not Path(str(sample.store.path) + suffix).exists()
    before = fingerprint(sample.temporary)
    rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_READER_UNSUPPORTED_JOURNAL")
    assert fingerprint(sample.temporary) == before


def test_wal_switch_between_preflight_and_native_connect_creates_no_reader_sidecars(sample, monkeypatch):
    """The test writer changes the DB; compare only after that real commit."""
    import security_runtime.snapshot_reader as reader_module

    ref, _ = seal(sample.store, sample.binding)
    native_connect = sqlite3.connect
    checkpoints, reader_sidecars = [], []

    def sidecars():
        return [suffix for suffix in ("-wal", "-shm")
                if Path(str(sample.store.path) + suffix).exists()]

    class ObservedConnection:
        """Forward real SQLite calls and observe transient file creation too."""
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, *args, **kwargs):
            try:
                return self.connection.execute(*args, **kwargs)
            finally:
                reader_sidecars.extend(sidecars())

    def switched_connect(database, *args, **kwargs):
        if not checkpoints and str(database) == sample.store.path.as_uri() + "?mode=ro":
            # Preflight saw rollback mode. A real separate writer switches
            # journal mode immediately before the reader's native connect.
            with closing(native_connect(sample.store.path)) as writer, writer:
                assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
            assert sample.store.path.read_bytes()[18:20] == b"\x02\x02"
            assert sidecars() == []
            checkpoints.append(fingerprint(sample.temporary))
            connection = native_connect(database, *args, **kwargs)
            reader_sidecars.extend(sidecars())
            return ObservedConnection(connection)
        return native_connect(database, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(reader_module.sqlite3, "connect", switched_connect)
        rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_READER_UNSUPPORTED_JOURNAL")
    assert checkpoints, "The actual native readonly-connect boundary was not reached"
    assert reader_sidecars == [], "The reader created WAL sidecars, even if later removed"
    assert fingerprint(sample.temporary) == checkpoints[0]


def test_oversized_sql_sequence_index_is_rejected_without_python_materialization(sample):
    ref, _ = seal(sample.store, sample.binding)
    with closing(sqlite3.connect(sample.store.path)) as db, db:
        db.execute("UPDATE entries SET seq=zeroblob(8000000) WHERE ref=? AND seq=1", (ref,))
    before = fingerprint(sample.temporary)
    tracemalloc.start()
    try:
        rejected_open(sample.store, ref, sample.binding, "SNAPSHOT_RECORD_INVALID")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2_000_000, f"Corrupt 8MB SQL index was materialized: Python peak={peak}"
    assert fingerprint(sample.temporary) == before
