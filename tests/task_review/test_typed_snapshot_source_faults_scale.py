"""Typed metadata verification against real raw pages and private scratch.

No Runtime task, scanner, frozen-body locator, plan or host routing is invoked.
The source fixtures and canonical oracle are built before reader tracing starts.
"""
from dataclasses import asdict
import builtins
import gc
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import time
import tracemalloc

import pytest

import security_runtime
from security_runtime.closeout_state import encode
from security_runtime.snapshot_contract import development_capabilities
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore
from security_runtime.task_review.snapshot_source import (
    TypedSnapshotSource, TypedSnapshotSourceError, TypedSourceBudget,
)
from paged_review_source_helpers import pack_review_sources
from test_paged_review_transactions import (
    CHARGE, _assert_legacy_unchanged, _create, _head, _metadata, _mutate, _sample,
)


pytestmark = pytest.mark.skipif(os.name == "nt", reason="Real POSIX private scratch and process lifecycle")
PACKAGE_PARENT = str(Path(security_runtime.__file__).resolve().parent.parent)
SCALE_ENV = "SECURITY_RUNTIME_TYPED_SOURCE_SCALE_TEST"
JOB_NAME = "typed-source-v1.job"


def _name(index):
    return f"modules/record_{index:05d}.py"


def _maps(index, text_size=0):
    text = f"frozen_value = {index}" + "x" * text_size
    return dict(hashes=hashlib.sha256(text.encode()).hexdigest(),
                texts=[text], line_counts=1)


def _fingerprint(directory):
    return {str(path.relative_to(directory)): (stat.S_IMODE(path.stat().st_mode),
        path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
        for path in directory.rglob("*") if path.is_file()}


def _sample_source(tmp_path, count=17, text_size=0):
    sample = _sample(tmp_path, capacity=True)
    names = [_name(index) for index in range(count)]
    maps = {key: {} for key in ("hashes", "texts", "line_counts", "preimages",
                               "text_truncations", "text_unavailable")}
    for index, name in enumerate(names):
        for key, value in _maps(index, text_size).items():
            maps[key][name] = value
    lists = dict(inventory=names, read_priority=list(reversed(names)))
    sample.template["end"] = dict(**maps, **lists, redaction_version=3,
                                   inventory_complete=True)
    sample.sources = pack_review_sources(sample.state, sample.template)
    _create(sample)
    audit = _mutate(sample, dict(kind="create", name="typed-source-audit"), "audit-create")
    _mutate(sample, dict(kind="append", ref=audit["metadata"]["ref"],
                        items=[dict(event="real original nonzero charge")]),
            "audit-charge", charge=dict(CHARGE))
    sample.original_head = _head(sample)
    sample.original_ledger = _metadata(sample).ledger(sample.binding)
    assert sample.original_ledger["spent"] == CHARGE
    assert sample.state.get(sample.legacy["task_ref"])["review_ledger"]["total_bytes"] > 0
    sample.raw = SnapshotStore(sample.state.path.parent / "snapshot-pages",
                               workspace_root=sample.root, key=sample.state.key())
    sample.pointer = sample.sources["end"]["paged_entries"]
    sample.canonical = hashlib.sha256(encode(dict(maps=maps, lists=lists))).hexdigest()
    assert sample.pointer["source"] == sample.canonical
    sample.count, sample.text_size = count, text_size
    sample.scratch = tmp_path / "private-scratch"
    sample.scratch.mkdir(mode=0o700)
    sample.keep = sample.scratch / "caller-file.txt"
    sample.keep.write_bytes(b"caller-owned bytes must survive every attempt")
    sample.keep.chmod(0o640)
    sample.original_state = _fingerprint(sample.state.path.parent)
    return sample


def _source(sample, budget=None):
    return TypedSnapshotSource(sample.raw, sample.pointer, review_binding=sample.binding,
        field="end", scratch_directory=sample.scratch,
        budget=budget or TypedSourceBudget())


def _preserved(sample):
    assert _fingerprint(sample.state.path.parent) == sample.original_state
    assert _head(sample) == sample.original_head
    assert _metadata(sample).ledger(sample.binding) == sample.original_ledger
    _assert_legacy_unchanged(sample)
    assert sample.keep.read_bytes() == b"caller-owned bytes must survive every attempt"
    assert stat.S_IMODE(sample.keep.stat().st_mode) == 0o640
    assert stat.S_IMODE(sample.scratch.stat().st_mode) == 0o700


def _clean_slot(sample):
    assert not (sample.scratch / JOB_NAME).exists()
    for path in sample.scratch.iterdir():
        if path != sample.keep:
            assert path.is_file() and not path.is_symlink()
            assert stat.S_IMODE(path.stat().st_mode) == 0o600


def _private_slot(sample, budget):
    job = sample.scratch / JOB_NAME
    assert job.is_dir() and not job.is_symlink()
    assert stat.S_IMODE(job.stat().st_mode) == 0o700
    size = 0
    for path in job.rglob("*"):
        assert not path.is_symlink()
        if path.is_file():
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            size += path.stat().st_size
    assert 0 < size <= budget.scratch_bytes
    return size


def _same_source_recovers(sample):
    with _source(sample) as recovered:
        assert recovered.summary["source_digest_verified"] is True
        assert recovered.entry(_name(sample.count - 1))["maps"] == _maps(
            sample.count - 1, sample.text_size)
    _clean_slot(sample)
    _preserved(sample)


@pytest.mark.parametrize("count", [1001, pytest.param(10001, marks=pytest.mark.skipif(
    os.getenv(SCALE_ENV) != "1", reason=f"Opt in with {SCALE_ENV}=1; actual 10001 typed records",
))])
def test_complete_canonical_recomputation_and_all_original_typed_pages(tmp_path, monkeypatch, count):
    started = time.perf_counter()
    sample = _sample_source(tmp_path, count)
    fixture_seconds = time.perf_counter() - started
    budget = TypedSourceBudget(elapsed_seconds=600 if count == 10001 else 120)
    # No current source file is needed. Make even an attempted live read fail.
    def forbidden_live(*args, **kwargs):
        raise AssertionError("Typed metadata must not read the live workspace")
    from security_runtime.local_evidence import WorkspaceReader
    monkeypatch.setattr(WorkspaceReader, "read", forbidden_live)
    def guard_file_open(original):
        def guarded(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(path)).absolute()
                if candidate != sample.root and candidate.is_relative_to(sample.root):
                    forbidden_live()
            return original(path, *args, **kwargs)
        return guarded
    monkeypatch.setattr(builtins, "open", guard_file_open(builtins.open))
    monkeypatch.setattr(io, "open", guard_file_open(io.open))
    monkeypatch.setattr(os, "open", guard_file_open(os.open))
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    try:
        source = _source(sample, budget)
        with source as reader:
            summary = reader.summary
            assert summary["state"] == "VERIFIED" and summary["source_digest_verified"] is True
            assert summary["entry_count"] == count
            assert summary["map_counts"] == dict(hashes=count, texts=count, line_counts=count,
                preimages=0, text_truncations=0, text_unavailable=0)
            assert summary["list_counts"] == dict(inventory=count, read_priority=count)
            assert summary["project_coverage"] == "UNKNOWN"
            assert summary["external_bodies_available"] is False
            scratch_bytes = _private_slot(sample, budget)
            seen, pages, cursor, digest = 0, 0, None, hashlib.sha256()
            while True:
                page = reader.entries_page(cursor=cursor, limit_items=128, limit_bytes=65536)
                assert page["entries"]
                for entry in page["entries"]:
                    assert entry == dict(path=_name(seen), maps=_maps(seen),
                        positions=dict(inventory=seen, read_priority=count - seen - 1))
                    digest.update(encode(entry) + b"\n")
                    seen += 1
                pages += 1
                if page["complete"]:
                    assert page["next_cursor"] is None
                    break
                assert page["next_cursor"] and page["next_cursor"] != cursor
                cursor = page["next_cursor"]
            assert seen == count and pages == (count + 127) // 128
            assert reader.entry(_name(count - 1)) == dict(path=_name(count - 1),
                maps=_maps(count - 1), positions=dict(inventory=count - 1, read_priority=0))
            assert reader.entry("missing.py") is None
        _, peak = tracemalloc.get_traced_memory()
        elapsed = time.perf_counter() - started
    finally:
        tracemalloc.stop()
    assert peak < 4_000_000
    _clean_slot(sample)
    _preserved(sample)
    assert development_capabilities()["paged_review_storage"] is False
    print(json.dumps(dict(scope="internal-typed-snapshot-metadata-only", records=count,
        fixture_seconds=fixture_seconds, verification_and_pages_seconds=elapsed,
        python_peak_bytes=peak, source_digest=sample.canonical,
        complete_canonical_recomputed=True, all_original_maps_verified=True,
        scratch_bytes_observed=scratch_bytes, raw_database_bytes=sample.raw.path.stat().st_size,
        budget=asdict(budget), elapsed_policy_is_default=count != 10001,
        measurement="tracemalloc includes context open/full verification/traversal/cleanup; excludes fixture capture",
        task_head_and_both_ledgers_unchanged=True, production_routing_enabled=False), sort_keys=True))


def test_real_sqlite_full_cleans_only_registered_scratch_and_preserves_sources(tmp_path, monkeypatch):
    sample = _sample_source(tmp_path, 8, text_size=32768)
    connect, failures, armed = sqlite3.connect, [], []

    class FullConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if "into files" in sql.lower() and not armed:
                pages = super().execute("PRAGMA page_count").fetchone()[0]
                super().execute(f"PRAGMA max_page_count={pages}")
                armed.append(pages)
            try:
                return super().execute(sql, parameters)
            except sqlite3.Error as error:
                failures.append(getattr(error, "sqlite_errorcode", None))
                raise

    def constrained(*args, **kwargs):
        if str(sample.scratch) in str(args[0]):
            kwargs["factory"] = FullConnection
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", constrained)
    source = _source(sample)
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_WAITING_SCRATCH_CAPACITY$"):
        with source:
            pytest.fail("A partial source must never become VERIFIED")
    assert armed and sqlite3.SQLITE_FULL in failures
    _clean_slot(sample)
    _preserved(sample)
    monkeypatch.setattr(sqlite3, "connect", connect)
    _same_source_recovers(sample)


def test_real_midway_sql_failure_never_publishes_a_prefix_and_preserves_state(tmp_path, monkeypatch):
    sample = _sample_source(tmp_path)
    connect, inserted, failures = sqlite3.connect, [], []

    class FailedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if "into files" in sql.lower():
                if len(inserted) == 5:
                    try:
                        super().execute("INSERT INTO deliberately_missing_typed_table VALUES(1)")
                    except sqlite3.Error as error:
                        failures.append(getattr(error, "sqlite_errorcode", None))
                        raise
                result = super().execute(sql, parameters)
                inserted.append(1)
                return result
            return super().execute(sql, parameters)

    def constrained(*args, **kwargs):
        if str(sample.scratch) in str(args[0]):
            kwargs["factory"] = FailedConnection
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", constrained)
    source = _source(sample)
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_STORAGE_UNAVAILABLE$"):
        with source:
            pytest.fail("Five real inserted records cannot count as a verified full source")
    assert len(inserted) == 5 and failures == [sqlite3.SQLITE_ERROR]
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CLOSED$"):
        source.entries_page()
    _clean_slot(sample)
    _preserved(sample)
    monkeypatch.setattr(sqlite3, "connect", connect)
    _same_source_recovers(sample)


@pytest.mark.parametrize("changes,reason", [
    (dict(body_bytes=1), "WAITING_BODY_BUDGET"),
    (dict(entry_bytes=1), "WAITING_ENTRY_BUDGET"),
    (dict(source_bytes=1), "WAITING_SOURCE_BUDGET"),
    (dict(scratch_bytes=1), "WAITING_SCRATCH_CAPACITY"),
    (dict(elapsed_seconds=0.000000001), "WAITING_TIME_BUDGET"),
])
def test_resource_wait_never_becomes_verified_prefix(tmp_path, changes, reason):
    sample = _sample_source(tmp_path)
    source = _source(sample, TypedSourceBudget(**changes))
    with pytest.raises(TypedSnapshotSourceError, match=f"^TYPED_SOURCE_{reason}$"):
        with source:
            pytest.fail("Resource waiting cannot expose a verified partial source")
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CLOSED$"):
        source.summary
    _clean_slot(sample)
    _preserved(sample)
    _same_source_recovers(sample)


def test_caller_context_exception_is_unchanged_and_releases_scratch(tmp_path):
    sample = _sample_source(tmp_path)
    source, fault = _source(sample), LookupError("original typed reader caller failure")
    with pytest.raises(LookupError) as caught:
        with source as reader:
            assert reader.entry(_name(0))["maps"] == _maps(0)
            raise fault
    assert caught.value is fault
    with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CLOSED$"):
        source.entry(_name(0))
    _clean_slot(sample)
    _preserved(sample)
    _same_source_recovers(sample)


def test_first_registration_interleaving_reports_real_busy_without_adopting_empty_lock(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import errno
    import fcntl
    import threading
    import security_runtime.task_review.typed_source_scratch as scratch_module

    root = tmp_path / "source"
    root.mkdir()
    store = SnapshotStore(tmp_path / "raw", workspace_root=root, key=b"r" * 32)
    binding = SnapshotBinding("scratch-race", dict(host="codex", session="c" * 64), "fixed", 3)
    ref = store.create(binding)["ref"]
    store.seal(ref, binding, expected_files=0, inventory_complete=True)
    original_raw = _fingerprint(store.directory)
    parent = tmp_path / "scratch"
    parent.mkdir(mode=0o700)
    keep = parent / "caller.txt"
    keep.write_bytes(b"caller bytes")
    keep.chmod(0o640)
    created, blocked, release = (threading.Event() for _ in range(3))
    original_open, original_flock = scratch_module._open, fcntl.flock

    def ordered_open(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if (threading.current_thread().name == "first-registration"
                and os.fsdecode(path) == scratch_module.LOCK_NAME and flags & os.O_EXCL):
            created.set()
            assert release.wait(5)
        return fd

    def observed_flock(fd, flags):
        try:
            return original_flock(fd, flags)
        except OSError as error:
            if (threading.current_thread().name == "second-registration"
                    and error.errno in {errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK}):
                blocked.set()  # The operating system actually refused this lock.
            raise

    def first():
        threading.current_thread().name = "first-registration"
        with scratch_module.ScratchSlot(store, parent):
            return "REGISTERED"

    def second():
        threading.current_thread().name = "second-registration"
        try:
            with scratch_module.ScratchSlot(store, parent):
                return "UNEXPECTED_SUCCESS"
        except scratch_module.TypedSnapshotSourceError as error:
            return error.reason_code

    monkeypatch.setattr(scratch_module, "_open", ordered_open)
    monkeypatch.setattr(fcntl, "flock", observed_flock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_result = pool.submit(first)
        try:
            assert created.wait(5)
            lock = parent / scratch_module.LOCK_NAME
            inode = lock.stat().st_ino
            assert lock.read_bytes() == b""
            snapshot = _fingerprint(parent)
            second_result = pool.submit(second)
            assert blocked.wait(5)
            assert second_result.result(timeout=5) == "TYPED_SOURCE_WAITING_SCRATCH_BUSY"
            assert _fingerprint(parent) == snapshot
            assert lock.stat().st_ino == inode and lock.read_bytes() == b""
        finally:
            release.set()
        assert first_result.result(timeout=5) == "REGISTERED"
    assert lock.stat().st_ino == inode and lock.read_bytes()
    assert not (parent / scratch_module.SLOT_NAME).exists()
    assert keep.read_bytes() == b"caller bytes" and stat.S_IMODE(keep.stat().st_mode) == 0o640
    assert _fingerprint(store.directory) == original_raw

    # A genuinely damaged empty registration is still unsafe. Contention must
    # not become a general permission to adopt or overwrite empty caller data.
    lock.write_bytes(b"")
    before_rejection = _fingerprint(parent)
    with pytest.raises(scratch_module.TypedSnapshotSourceError, match="^TYPED_SOURCE_SCRATCH_UNSAFE$"):
        with scratch_module.ScratchSlot(store, parent):
            pytest.fail("An empty damaged registration must not be adopted")
    assert _fingerprint(parent) == before_rejection
    assert _fingerprint(store.directory) == original_raw


CHILD = r'''
import json,os,sys
sys.path.insert(0,sys.argv[1])
from security_runtime.snapshot_store import SnapshotStore
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.snapshot_source import TypedSnapshotSource
data=json.loads(sys.argv[2])
store=SnapshotStore(data['directory'],workspace_root=data['root'],key=bytes.fromhex(data['key']))
binding=ReviewMetadataBinding(**data['binding'])
with TypedSnapshotSource(store,data['pointer'],review_binding=binding,field='end',scratch_directory=data['scratch']) as reader:
    assert reader.summary['source_digest_verified'] is True
    print('VERIFIED_READY',flush=True)
    sys.stdin.readline()
    if data['exit_kind']=='os_exit':
        os._exit(23)
    raise SystemExit(23)
'''


@pytest.mark.parametrize("exit_kind", ["system_exit", "os_exit"])
def test_real_process_exit_cleanup_or_authenticated_bounded_resume(tmp_path, exit_kind):
    import select

    sample = _sample_source(tmp_path)
    data = dict(directory=str(sample.raw.directory), root=str(sample.root),
        key=sample.state.key().hex(), binding=asdict(sample.binding), pointer=sample.pointer,
        scratch=str(sample.scratch), exit_kind=exit_kind)
    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", CHILD,
        PACKAGE_PARENT, json.dumps(data)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, cwd=tmp_path)
    try:
        readable, _, _ = select.select([child.stdout], [], [], 10)
        assert readable and child.stdout.readline().strip() == "VERIFIED_READY"
        _private_slot(sample, TypedSourceBudget())
        _, error = child.communicate("exit\n", timeout=5)
        assert child.returncode == 23, error
        _preserved(sample)
        if exit_kind == "os_exit":
            # A process death cannot execute __exit__. Only the registered
            # bounded private slot may remain; the next same-source writer
            # authenticates it before cleanup/reuse instead of deleting parent.
            _private_slot(sample, TypedSourceBudget())
        else:
            _clean_slot(sample)
        with _source(sample) as recovered:
            assert recovered.summary["source_digest_verified"] is True
            assert recovered.entry(_name(sample.count - 1))["maps"] == _maps(sample.count - 1)
        _clean_slot(sample)
        _preserved(sample)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=5)


def test_fork_child_rejects_inherited_api_without_closing_parent_callbacks_or_lock(tmp_path):
    """No inherited SQLite operation or normal child interpreter teardown."""
    import select
    import signal

    sample = _sample_source(tmp_path)
    callbacks = []
    with _source(sample) as reader:
        reader._stack.callback(lambda: callbacks.append("parent cleanup"))
        original_scratch = _fingerprint(sample.scratch)
        receive, send = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(receive)
            status = 1
            try:
                reasons = []
                for operation in (reader.close, reader.entries_page):
                    try:
                        operation()
                    except TypedSnapshotSourceError as error:
                        reasons.append(error.reason_code)
                packet = dict(reasons=reasons, exit_result=reader.__exit__(None, None, None),
                              callbacks=list(callbacks))
                os.write(send, json.dumps(packet).encode())
                status = 0
            except BaseException as error:
                os.write(send, json.dumps(dict(child_error=type(error).__name__)).encode())
            finally:
                os.close(send)
                os._exit(status)
        os.close(send)
        reaped = False
        try:
            readable, _, _ = select.select([receive], [], [], 5)
            assert readable
            packet = json.loads(os.read(receive, 16384))
            _, status = os.waitpid(child, 0)
            reaped = True
            assert os.waitstatus_to_exitcode(status) == 0
            assert packet == dict(reasons=["TYPED_SOURCE_CLOSED", "TYPED_SOURCE_CLOSED"],
                                  exit_result=False, callbacks=[])
        finally:
            os.close(receive)
            if not reaped:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
        assert callbacks == []
        assert _fingerprint(sample.scratch) == original_scratch
        assert reader.entry(_name(sample.count - 1))["maps"] == _maps(sample.count - 1)

        code = r'''
import json,sys
sys.path.insert(0,sys.argv[1])
from security_runtime.snapshot_store import SnapshotStore
from security_runtime.task_review.typed_source_scratch import ScratchSlot,TypedSnapshotSourceError
store=SnapshotStore(sys.argv[2],workspace_root=sys.argv[3],key=bytes.fromhex(sys.argv[5]))
try:
    with ScratchSlot(store,sys.argv[4]):
        raise AssertionError('Parent lock was released by the fork child')
except TypedSnapshotSourceError as error:
    print(json.dumps(dict(reason=error.reason_code)),flush=True)
'''
        competing = subprocess.run([sys.executable, "-I", "-B", "-c", code,
            PACKAGE_PARENT, str(sample.raw.directory), str(sample.root),
            str(sample.scratch), sample.state.key().hex()], capture_output=True,
            text=True, cwd=tmp_path, timeout=5)
        assert competing.returncode == 0, competing.stderr
        assert json.loads(competing.stdout) == dict(reason="TYPED_SOURCE_WAITING_SCRATCH_BUSY")
        assert reader.entry(_name(0))["maps"] == _maps(0)
    assert callbacks == ["parent cleanup"]
    _clean_slot(sample)
    _preserved(sample)
