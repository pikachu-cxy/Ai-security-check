"""Birth-only opt-in and actual old-install fences, without a V2 publisher."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import digest, encode
from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStoreError
from security_runtime.tasks.activity import LEGACY, POLICY as CLOSEOUT_POLICY
from security_runtime.tasks.capture_source_profile import (
    POLICY, PROFILE, PROFILE_FIELD, DESCRIPTOR_FIELD, CaptureSourceProfileError, validate_record,
)
from security_runtime.tasks.ownership import session_owner
from security_runtime.tasks.security import TaskSecurityService
from security_runtime.tasks.security_state import CONTRACT
from security_runtime.tasks.snapshot_gc import collect_pages
from security_runtime.tasks.snapshot_page_guard import page_guard
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY, POINTER, _binding, _store, batched, managed
from test_native_repair_intent import sample as native_intent_sample, ready as ready_native_intent


class NoScanner:
    def scan(self, *args, **kwargs):
        pytest.fail("A birth/profile/storage probe must not scan")


def create(tmp_path, *, enabled=True, owner=True, policy=CLOSEOUT_POLICY, frozen=True):
    root = (tmp_path / "source").resolve()
    root.mkdir()
    (root / "source.py").write_text("value=1\n")
    hooks = HookStateStore(tmp_path / "private")
    scope = session_owner("codex", "capture-profile") if owner else None
    service = TaskSecurityService(NoScanner(), hooks, owner=scope, now=lambda: 100.0,
                                  frozen_body_contexts=frozen, capture_sources=enabled)
    response = service.begin(root, "original-task", check_policy=policy)
    assert response["status"] == "ACTIVE"
    state = service.store(root)
    return SimpleNamespace(service=service, root=root, hooks=hooks, state=state,
        owner=scope, ref=response["task_ref"], record=service.load(root, response["task_ref"]))


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_RUNTIME_STATE_DIR", str(tmp_path / "runtime-state"))


def rows(state):
    with sqlite3.connect(state.path) as db:
        return tuple(db.execute("SELECT ref,data,mac FROM security_tasks ORDER BY ref"))


def page_rows(state):
    with sqlite3.connect(_store(state).path) as db:
        return tuple(db.iterdump())


def storage_tree(state):
    directory = state.path.parent
    return {str(path.relative_to(directory)): (stat.S_IMODE(path.stat().st_mode),
        path.stat().st_mtime_ns, path.read_bytes() if path.is_file() else None)
        for path in (directory, *directory.rglob("*"))}


def widen_old_storage(state):
    state.path.parent.chmod(0o755)
    for name in ("task-security.db", "snapshot.key", "snapshot-pages.gc.lock", "snapshot-pages.gc.identity"):
        path = state.path.parent / name
        if path.exists():
            path.chmod(0o644)


def test_fresh_owned_closeout_gets_immutable_birth_fence_and_original_donor_domain(tmp_path):
    sample = create(tmp_path)
    record = sample.record
    assert record["contract"] == GC_CONTRACT
    assert record["capture_policy"] == POLICY and record[PROFILE_FIELD] == PROFILE
    assert batched(record) and managed(record)
    assert "review_plan" not in record and "review_revision" not in record
    assert DESCRIPTOR_FIELD not in record and DESCRIPTOR_FIELD not in record["baseline"]
    pointer = record["baseline"][POINTER]
    binding = _binding(record, "baseline", pointer["source"])
    assert binding.retention_domain == "TASK_PAGES_GC_V1"
    assert _store(sample.state).resume(pointer["ref"], binding)["state"] == "SEALED"
    assert sample.service.before_lines(sample.root, record, "source.py") == ["value=1"]
    saved = sample.state.save(record)
    assert saved["generation"] == record["generation"] + 1
    assert saved[PROFILE_FIELD] == PROFILE and saved["capture_policy"] == POLICY
    assert saved["baseline"] == record["baseline"]


@pytest.mark.parametrize("option,frozen", [(1, True), (None, True), ("yes", True), (True, False)])
def test_option_is_exact_bool_and_requires_original_body_opt_in(tmp_path, option, frozen):
    hooks = HookStateStore(tmp_path / "private")
    with pytest.raises(ValueError):
        TaskSecurityService(NoScanner(), hooks, frozen_body_contexts=frozen, capture_sources=option)
    assert not hooks.directory.exists()


@pytest.mark.parametrize("owner,policy", [(False, LEGACY), (True, LEGACY)])
def test_legacy_and_anonymous_births_keep_original_contract(tmp_path, owner, policy):
    sample = create(tmp_path, owner=owner, policy=policy)
    assert sample.record["contract"] == CONTRACT
    assert PROFILE_FIELD not in sample.record and "capture_policy" not in sample.record


def test_anonymous_closeout_keeps_original_owner_gate_without_capturing_a_task(tmp_path):
    root = (tmp_path / "source").resolve()
    root.mkdir()
    source = root / "source.py"
    source.write_text("value=1\n")
    hooks = HookStateStore(tmp_path / "private")
    service = TaskSecurityService(NoScanner(), hooks, now=lambda: 100.0,
                                  frozen_body_contexts=True, capture_sources=True)
    with pytest.raises(ValueError, match="^Closeout tasks require an explicit owner$"):
        service.begin(root, "anonymous-closeout", check_policy=CLOSEOUT_POLICY)
    # The original begin preflight initializes its workspace lock/key before
    # this owner gate. No task, page or body capture is started after rejection.
    assert set(path.name for path in hooks.workspace_directory(root).iterdir()) == {
        "workspace.lock", "snapshot.key"}
    assert source.read_text() == "value=1\n"


def test_existing_key_is_resumed_without_adopting_new_profile_or_current_source(tmp_path):
    sample = create(tmp_path, enabled=False)
    before = rows(sample.state)
    (sample.root / "source.py").write_text("value=2\n")
    enabled = TaskSecurityService(NoScanner(), sample.hooks, owner=sample.owner, now=lambda: 100.0,
                                  frozen_body_contexts=True, capture_sources=True)
    resumed = enabled.begin(sample.root, "original-task", check_policy=CLOSEOUT_POLICY)
    assert resumed["task_ref"] == sample.ref
    assert rows(sample.state) == before
    current = enabled.load(sample.root, sample.ref)
    assert PROFILE_FIELD not in current and current["capture_policy"] == GC_POLICY
    assert current["baseline"] == sample.record["baseline"]
    assert enabled.before_lines(sample.root, current, "source.py") == ["value=1"]


def test_native_preparation_is_not_born_into_capture_profile(native_intent_sample):
    tasks, _, root, preparation = native_intent_sample
    ready_native_intent(native_intent_sample)
    enabled = TaskSecurityService(tasks.runtime, tasks.hooks, owner=tasks.owner,
        now=tasks.now, frozen_body_contexts=True, capture_sources=True)
    ref = enabled.begin(root, "native-exclusion", check_policy=CLOSEOUT_POLICY,
                        _native_preparation=preparation)["task_ref"]
    record = enabled.load(root, ref)
    assert record["native_repair"] == preparation
    assert PROFILE_FIELD not in record and record.get("capture_policy") != POLICY


@pytest.mark.parametrize("entry", ["save", "_save"])
@pytest.mark.parametrize("change", ["adopt", "none", "other"])
def test_old_task_cas_cannot_add_profile_or_change_capture_policy(tmp_path, change, entry):
    sample = create(tmp_path, enabled=False)
    store, orphan_binding, orphan = _orphan(sample)
    candidate = copy.deepcopy(sample.record)
    if change == "adopt":
        candidate.update(capture_policy=POLICY, **{PROFILE_FIELD: PROFILE})
    else:
        candidate["capture_policy"] = None if change == "none" else "BATCHED_FILES_V1"
    widen_old_storage(sample.state)
    before = rows(sample.state), page_rows(sample.state), storage_tree(sample.state)
    with pytest.raises(CaptureSourceProfileError):
        getattr(sample.state, entry)(candidate)
    assert (rows(sample.state), page_rows(sample.state), storage_tree(sample.state)) == before
    assert store.resume(orphan, orphan_binding)["state"] == "SEALED"


@pytest.mark.parametrize("entry", ["save", "_save"])
def test_valid_managed_writer_still_upgrades_original_wide_permissions(tmp_path, entry):
    sample = create(tmp_path, enabled=False)
    baseline, key = copy.deepcopy(sample.record["baseline"]), sample.state.key()
    widen_old_storage(sample.state)
    saved = getattr(sample.state, entry)(sample.record)
    assert saved["generation"] == sample.record["generation"] + 1
    assert saved["baseline"] == baseline and sample.state.key() == key
    assert stat.S_IMODE(sample.state.path.parent.stat().st_mode) == 0o700
    for name in ("task-security.db", "snapshot.key", "snapshot-pages.gc.lock", "snapshot-pages.gc.identity"):
        assert stat.S_IMODE((sample.state.path.parent / name).stat().st_mode) == 0o600


def test_absent_legacy_policy_cannot_be_changed_to_explicit_none(tmp_path):
    sample = create(tmp_path, enabled=False, owner=False, policy=LEGACY)
    candidate = dict(sample.record, capture_policy=None)
    before = rows(sample.state)
    with pytest.raises(CaptureSourceProfileError):
        sample.state.save(candidate)
    assert rows(sample.state) == before


@pytest.mark.parametrize("change", ["remove", "replace", "downgrade", "none"])
def test_new_profile_cannot_be_removed_replaced_or_downgraded(tmp_path, change):
    sample = create(tmp_path)
    candidate = copy.deepcopy(sample.record)
    if change == "remove":
        candidate.pop(PROFILE_FIELD)
    elif change == "replace":
        candidate[PROFILE_FIELD] = "other-profile"
    else:
        candidate["capture_policy"] = GC_POLICY if change == "downgrade" else None
    before = rows(sample.state)
    with pytest.raises(CaptureSourceProfileError):
        sample.state.save(candidate)
    assert rows(sample.state) == before


def test_head_rejects_resigned_invalid_profile_combination(tmp_path):
    sample = create(tmp_path)
    with sqlite3.connect(sample.state.path) as db:
        raw = db.execute("SELECT data FROM security_tasks WHERE ref=?", (sample.ref,)).fetchone()[0]
        broken = json.loads(raw)
        broken.pop(PROFILE_FIELD)
        db.execute("UPDATE security_tasks SET data=?,mac=? WHERE ref=?",
                   (encode(broken).decode(), digest(sample.state.key(), broken), sample.ref))
    before = rows(sample.state), page_rows(sample.state)
    with pytest.raises(CaptureSourceProfileError):
        sample.state.get(sample.ref)
    assert (rows(sample.state), page_rows(sample.state)) == before


@pytest.mark.parametrize("location", ["top", "baseline", "history"])
def test_unpublished_descriptors_are_rejected_for_every_task_policy(tmp_path, location):
    sample = create(tmp_path, enabled=False)
    candidate = copy.deepcopy(sample.record)
    target = candidate if location == "top" else candidate["baseline"]
    if location == "history":
        candidate["previous_reviews"] = [{"end": {}}]
        target = candidate["previous_reviews"][0]["end"]
    target[DESCRIPTOR_FIELD] = {"contract": "unpublished-fixture"}
    before = rows(sample.state), page_rows(sample.state)
    with pytest.raises(CaptureSourceProfileError) as error:
        sample.state.save(candidate)
    assert error.value.reason_code == "CAPTURE_SOURCE_PROFILE_PUBLISHER_UNAVAILABLE"
    assert (rows(sample.state), page_rows(sample.state)) == before


def test_user_map_values_are_not_interpreted_as_control_descriptors():
    # Pure validation only: this is ordinary opaque source metadata, not a
    # claimed valid body reference or a manufactured published task.
    validate_record({"baseline": {"hashes": {"capture_source": "ordinary-key"},
        "preimages": {"source.py": {"capture_source": {"user": "data"}}}}})


def _old_probe(sample, tmp_path, mode):
    interpreter = Path(os.environ.get("SECURITY_RUNTIME_OLD_PROFILE_PYTHON",
        "/Users/cxy/.local/share/ai-security-runtime/source-builds/20261024-23418aaf411f/venv/bin/python"))
    if not interpreter.exists():
        pytest.skip("Requires a preserved actual pre-profile installation")
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(encode(sample.record))
    candidate.chmod(0o600)
    script = tmp_path / "old_probe.py"
    script.write_text('''import hashlib,json,pathlib,sys
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security_state import TaskSecurityStore
from security_runtime.tasks.snapshot_gc import collect_pages
import security_runtime.tasks.security_state as state_module
import security_runtime.tasks.snapshot_gc as gc_module
installation=pathlib.Path(sys.argv[1]).absolute()
assert pathlib.Path(state_module.__file__).resolve().is_relative_to(installation)
assert pathlib.Path(gc_module.__file__).resolve().is_relative_to(installation)
root,hooks=pathlib.Path(sys.argv[2]),HookStateStore(pathlib.Path(sys.argv[3]))
record=json.loads(pathlib.Path(sys.argv[4]).read_text())
state=TaskSecurityStore(hooks,root,now=lambda:100.0)
operations=[]
if sys.argv[5]=="fenced":
    for name,call in (("read",lambda:state.get(record["task_ref"])),
                      ("write",lambda:state.save(record)),
                      ("gc",lambda:collect_pages(state,prune=False))):
        try: call()
        except ValueError as error:
            if name=="gc":
                assert getattr(error,"reason_code",None)=="REVIEW_METADATA_HISTORY_UNAVAILABLE",str(error)
            else:
                assert str(error)=="Snapshot collection contract mismatch",str(error)
            operations.append(name)
        else: raise AssertionError("Old operation accepted new capture policy: "+name)
else:
    loaded=state.get(record["task_ref"])
    assert loaded["baseline"]==record["baseline"]
    saved=state.save(loaded)
    assert saved["generation"]==record["generation"]+1
    assert saved["baseline"]==record["baseline"]
    operations=["legacy-read","legacy-write"]
print(json.dumps(dict(operations=operations,modules={m.__name__:{"path":m.__file__,
    "sha256":hashlib.sha256(pathlib.Path(m.__file__).read_bytes()).hexdigest()}
    for m in (state_module,gc_module)})))
''')
    script.chmod(0o600)
    result = subprocess.run([str(interpreter), "-I", "-B", str(script),
        str(interpreter.parent.parent), str(sample.root), str(sample.hooks.directory),
        str(candidate), mode], cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _orphan(sample):
    store = _store(sample.state)
    binding = SnapshotBinding(task_ref="profile-orphan", owner=sample.owner,
        source_ref=hashlib.sha256(b"orphan").hexdigest(), representation_version=3,
        kind="TASK_BEFORE_EDIT", captured_before_edit=True, retention_domain="TASK_PAGES_GC_V1")
    with page_guard(sample.state.path.parent):
        ref = store.create(binding)["ref"]
        store.append_page(ref, binding, [("source.py", b"value=1\n")], expected_cursor=None, cursor="1")
        store.seal(ref, binding, expected_files=1, inventory_complete=True)
    return store, binding, ref


def test_real_old_install_rejects_read_write_and_gc_before_deleting_a_collectible_orphan(tmp_path, record_testsuite_property):
    sample = create(tmp_path)
    store, binding, orphan = _orphan(sample)
    before = rows(sample.state), page_rows(sample.state)
    report = _old_probe(sample, tmp_path, "fenced")
    assert report["operations"] == ["read", "write", "gc"]
    assert (rows(sample.state), page_rows(sample.state)) == before
    assert store.resume(orphan, binding)["state"] == "SEALED"
    # This same orphan really is collectible: a current, authenticated whole
    # inventory removes it while retaining the fenced task's donor source.
    result = collect_pages(sample.state)
    assert result["collected_captures"] == 1 and result["released_logical_bytes"] > 0
    with pytest.raises(SnapshotStoreError) as error:
        store.resume(orphan, binding)
    assert error.value.reason_code == "SNAPSHOT_HISTORY_UNAVAILABLE"
    assert sample.state.get(sample.ref)["baseline"] == sample.record["baseline"]
    record_testsuite_property("actual_old_fenced_modules", json.dumps(report["modules"], sort_keys=True))


def test_real_old_install_still_reads_and_writes_original_v1_task(tmp_path, record_testsuite_property):
    sample = create(tmp_path, enabled=False)
    before = page_rows(sample.state)
    report = _old_probe(sample, tmp_path, "legacy")
    assert report["operations"] == ["legacy-read", "legacy-write"]
    current = sample.state.get(sample.ref)
    assert current["generation"] == sample.record["generation"] + 1
    assert current["baseline"] == sample.record["baseline"]
    assert current["capture_policy"] == GC_POLICY and PROFILE_FIELD not in current
    assert page_rows(sample.state) == before
    record_testsuite_property("actual_old_v1_modules", json.dumps(report["modules"], sort_keys=True))
