"""Typed maps/list contracts over independently written new-domain sources.

Old pack/unpack is only a small oracle. No task is migrated, no live source or
external preimage is read, and entering this context explicitly writes scratch.
"""
import builtins
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from types import SimpleNamespace

import pytest

from security_runtime.closeout_state import encode
from security_runtime.snapshot_store import SnapshotStore, SnapshotStoreError
from security_runtime.task_review.metadata_store import ReviewMetadataBinding
from security_runtime.task_review.paged_task_store import source_binding
from security_runtime.task_review.snapshot_source import (
    TypedSnapshotSource, TypedSourceBudget, TypedSnapshotSourceError,
)
from security_runtime.tasks.snapshot_pages import GC_CONTRACT, GC_POLICY, LISTS, MAPS, pack, unpack


KEY = b"t" * 32
OWNER = dict(host="codex", session="a" * 64)
SHA = hashlib.sha256(b"value=1\n").hexdigest()


@pytest.fixture(autouse=True)
def supported_private_scratch(request):
    if (os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW')) and request.node.name not in {
        'test_unverified_pointer_or_old_domain_is_not_adopted',
        'test_unsupported_platform_rejects_before_creating_scratch',
    }:
        pytest.skip('Typed source scratch requires POSIX private-directory guarantees')


@pytest.mark.skipif(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), reason='Unsupported-platform contract')
def test_unsupported_platform_rejects_before_creating_scratch(sample):
    pointer, _ = write_raw(sample, rich_snapshot())
    before = fingerprint(sample.scratch)
    with pytest.raises(TypedSnapshotSourceError, match='^TYPED_SOURCE_PLATFORM_UNSUPPORTED$'):
        with open_source(sample, pointer):
            pytest.fail('Unsupported scratch platform was accepted')
    assert fingerprint(sample.scratch) == before


def logical(snapshot):
    return dict(maps={key: snapshot.get(key, {}) for key in MAPS},
                lists={key: snapshot.get(key, []) for key in LISTS})


def source_digest(snapshot):
    return hashlib.sha256(encode(logical(snapshot))).hexdigest()


def path_rows(snapshot):
    value = logical(snapshot)
    paths = sorted(set().union(*(set(v) for v in [*value["maps"].values(), *value["lists"].values()])))
    positions = {key: {name: index for index, name in enumerate(names)}
                 for key, names in value["lists"].items()}
    return [(path, encode(dict(maps={key: items[path] for key, items in value["maps"].items() if path in items},
                              positions={key: items[path] for key, items in positions.items() if path in items})))
            for path in paths]


def write_raw(sample, snapshot, *, binding=None, field="baseline", rows=None, digest=None):
    model = binding or sample.binding
    source = digest or source_digest(snapshot)
    claim = source_binding(model, field, source)
    rows = path_rows(snapshot) if rows is None else rows
    ref = sample.store.create(claim)["ref"]
    cursor = None
    # Physical append order is deliberately unrelated to logical list order.
    for offset in range(0, len(rows), 2):
        page = list(reversed(rows[offset:offset + 2]))
        following = str(offset + len(page))
        sample.store.append_page(ref, claim, page, expected_cursor=cursor, cursor=following)
        cursor = following
    sample.store.seal(ref, claim, expected_files=len(rows), inventory_complete=True)
    return dict(ref=ref, source=source), rows


def open_source(sample, pointer, *, binding=None, field="baseline", budget=None):
    return TypedSnapshotSource(sample.store, pointer, review_binding=binding or sample.binding,
                               field=field, scratch_directory=sample.scratch,
                               budget=budget or TypedSourceBudget())


def fingerprint(directory):
    result = {}
    for current, dirs, files in os.walk(directory, followlinks=False):
        for path in [Path(current), *(Path(current) / name for name in dirs + files)]:
            info = path.lstat()
            value = (stat.S_IMODE(info.st_mode), stat.S_IFMT(info.st_mode), info.st_dev,
                     info.st_ino, info.st_uid, info.st_nlink, info.st_size, info.st_mtime_ns)
            if stat.S_ISREG(info.st_mode):
                value += (hashlib.sha256(path.read_bytes()).hexdigest(),)
            result[str(path.relative_to(directory))] = value
    return result


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    store = SnapshotStore(tmp_path / "new-domain", workspace_root=root, key=KEY)
    binding = ReviewMetadataBinding("ts1-" + "a" * 32, dict(OWNER), 1, "original-review", 3)
    return SimpleNamespace(root=root, scratch=scratch, store=store, binding=binding, temporary=tmp_path)


def rich_snapshot():
    names = ['Z.py', '中文/引号"😀.py', 'unknown.py', 'text-only.py']
    return dict(redaction_version=3,
        hashes={names[0]: SHA, names[1]: hashlib.sha256(b"value=2\n").hexdigest()},
        texts={names[0]: ['quote" backslash\\ newline\n emoji😀', "value=1"],
               names[1]: ["中文😀"], names[3]: ["original metadata only"]},
        line_counts={names[0]: 2, names[1]: 1},
        text_truncations={names[0]: {"lines": [1]}},
        text_unavailable={names[2]: "ORIGINAL_BODY_UNAVAILABLE"},
        preimages={names[0]: {"ref": "ordinary-unresolved-reference",
                              "nested": [None, True, 1.25, {"中": "😀", "escaped_code_unit": "\ud800"}]}},
        inventory=names, read_priority=list(reversed(names)))


def expected_entries(snapshot):
    return {name: dict(path=name, **json.loads(raw)) for name, raw in path_rows(snapshot)}


def test_real_old_pack_oracle_matches_new_domain_canonical_maps_and_both_list_orders(sample):
    snapshot = rich_snapshot()
    old_directory = sample.temporary / "old-oracle"
    old_directory.mkdir(mode=0o700)
    old_state = SimpleNamespace(path=old_directory / "task-security.db", root=sample.root, key=lambda: KEY)
    old_record = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY,
                      task_ref=sample.binding.task_ref, task_owner=dict(OWNER), baseline=snapshot)
    packed = pack(old_state, old_record)
    restored = unpack(old_state, packed)["baseline"]
    pointer, rows = write_raw(sample, snapshot)
    assert packed["baseline"]["paged_entries"]["source"] == pointer["source"] == source_digest(snapshot)
    assert logical(restored) == logical(snapshot)
    old_before, raw_before = fingerprint(old_directory), fingerprint(sample.store.directory)
    (sample.scratch / "caller-owned.txt").write_bytes(b"keep this unrelated scratch-parent file")
    expected, actual, cursor = expected_entries(restored), {}, None
    with open_source(sample, pointer) as source:
        summary = source.summary
        assert summary["state"] == "VERIFIED"
        assert summary["metadata_verified"] and summary["source_digest_verified"]
        assert summary["project_coverage"] == "UNKNOWN" and not summary["external_bodies_available"]
        assert summary["entry_count"] == len(expected)
        assert summary["source_bytes"] == sum(len(raw) for _, raw in rows)
        assert summary["map_counts"] == {key: len(snapshot.get(key, {})) for key in MAPS}
        assert summary["list_counts"] == {key: len(snapshot.get(key, [])) for key in LISTS}
        while True:
            page = source.entries_page(cursor=cursor, limit_items=2, limit_bytes=4096)
            assert len(encode(page)) <= 4096  # Includes signature cursor and all envelope fields.
            assert 0 < len(page["entries"]) <= 2
            for item in page["entries"]:
                assert item == expected[item["path"]]
                assert item["path"] not in actual
                actual[item["path"]] = item
            if page["complete"]:
                assert page["next_cursor"] is None
                break
            assert isinstance(page["next_cursor"], str)
            assert page["next_cursor"] != cursor
            cursor = page["next_cursor"]
        for key in LISTS:
            ordered = sorted((value["positions"][key], name) for name, value in actual.items()
                             if key in value["positions"])
            assert [name for _, name in ordered] == snapshot[key]
        assert source.entry("not-observed.py") is None
        assert "hashes" not in source.entry("unknown.py")["maps"]
        assert "hashes" not in source.entry("text-only.py")["maps"]
        assert source.summary["project_coverage"] == "UNKNOWN"
    assert actual == expected
    assert list(actual) == sorted(expected, key=lambda name: name.encode("utf-8"))
    assert fingerprint(old_directory) == old_before
    assert fingerprint(sample.store.directory) == raw_before
    assert (sample.scratch / "caller-owned.txt").read_bytes() == b"keep this unrelated scratch-parent file"


def test_empty_maps_and_lists_verify_the_exact_original_canonical_digest(sample):
    pointer, _ = write_raw(sample, dict(redaction_version=3))
    with open_source(sample, pointer) as source:
        assert source.summary["entry_count"] == 0
        assert source.summary["map_counts"] == dict.fromkeys(MAPS, 0)
        assert source.summary["list_counts"] == dict.fromkeys(LISTS, 0)
        assert source.entries_page() == dict(entries=[], next_cursor=None, complete=True)
        assert source.entry("missing.py") is None


def test_constructor_is_io_free_and_freezes_caller_pointer_and_owner(sample, monkeypatch):
    pointer, _ = write_raw(sample, rich_snapshot())
    model = replace(sample.binding, owner=dict(OWNER))
    supplied = dict(pointer)
    before = fingerprint(sample.temporary)

    def forbidden(*args, **kwargs):
        pytest.fail("Typed constructor performed filesystem or SQLite I/O")

    with monkeypatch.context() as scoped:
        for name in ("open", "stat", "lstat", "mkdir", "chmod", "listdir", "scandir"):
            scoped.setattr(os, name, forbidden)
        scoped.setattr(builtins, "open", forbidden)
        scoped.setattr(Path, "open", forbidden)
        scoped.setattr(sqlite3, "connect", forbidden)
        # Keep native capability labels intact while observing forbidden I/O.
        scoped.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, forbidden})
        scoped.setattr(os, "supports_follow_symlinks", {*os.supports_follow_symlinks, forbidden})
        source = open_source(sample, supplied, binding=model)
    assert fingerprint(sample.temporary) == before
    supplied["source"] = "b" * 64
    model.owner["session"] = "b" * 64
    with source:
        assert source.summary["state"] == "VERIFIED"
        supplied["ref"] = "ws2-" + "c" * 32
        model.owner["session"] = "c" * 64
        assert source.entry("Z.py")["maps"]["hashes"] == SHA


def test_entry_summary_and_pages_are_detached_and_closed_handle_cannot_read(sample):
    pointer, _ = write_raw(sample, rich_snapshot())
    with open_source(sample, pointer) as source:
        summary = source.summary
        summary["map_counts"]["hashes"] = 999
        assert source.summary["map_counts"]["hashes"] == 2
        value = source.entry("Z.py")
        value["maps"]["preimages"]["nested"][-1]["中"] = "caller edit"
        assert source.entry("Z.py")["maps"]["preimages"]["nested"][-1]["中"] == "😀"
        page = source.entries_page(limit_items=1)
        name = page["entries"][0]["path"]
        page["entries"][0]["maps"]["caller_only"] = True
        assert "caller_only" not in source.entry(name)["maps"]
    for operation in (lambda: source.summary, lambda: source.entry("Z.py"), lambda: source.entries_page()):
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CLOSED$"):
            operation()


def reject_typed(sample, pointer, reason, **kwargs):
    before = fingerprint(sample.store.directory)
    with pytest.raises(TypedSnapshotSourceError) as error:
        with open_source(sample, pointer, **kwargs):
            pytest.fail("Malformed typed source was exposed as VERIFIED")
    assert error.value.reason_code == "TYPED_SOURCE_" + reason
    assert fingerprint(sample.store.directory) == before


def test_validly_signed_wrong_pointer_digest_does_not_become_verified(sample):
    snapshot = rich_snapshot()
    pointer, _ = write_raw(sample, snapshot, digest="f" * 64)
    reject_typed(sample, pointer, "SOURCE_MISMATCH")


@pytest.mark.parametrize("case", ["duplicate_top", "duplicate_nested", "unknown_top", "unknown_map",
                                  "unknown_list", "root_array", "maps_array", "ghost_path",
                                  "NaN", "Infinity", "-Infinity", "overflow_float"])
def test_signed_payload_requires_strict_finite_unambiguous_json(sample, case):
    snapshot = dict(hashes={"a.py": SHA}, inventory=["a.py"])
    raw = encode(dict(maps=dict(hashes=SHA), positions=dict(inventory=0)))
    if case == "duplicate_top":
        raw = b'{"maps":{"hashes":"' + SHA.encode() + b'"},"maps":{"hashes":"' + SHA.encode() + b'"},"positions":{"inventory":0}}'
    elif case == "duplicate_nested":
        raw = raw.replace(b'"inventory":0', b'"inventory":0,"inventory":0')
    elif case == "unknown_top":
        raw = raw[:-1] + b',"unknown":0}'
    elif case == "unknown_map":
        raw = encode(dict(maps=dict(hashes=SHA, unknown=1), positions=dict(inventory=0)))
    elif case == "unknown_list":
        raw = encode(dict(maps=dict(hashes=SHA), positions=dict(inventory=0, unknown=0)))
    elif case == "root_array":
        raw, snapshot = b'[]', {}
    elif case == "maps_array":
        raw, snapshot = b'{"maps":[],"positions":{}}', {}
    elif case == "ghost_path":
        raw, snapshot = b'{"maps":{},"positions":{}}', {}
    else:
        value = float('inf') if case == "overflow_float" else float(case)
        snapshot = dict(preimages={"a.py": value}, inventory=["a.py"])
        raw = encode(dict(maps=dict(preimages=value), positions=dict(inventory=0)))
        if case == "overflow_float":
            raw = raw.replace(b'Infinity', b'1e999')
    pointer, _ = write_raw(sample, snapshot, rows=[("a.py", raw)])
    reject_typed(sample, pointer, "INVALID_PAYLOAD")


@pytest.mark.parametrize("positions", [[False], [-1], [0.0], [2**80], [0, 0], [0, 2], [1]])
def test_positions_are_nonboolean_bounded_unique_and_contiguous(sample, positions):
    names = [f"path_{index}.py" for index in range(len(positions))]
    snapshot = dict(hashes=dict.fromkeys(names, SHA), inventory=names)
    rows = [(name, encode(dict(maps=dict(hashes=SHA), positions=dict(inventory=position))))
            for name, position in zip(names, positions)]
    pointer, _ = write_raw(sample, snapshot, rows=rows)
    reject_typed(sample, pointer, "POSITION_INVALID")


@pytest.mark.parametrize("scope", ["revision", "snapshot", "field", "owner", "ref"])
def test_cursor_is_bound_to_complete_review_scope_and_can_resume_same_scope(sample, scope):
    snapshot = rich_snapshot()
    pointer, _ = write_raw(sample, snapshot)
    model, field = sample.binding, "baseline"
    if scope == "revision":
        model = replace(model, revision=2)
        other = pointer
    elif scope == "snapshot":
        model = replace(model, snapshot_id="another-review-snapshot")
        other = pointer
    else:
        if scope == "field":
            field = "end"
        elif scope == "owner":
            # A different owner gets its own task; never readopt the unique
            # raw task/source slot already owned by the original caller.
            model = replace(model, task_ref="ts1-" + "c" * 32,
                            owner=dict(host="cursor", session="b" * 64))
        else:
            model = replace(model, task_ref="ts1-" + "b" * 32)
        other, _ = write_raw(sample, snapshot, binding=model, field=field)
    with open_source(sample, pointer) as first:
        token = first.entries_page(limit_items=1, limit_bytes=4096)["next_cursor"]
        assert isinstance(token, str)
    with open_source(sample, pointer) as same:
        assert same.entries_page(cursor=token, limit_items=1, limit_bytes=4096)["entries"]
    with open_source(sample, other, binding=model, field=field) as different:
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CURSOR_INVALID$"):
            different.entries_page(cursor=token, limit_items=1, limit_bytes=4096)


def test_cursor_tampering_and_response_budget_never_return_a_partial_item(sample):
    pointer, _ = write_raw(sample, rich_snapshot())
    with open_source(sample, pointer) as source:
        token = source.entries_page(limit_items=1, limit_bytes=4096)["next_cursor"]
        for invalid in ("not-a-cursor", token[:-1], token + "x"):
            with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_CURSOR_INVALID$"):
                source.entries_page(cursor=invalid)
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_PAGE_BYTE_BUDGET$"):
            source.entries_page(limit_bytes=1)


def test_larger_original_object_requires_explicit_budget_and_is_not_truncated(sample):
    body = "x" * 70_000
    snapshot = dict(texts={"large.py": [body]}, inventory=["large.py"])
    pointer, _ = write_raw(sample, snapshot)
    reject_typed(sample, pointer, "WAITING_BODY_BUDGET")
    reject_typed(sample, pointer, "WAITING_ENTRY_BUDGET", budget=TypedSourceBudget(body_bytes=80_000))
    with open_source(sample, pointer, budget=TypedSourceBudget(body_bytes=80_000, entry_bytes=80_000)) as source:
        assert source.entry("large.py")["maps"]["texts"] == [body]
        with pytest.raises(TypedSnapshotSourceError, match="^TYPED_SOURCE_PAGE_BYTE_BUDGET$"):
            source.entries_page()


def test_unverified_pointer_or_old_domain_is_not_adopted(sample):
    snapshot = rich_snapshot()
    pointer, rows = write_raw(sample, snapshot)
    with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_BINDING_MISMATCH$"):
        with open_source(sample, dict(pointer, source="c" * 64)):
            pytest.fail("An unsigned pointer rewrite was adopted")
    old = sample.temporary / "old-domain"
    old.mkdir(mode=0o700)
    state = SimpleNamespace(path=old / "task-security.db", root=sample.root, key=lambda: KEY)
    record = dict(contract=GC_CONTRACT, capture_policy=GC_POLICY, task_ref=sample.binding.task_ref,
                  task_owner=dict(OWNER), baseline=snapshot)
    old_pointer = pack(state, record)["baseline"]["paged_entries"]
    old_store = SnapshotStore(old / "snapshot-pages", workspace_root=sample.root, key=KEY)
    before = fingerprint(old)
    with pytest.raises(SnapshotStoreError, match="^SNAPSHOT_BINDING_MISMATCH$"):
        with TypedSnapshotSource(old_store, old_pointer, review_binding=sample.binding,
                                 field="baseline", scratch_directory=sample.scratch):
            pytest.fail("Old-domain evidence was relabelled as a new source")
    assert fingerprint(old) == before
