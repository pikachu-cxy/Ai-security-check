"""Discovery limits bound actual work, including one-directory large projects."""
from pathlib import Path

import pytest

from security_runtime.task_inventory import non_git_inventory


def discover(root, **overrides):
    limits = dict(max_entries=100, max_directories=10, max_depth=3,
                  max_name_bytes=10_000)
    limits.update(overrides)
    return non_git_inventory(root, {'.git', 'node_modules'}, **limits)


class Entry:
    def __init__(self, name, *, directory=False, junction=False, symlink=False):
        self.name, self.directory, self.junction = name, directory, junction
        self.symlink = symlink
        self.inspected = 0

    def is_symlink(self):
        self.inspected += 1
        return self.symlink

    def is_junction(self):
        return self.junction

    def is_dir(self, *, follow_symlinks):
        assert follow_symlinks is False
        assert not self.junction and not self.symlink
        return self.directory


class Scan:
    def __init__(self, count):
        self.count, self.yielded, self.closed = count, [], False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def __iter__(self):
        for index in range(self.count):
            entry = Entry(f'module_{index}.py')
            self.yielded.append(entry)
            yield entry


class EntryScan(Scan):
    def __init__(self, entries):
        super().__init__(0)
        self.entries = entries

    def __iter__(self):
        return iter(self.entries)


def test_large_directory_does_not_materialize_or_inspect_the_unbounded_tail(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = Scan(1_000_000)
    monkeypatch.setattr(task_inventory.os, 'scandir', lambda path: scan)
    names, limitations = discover(tmp_path, max_entries=3)
    assert names == [f'module_{index}.py' for index in range(3)]
    assert len(scan.yielded) == 4 and scan.closed
    assert [entry.inspected for entry in scan.yielded] == [1, 1, 1, 0]
    assert limitations == [dict(reason='SNAPSHOT_INVENTORY_ENTRY_BUDGET',
        limit=3, used=3, observed_at_least=4, pending_count_unknown=True)]
    assert not any('pending_count' in item for item in limitations)


def test_exact_entry_capacity_is_complete_when_there_is_no_tail(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = Scan(3)
    monkeypatch.setattr(task_inventory.os, 'scandir', lambda path: scan)
    names, limitations = discover(tmp_path, max_entries=3)
    assert len(names) == 3 and not limitations and scan.closed


def test_name_byte_limit_stops_before_entry_inspection_and_closes_handle(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = Scan(1_000_000)
    monkeypatch.setattr(task_inventory.os, 'scandir', lambda path: scan)
    names, limitations = discover(tmp_path, max_name_bytes=len('module_0.py'.encode()))
    assert names == ['module_0.py'] and len(scan.yielded) == 2 and scan.closed
    assert scan.yielded[-1].inspected == 0
    assert limitations == [dict(reason='SNAPSHOT_INVENTORY_NAME_BYTE_BUDGET',
        limit=11, used=11, required=11, pending_count_unknown=True)]


def test_real_tree_skips_ignored_and_temporary_directories_without_opening_them(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    for name in ('node_modules', '.test-tmp', '.test-tmp-one', 'src'):
        (tmp_path/name).mkdir()
        (tmp_path/name/'sample.py').write_text('value = 1\n')
    (tmp_path/'notes.txt').write_text('not yet filtered by source type')
    original, opened = task_inventory.os.scandir, []

    def tracked(path):
        opened.append(Path(path))
        return original(path)

    monkeypatch.setattr(task_inventory.os, 'scandir', tracked)
    names, limitations = discover(tmp_path)
    assert set(names) == {'notes.txt', 'src/sample.py'} and not limitations
    assert set(opened) == {tmp_path, tmp_path/'src'}


def test_directory_budget_is_checked_before_opening_queued_subdirectories(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    for name in ('a', 'b'):
        (tmp_path/name).mkdir()
        (tmp_path/name/'inside.py').write_text('value = 1\n')
    (tmp_path/'main.py').write_text('value = 1\n')
    original, opened = task_inventory.os.scandir, []

    def tracked(path):
        opened.append(Path(path))
        return original(path)

    monkeypatch.setattr(task_inventory.os, 'scandir', tracked)
    names, limitations = discover(tmp_path, max_directories=1)
    assert names == ['main.py'] and opened == [tmp_path]
    assert limitations[0]['reason'] == 'SNAPSHOT_INVENTORY_DIRECTORY_BUDGET'
    assert limitations[0]['used'] == 1 and limitations[0]['observed_at_least'] == 2
    assert limitations[0]['pending_count_unknown']


def test_depth_limit_retains_allowed_files_and_reports_excluded_subtree(tmp_path):
    (tmp_path/'a'/'b').mkdir(parents=True)
    (tmp_path/'a'/'allowed.py').write_text('value = 1\n')
    (tmp_path/'a'/'b'/'excluded.py').write_text('value = 1\n')
    names, limitations = discover(tmp_path, max_depth=1)
    assert names == ['a/allowed.py']
    assert limitations == [dict(reason='LINK_OR_DEPTH_EXCLUDED', path='a/b')]


def test_junction_entry_is_never_queued_or_opened(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = EntryScan([Entry('outside', directory=True, junction=True)])
    opened = []

    def tracked(path):
        opened.append(Path(path))
        assert Path(path) == tmp_path
        return scan

    monkeypatch.setattr(task_inventory.os, 'scandir', tracked)
    names, limitations = discover(tmp_path)
    assert names == [] and opened == [tmp_path] and scan.closed
    assert limitations == [dict(reason='LINK_OR_DEPTH_EXCLUDED', path='outside')]


def test_symlink_entry_is_excluded_without_following_its_type(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = EntryScan([Entry('outside', directory=True, symlink=True)])
    monkeypatch.setattr(task_inventory.os, 'scandir', lambda path: scan)
    names, limitations = discover(tmp_path)
    assert names == [] and scan.closed
    assert limitations == [dict(reason='LINK_OR_DEPTH_EXCLUDED', path='outside')]


def test_ignored_entries_still_consume_actual_discovery_capacity(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    scan = EntryScan([Entry('node_modules', directory=True), Entry('.git', directory=True)])
    monkeypatch.setattr(task_inventory.os, 'scandir', lambda path: scan)
    names, limitations = discover(tmp_path, max_entries=1)
    assert names == [] and scan.closed
    assert limitations[0]['reason'] == 'SNAPSHOT_INVENTORY_ENTRY_BUDGET'
    assert limitations[0]['observed_at_least'] == 2
    assert limitations[0]['pending_count_unknown']


def test_queued_directory_is_rechecked_for_link_replacement(tmp_path, monkeypatch):
    from security_runtime import task_inventory
    (tmp_path/'a').mkdir()
    scan = EntryScan([Entry('a', directory=True)])
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda path:
        (path == tmp_path/'a' and scan.closed) or original(path))
    opened = []

    def tracked(path):
        opened.append(Path(path))
        return scan

    monkeypatch.setattr(task_inventory.os, 'scandir', tracked)
    names, limitations = discover(tmp_path)
    assert names == [] and opened == [tmp_path]
    assert limitations == [dict(reason='LINK_OR_DEPTH_EXCLUDED', path='a')]


def test_unavailable_directory_returns_closed_reason_without_exception_text(tmp_path, monkeypatch):
    from security_runtime import task_inventory

    def rejected(path):
        raise PermissionError('private-exception-canary')

    monkeypatch.setattr(task_inventory.os, 'scandir', rejected)
    names, limitations = discover(tmp_path)
    assert names == [] and limitations == [dict(reason='INVENTORY_DIRECTORY_UNAVAILABLE', path='.')]
    assert 'private-exception-canary' not in str(limitations)


@pytest.mark.parametrize('overrides', [dict(max_entries=True), dict(max_entries=0),
    dict(max_directories=0), dict(max_depth=-1), dict(max_name_bytes=0)])
def test_invalid_discovery_limits_are_rejected_without_enumerating(tmp_path, overrides):
    with pytest.raises(ValueError, match='Invalid non-Git inventory capacity'):
        discover(tmp_path, **overrides)
