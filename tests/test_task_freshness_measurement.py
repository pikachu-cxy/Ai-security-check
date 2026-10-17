"""Freshness remains content-based when unused text preparation is omitted."""
import os

import pytest

from security_runtime import task_security as ts
from security_runtime.local_evidence import EvidenceUnavailable
from test_task_security import service, prepared


def test_hash_only_capture_preserves_inventory_hashes_and_failures(service, monkeypatch):
    s, root, _ = service
    (root/'binary.py').write_bytes(b'\0binary')
    # A long identifier is fully masked as a possible credential. Exercise
    # actual display truncation with ordinary source operators instead.
    (root/'wide.py').write_text('value = '+'1 + '*200+'1\n')
    text = ts.capture(root)
    calls = []
    monkeypatch.setattr(ts, 'safe_source', lambda value, **kw: calls.append(value))
    digest = ts.capture(root, include_text=False)
    assert not calls and digest['texts'] == {} and digest['text_truncations'] == {}
    for key in ('hashes','limitations','inventory','inventory_complete','read_priority'):
        assert digest[key] == text[key]
    assert text['text_truncations']['wide.py']


def test_fresh_still_reads_all_files_and_read_only_sanitizes_requested_file(service, monkeypatch):
    s, root, _ = service
    ref, session, _ = prepared(service)
    reads, sanitized = [], []
    original_read, original_safe = ts.WorkspaceReader.read, ts.safe_source
    def read(reader, name, *a, **kw):
        reads.append(name)
        return original_read(reader, name, *a, **kw)
    def safe(text, **kw):
        sanitized.append(text)
        return original_safe(text, **kw)
    monkeypatch.setattr(ts.WorkspaceReader, 'read', read)
    monkeypatch.setattr(ts, 'safe_source', safe)
    packet = s.read(root, ref, session, 'routes.py', 1, 2)
    assert set(reads) == {'routes.py','service.py','auth.py'}
    assert reads.count('routes.py') == 2
    assert len(sanitized) == 1 and packet['location_version'] == 'CURRENT_TASK_END'


def test_same_size_external_last_edit_preserving_mtime_is_stale(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    path = root/'auth.py'
    before = path.stat()
    raw = path.read_bytes()
    path.write_bytes(raw.replace(b'==', b'!='))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ValueError, match='stale'):
        s.read(root, ref, session, 'routes.py', 1, 2)
    assert s.get(root, ref)['status'] == 'STALE'


def test_rapid_last_edit_and_revert_checks_current_bytes_without_hook(service):
    s, root, _ = service
    ref, session, _ = prepared(service)
    path = root/'auth.py'
    raw = path.read_bytes()
    path.write_bytes(b'first external edit\n')
    path.write_bytes(b'last external edit\n')
    assert s.get(root, ref)['status'] == 'STALE'
    path.write_bytes(raw)
    assert s.get(root, ref)['current_version'] is True
    assert s.read(root, ref, session, 'routes.py', 1, 2)['file_sha256']


def test_read_failure_during_freshness_rejects_existing_evidence(service, monkeypatch):
    s, root, _ = service
    ref, session, _ = prepared(service)
    original = ts.WorkspaceReader.read
    def read(reader, path, *a, **kw):
        if path == 'auth.py': raise EvidenceUnavailable('SOURCE_UNAVAILABLE')
        return original(reader, path, *a, **kw)
    monkeypatch.setattr(ts.WorkspaceReader, 'read', read)
    with pytest.raises(ValueError, match='stale'):
        s.read(root, ref, session, 'routes.py', 1, 2)


def test_changed_rule_and_config_inventory_cannot_be_reused(service, monkeypatch):
    s, root, _ = service
    (root/'rule.yml').write_text('rules: []\n')
    (root/'config.toml').write_text('enabled = true\n')
    ref, session, _ = prepared(service)
    (root/'rule.yml').write_text('rules: [changed]\n')
    assert s.get(root, ref)['status'] == 'STALE'
    (root/'rule.yml').write_text('rules: []\n')
    (root/'config.toml').write_text('enabled = false\n')
    assert s.get(root, ref)['status'] == 'STALE'
    (root/'config.toml').write_text('enabled = true\n')
    monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'config.toml')
    assert s.get(root, ref)['status'] == 'STALE'


def test_faster_hash_path_at_five_second_budget_is_conservatively_stale(service, monkeypatch):
    s, root, _ = service
    ticks = [0.0]
    original_safe = ts.safe_source
    def slow_safe(text, **kw):
        ticks[0] += 3.0
        return original_safe(text, **kw)
    # Stub only inventory overhead and the clock: all file reads/hashes are real.
    monkeypatch.setattr(ts, '_inventory', lambda root, ignored: (['auth.py','routes.py','service.py'], [], True, []))
    monkeypatch.setattr(ts.time, 'monotonic', lambda: ticks[0])
    monkeypatch.setattr(ts, 'safe_source', slow_safe)
    old = ts.capture(root)
    assert len(old['hashes']) == 2 and old['limitations'] == [{'reason':'INVENTORY_READ_BUDGET'}]
    ticks[0] = 0.0
    fast = ts.capture(root, include_text=False)
    assert len(fast['hashes']) == 3 and fast['limitations'] == []
    # Same unmodified bytes; additional coverage never makes old proof current.
    record = dict(baseline=old, end=old)
    ticks[0] = 0.0
    assert s._fresh(root, record) is False
