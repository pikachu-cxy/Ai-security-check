"""Retention optimization keeps both tables' existing hard bounds on every write."""
from contextlib import closing
import time

import pytest

from security_runtime import context_cost
from security_runtime.context_cost import ContextCostStore


@pytest.fixture
def store(tmp_path, monkeypatch):
    for name in ('SECURITY_RUNTIME_CONTEXT_MODE', 'SECURITY_RUNTIME_CONTEXT_MONITOR',
                 'SECURITY_RUNTIME_CONTEXT_RUN'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('SECURITY_RUNTIME_CONTEXT_MODE', 'basic')
    return ContextCostStore(tmp_path / 'metrics.sqlite3')


def seed(db, events, imports):
    db.executemany('INSERT INTO events(id,at,run,record,mac) VALUES(?,?,?,?,?)',
                   [(index, at, 'synthetic', b'{}', '') for index, at in events])
    db.executemany('INSERT INTO host_usage(source,at,run,record,mac) VALUES(?,?,?,?,?)',
                   [(str(index), at, 'synthetic', b'{}', '') for index, at in imports])


@pytest.mark.parametrize('count', [0, 1, 4, 5, 8])
def test_count_bounds_keep_newest_rows_including_empty_and_exact_limit(store, monkeypatch, count):
    monkeypatch.setattr(context_cost, 'MAX_EVENTS', 5)
    monkeypatch.setattr(context_cost, 'MAX_HOST_IMPORTS', 3)
    now = time.time()
    db, _ = store._connect(write=True)
    with closing(db), db:
        seed(db, [(index, now + index) for index in range(1, count + 1)],
             [(index, now + index) for index in range(1, count + 1)])
        store._prune(db)
        events = [row[0] for row in db.execute('SELECT id FROM events ORDER BY id')]
        imports = [int(row[0]) for row in db.execute('SELECT source FROM host_usage ORDER BY at')]
    assert events == list(range(max(1, count - 4), count + 1))
    assert imports == list(range(max(1, count - 2), count + 1))


def test_event_write_expires_imports_and_enforces_both_tables_caps(store, monkeypatch):
    monkeypatch.setattr(context_cost, 'MAX_EVENTS', 5)
    monkeypatch.setattr(context_cost, 'MAX_HOST_IMPORTS', 3)
    now = time.time()
    old = now - context_cost.RETENTION_SECONDS - 1
    db, _ = store._connect(write=True)
    with closing(db), db:
        seed(db, [(1, old), *[(index, now) for index in range(2, 8)]],
             [(1, old), *[(index, now + index) for index in range(2, 7)]])
    assert store.record_call('get_runtime_info', {})['status'] == 'RECORDED'
    db, _ = store._connect()
    with closing(db):
        assert [row[0] for row in db.execute('SELECT id FROM events ORDER BY id')] == [4, 5, 6, 7, 8]
        assert [row[0] for row in db.execute('SELECT source FROM host_usage ORDER BY at')] == ['4', '5', '6']


def test_import_write_expires_events_even_when_both_tables_are_below_caps(store):
    now = time.time()
    old = now - context_cost.RETENTION_SECONDS - 1
    db, _ = store._connect(write=True)
    with closing(db), db:
        seed(db, [(1, old), (2, now)], [(1, old)])
    usage = dict(input_tokens=1, output_tokens=1)
    report = dict(import_key='a' * 64, usage=usage, streams=[dict(
        identity='thread:' + 'b' * 64, source_identity='c' * 64,
        usage=usage, basis='cumulative')])
    assert store.record_host_usage('synthetic', report)['status'] == 'RECORDED'
    db, _ = store._connect()
    with closing(db):
        assert [row[0] for row in db.execute('SELECT id FROM events')] == [2]
        assert db.execute('SELECT count(*) FROM host_usage').fetchone()[0] == 1


def test_equal_import_timestamps_still_obey_hard_limit(store, monkeypatch):
    monkeypatch.setattr(context_cost, 'MAX_HOST_IMPORTS', 3)
    db, _ = store._connect(write=True)
    with closing(db), db:
        seed(db, [], [(index, time.time() // 1000) for index in range(8)])
        # Use one current timestamp for every import; no tie-break identity is promised.
        db.execute('UPDATE host_usage SET at=?', (time.time(),))
        store._prune(db)
        assert db.execute('SELECT count(*) FROM host_usage').fetchone()[0] == 3
