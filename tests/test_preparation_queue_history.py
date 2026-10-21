"""Historical and invalid rows cannot hide newly admitted preparation work."""
import json
import sqlite3

import pytest

from security_runtime.background_preparation import MAX_PENDING, MAX_WAITER_CANDIDATES
from security_runtime.closeout_state import digest
from test_background_preparation import job, waiter, run
from test_personal_install_readiness import readiness


def insert_history(store, item, key, count, *, status='COMPLETED', valid=True):
    with sqlite3.connect(store.path) as db:
        # Place history before the existing pending row, as in a long-lived DB.
        db.execute('DELETE FROM waiting')
        for number in range(count):
            old = dict(item, closeout_ref=f'co1-{number:032x}', status=status)
            db.execute('INSERT INTO waiting VALUES(?,?,?,?)',
                (old['workspace'], old['closeout_ref'], json.dumps(old),
                 digest(key, old) if valid else 'invalid'))
        db.execute('INSERT INTO waiting VALUES(?,?,?,?)',
            (item['workspace'], item['closeout_ref'], json.dumps(item), digest(key, item)))


@pytest.mark.parametrize('status', ['COMPLETED', 'NEEDS_RETRY', 'FAILED'])
def test_old_terminal_rows_do_not_hide_new_waiter(job, tmp_path, status):
    root, hooks = waiter(job, tmp_path)
    store = job[0]
    item = store.waiters()[0]
    insert_history(store, item, hooks.key(root), MAX_PENDING + 1, status=status)
    assert store.waiters() == [item]
    calls = []
    assert run(job, prepare=lambda **kw: readiness(),
               resume=lambda command, value: calls.append(value) or 'COMPLETED') == 0
    assert calls == [item]
    assert store.waiters() == []


def test_invalid_signatures_do_not_mask_later_valid_work(job, tmp_path):
    root, hooks = waiter(job, tmp_path)
    store = job[0]
    item = store.waiters()[0]
    insert_history(store, item, hooks.key(root), MAX_PENDING,
                   status='WAITING', valid=False)
    assert store.waiters() == [item]


def test_candidate_limit_is_not_reported_as_an_empty_queue(job, tmp_path):
    root, hooks = waiter(job, tmp_path)
    store = job[0]
    item = store.waiters()[0]
    insert_history(store, item, hooks.key(root), MAX_WAITER_CANDIDATES,
                   status='WAITING', valid=False)
    with pytest.raises(ValueError, match='inspection budget'):
        store.waiters()


def test_malformed_history_does_not_abort_waiter_query(job, tmp_path):
    waiter(job, tmp_path)
    store = job[0]
    item = store.waiters()[0]
    with sqlite3.connect(store.path) as db:
        db.execute('INSERT INTO waiting VALUES(?,?,?,?)', ('invalid', 'old', '{', 'invalid'))
    assert store.waiters() == [item]
