"""Retired history cannot consume new v3 slots or bypass signed-state bounds."""
import copy
import sqlite3
from contextlib import closing
from uuid import uuid4

import pytest

from security_runtime.task_security_state import MAX_HISTORY_RECORDS, MAX_V3_RECORDS
from test_task_security import service  # noqa: F401


def rows(store):
    with closing(sqlite3.connect(store.path)) as db:
        return dict((ref, (data, mac)) for ref, data, mac in
                    db.execute('SELECT ref,data,mac FROM security_tasks'))


def inventory(sample, protocol, count):
    s, root, _ = sample
    ref = s.begin(root, 'capacity-seed')['task_ref']
    assert s.finish(root, ref)['status'] == 'NO_CHANGES'
    store = s.store(root)
    template = s.load(root, ref)
    refs = []
    for index in range(count):
        record = copy.deepcopy(template)
        if index:
            record.update(task_ref='ts1-'+uuid4().hex,
                          task_key=s.key('capacity-'+str(index)), generation=0)
            record = store.save(record, new=True)
        if protocol != 3:
            if protocol is None:
                record.pop('review_protocol')
            else:
                record['review_protocol'] = protocol
            record = store.save(record)
        refs.append(record['task_ref'])
    return store, refs


@pytest.mark.parametrize('protocol', [1, 2, None])
def test_full_retired_inventory_preserves_every_row_and_allows_new_work(service, protocol):
    s, root, runtime = service
    store, refs = inventory(service, protocol, MAX_V3_RECORDS)
    original = rows(store)
    new = s.begin(root, 'new-independent-work')
    assert new['status'] == 'ACTIVE' and new['review_protocol'] == 3
    saved = rows(store)
    assert len(saved) == MAX_V3_RECORDS+1
    assert all(saved[ref] == raw for ref, raw in original.items())
    assert {item['task_ref'] for item in store.records()} == set(refs+[new['task_ref']])
    before_queries = rows(store)
    for ref in refs:
        result = s.get(root, ref)
        assert result['status'] == 'NO_CHANGES' and result['history_read_only'] is True
        assert result['protocol_version'] == protocol
        assert result['protocol_support']['reason_code'] == 'UNSUPPORTED_TASK_REVIEW_PROTOCOL'
    assert rows(store) == before_queries and not runtime.calls


def test_v3_task_allowance_still_rejects_the_thirty_third_record(service):
    s, root, _ = service
    store, _ = inventory(service, 3, MAX_V3_RECORDS)
    original = rows(store)
    with pytest.raises(ValueError, match='history budget'):
        s.begin(root, 'over-native-task-allowance')
    assert rows(store) == original
    assert MAX_HISTORY_RECORDS == 2*MAX_V3_RECORDS == 64


def test_new_admission_verifies_legacy_signatures_before_counting_slots(service):
    s, root, _ = service
    store, refs = inventory(service, 2, 1)
    with closing(sqlite3.connect(store.path)) as db, db:
        db.execute('UPDATE security_tasks SET mac=? WHERE ref=?', ('0'*64, refs[0]))
    original = rows(store)
    with pytest.raises(ValueError, match='cannot be verified'):
        s.begin(root, 'cannot-ignore-tampered-history')
    assert rows(store) == original


def test_combined_history_reserve_has_a_hard_bound_without_deleting_rows(service):
    s, root, _ = service
    store, _ = inventory(service, 2, MAX_HISTORY_RECORDS)
    original = rows(store)
    with pytest.raises(ValueError, match='history budget'):
        s.begin(root, 'over-combined-history-reserve')
    assert rows(store) == original and len(original) == MAX_HISTORY_RECORDS
