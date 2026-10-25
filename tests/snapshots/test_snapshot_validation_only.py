"""Whole raw validation before GC, with no main-database mutation or repair."""
from dataclasses import replace
import hashlib
import sqlite3
import tracemalloc

import pytest

from security_runtime.snapshot_store import SnapshotStore, SnapshotStoreError
from test_snapshot_copy_page import KEY, capture, sample


def fingerprint(store):
    return {path.name:(path.stat().st_mode,path.stat().st_mtime_ns,hashlib.sha256(path.read_bytes()).hexdigest())
            for path in store.directory.iterdir() if path.is_file()}


def test_all_prefix_states_validate_without_delete_usage_update_or_main_writes(sample,monkeypatch):
    store,binding=sample
    capture(store,binding)
    capture(store,replace(binding,task_ref='prefix'),seal=False)
    waiting=replace(binding,task_ref='waiting')
    header=store.create(waiting)
    constrained=SnapshotStore(store.directory,workspace_root=store.root,key=KEY,max_storage_bytes=210000)
    assert constrained.append_page(header['ref'],waiting,[('large.py',b'x'*100000)],expected_cursor=None,cursor='1')['state']=='WAITING_CAPACITY'
    before=fingerprint(store)
    def forbidden(*args): pytest.fail('Validation attempted to update persistent usage')
    monkeypatch.setattr(store,'_set_usage',forbidden)
    result=store.validate_contents()
    assert result['validated'] is True and result['mutated'] is False
    assert result['captures']==3 and result['entries']==4 and result['logical_bytes']>3*65536
    assert fingerprint(store)==before
    assert store.strict_header(header['ref'],waiting)['state']=='WAITING_CAPACITY'


@pytest.mark.parametrize('damage,reason',[('header_mac','SNAPSHOT_RECORD_INVALID'),
    ('entry_mac','SNAPSHOT_RECORD_INVALID'),('hole','SNAPSHOT_RECORD_INVALID'),
    ('body','SNAPSHOT_CONTENT_UNAVAILABLE'),('usage_mac','SNAPSHOT_RECORD_INVALID'),
    ('usage_replay','SNAPSHOT_USAGE_MISMATCH')])
def test_invalid_raw_history_never_mutates_or_repairs_itself(sample,damage,reason):
    store,binding=sample
    header=capture(store,binding)
    with sqlite3.connect(store.path) as db:
        if damage=='header_mac': db.execute('UPDATE captures SET mac=?',('0'*64,))
        elif damage=='entry_mac': db.execute('UPDATE entries SET mac=?',('0'*64,))
        elif damage=='hole': db.execute('DELETE FROM entries WHERE seq=1')
        elif damage=='body': db.execute('UPDATE objects SET body=?',(b'wrong',))
        elif damage=='usage_mac': db.execute('UPDATE usage SET mac=?',('0'*64,))
        else:
            value=1
            db.execute('UPDATE usage SET bytes=?,mac=?',(value,store._mac(dict(used=value))))
    before=fingerprint(store)
    with pytest.raises(SnapshotStoreError,match='^'+reason+'$'): store.validate_contents()
    assert fingerprint(store)==before


@pytest.mark.parametrize('table',['captures','entries'])
def test_huge_bad_signed_record_columns_are_not_loaded_into_python(sample,table):
    store,binding=sample
    capture(store,binding)
    with sqlite3.connect(store.path) as db: db.execute(f'UPDATE {table} SET data=zeroblob(16000000)')
    before=fingerprint(store)
    tracemalloc.start()
    try:
        with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_RECORD_INVALID$'): store.validate_contents()
        peak=tracemalloc.get_traced_memory()[1]
    finally: tracemalloc.stop()
    assert peak<1000000 and fingerprint(store)==before


def test_domain_witness_never_loads_a_huge_header_into_python(sample):
    store,binding=sample
    capture(store,binding)
    with sqlite3.connect(store.path) as db: db.execute('UPDATE captures SET data=zeroblob(16000000)')
    before=fingerprint(store)
    tracemalloc.start()
    try:
        with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_RECORD_INVALID$'):
            store.has_retention_domain('TASK_CAPTURE_SOURCE_V2')
        peak=tracemalloc.get_traced_memory()[1]
    finally: tracemalloc.stop()
    assert peak<1000000 and fingerprint(store)==before


def test_large_corrupt_object_is_hashed_in_bounded_chunks_without_repair(sample):
    store,binding=sample
    capture(store,binding)
    with sqlite3.connect(store.path) as db: db.execute('UPDATE objects SET body=zeroblob(16000000)')
    before=fingerprint(store)
    tracemalloc.start()
    try:
        with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_CONTENT_UNAVAILABLE$'): store.validate_contents()
        peak=tracemalloc.get_traced_memory()[1]
    finally: tracemalloc.stop()
    assert peak<1000000 and fingerprint(store)==before


def test_absent_store_and_existing_journal_are_never_initialized_or_recovered(sample):
    store,binding=sample
    with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_HISTORY_UNAVAILABLE$'): store.validate_contents()
    assert not store.directory.exists()
    capture(store,binding)
    journal=store.path.with_name(store.path.name+'-journal')
    journal.write_bytes(b'caller-owned incomplete journal')
    journal.chmod(0o600)
    before=fingerprint(store)
    with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_READER_JOURNAL_BUSY$'): store.validate_contents()
    assert fingerprint(store)==before


def test_valid_gapped_seal_remains_valid_raw_history_without_coverage_claim(sample):
    store,binding=sample
    header=capture(store,binding,seal=False)
    store.seal(header['ref'],binding,expected_files=None,inventory_complete=False,gap_count=1)
    before=fingerprint(store)
    assert store.validate_contents()['validated'] is True
    assert store.strict_header(header['ref'],binding)['coverage_complete'] is False
    assert fingerprint(store)==before


def test_domain_witness_authenticates_unsealed_history_without_body_claim(sample):
    store,binding=sample
    capture(store,binding)
    assert store.has_retention_domain('TASK_CAPTURE_SOURCE_V2') is False
    capture(store,replace(binding,task_ref='v2-prefix',retention_domain='TASK_CAPTURE_SOURCE_V2'),seal=False)
    before=fingerprint(store)
    assert store.has_retention_domain('TASK_CAPTURE_SOURCE_V2') is True
    assert fingerprint(store)==before
    # A witness is header-only. Body verification remains validate_contents().
    with sqlite3.connect(store.path) as db: db.execute('UPDATE objects SET body=?',(b'corrupt',))
    assert store.has_retention_domain('TASK_CAPTURE_SOURCE_V2') is True
    with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_CONTENT_UNAVAILABLE$'): store.validate_contents()


def test_domain_scan_never_stops_before_a_later_bad_header(sample):
    store,binding=sample
    capture(store,replace(binding,retention_domain='TASK_CAPTURE_SOURCE_V2'))
    later=capture(store,replace(binding,task_ref='later'))
    with sqlite3.connect(store.path) as db: db.execute('UPDATE captures SET mac=? WHERE ref=?',('0'*64,later['ref']))
    before=fingerprint(store)
    with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_RECORD_INVALID$'):
        store.has_retention_domain('TASK_CAPTURE_SOURCE_V2')
    assert fingerprint(store)==before


@pytest.mark.parametrize('domain',[True,None,'','x'*129,'\ud800'])
def test_domain_request_is_strict_and_never_initializes_storage(sample,domain):
    store,_=sample
    with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_PAGE_REQUEST_INVALID$'): store.has_retention_domain(domain)
    assert not store.directory.exists()


def test_domain_scan_resource_bound_does_not_return_a_prefix_false(sample,monkeypatch):
    store,binding=sample
    capture(store,binding)
    capture(store,replace(binding,task_ref='second'))
    # Only reduce the witness-count policy; preserve the real private DB.
    with monkeypatch.context() as scoped:
        scoped.setattr(store,'database_quota',65536)
        capture(store,replace(binding,task_ref='third'))
        with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_REFERENCE_INVENTORY_BUDGET$'):
            store.has_retention_domain('TASK_CAPTURE_SOURCE_V2')
