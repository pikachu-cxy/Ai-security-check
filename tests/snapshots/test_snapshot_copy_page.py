"""Bounded raw copy reads; no task publisher, live capture or scanner."""
from dataclasses import replace
import hashlib
import sqlite3
import tracemalloc

import pytest

from security_runtime.snapshot_reader import SealedSnapshotReader
from security_runtime.closeout_state import encode
from security_runtime.snapshot_store import SnapshotBinding, SnapshotStore, SnapshotStoreError


KEY = b'p' * 32
OWNER = dict(host='codex', session='a' * 64)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / 'source'
    root.mkdir()
    store = SnapshotStore(tmp_path / 'private', workspace_root=root, key=KEY)
    binding = SnapshotBinding('original', OWNER, 'original-source', 3)
    return store, binding


def capture(store, binding, entries=None, *, seal=True):
    entries = entries if entries is not None else [('one.py', b'original-one'), ('two.py', b'original-two')]
    header = store.create(binding)
    if entries:
        header = store.append_page(header['ref'], binding, entries, expected_cursor=None, cursor='original-cursor')
    return store.seal(header['ref'], binding, expected_files=len(entries), inventory_complete=True) if seal else header


def anchor(header):
    return {key: header[key] for key in ('root_digest', 'entry_count', 'source_bytes')}


def test_real_same_database_read_closes_before_append_and_preserves_raw_bytes(sample, monkeypatch):
    store, binding = sample
    original = capture(store, binding)
    target_binding = replace(binding, task_ref='copy')
    target = store.create(target_binding)
    def forbidden(*args):
        pytest.fail('Each copy turn must not scan the complete raw inventory')
    monkeypatch.setattr(SealedSnapshotReader, '_verify_inventory', forbidden)
    page = store.strict_copy_page(original['ref'], binding, limit_files=1, expected_header=anchor(original))
    assert page['next_seq'] == 1 and not page['at_end']
    assert page['inventory_verified'] is page['source_digest_verified'] is False
    assert page['entries'][0]['content'] == b'original-one'
    # A leaked SHARED read transaction would block this actual same-DB commit.
    target = store.append_page(target['ref'], target_binding,
        [(item['path'], item['content'], item['metadata']) for item in page['entries']],
        expected_cursor=None, cursor='1')
    tail = store.strict_copy_page(original['ref'], binding, after_seq=page['next_seq'])
    assert tail['next_seq'] == 2 and tail['at_end']
    target = store.append_page(target['ref'], target_binding,
        [(item['path'], item['content'], item['metadata']) for item in tail['entries']],
        expected_cursor='1', cursor='2')
    store.seal(target['ref'], target_binding, expected_files=2, inventory_complete=True)
    assert store.strict_header(original['ref'], binding) == original
    assert store.read_content(target['ref'], target_binding, 'two.py') == b'original-two'


@pytest.mark.parametrize('state', ['CAPTURING', 'WAITING_CAPACITY', 'SEALED'])
def test_strict_header_accepts_authenticated_prefix_states_without_sealing(sample, state):
    store, binding = sample
    header = capture(store, binding, seal=state == 'SEALED')
    if state == 'WAITING_CAPACITY':
        constrained = SnapshotStore(store.directory, workspace_root=store.root, key=KEY, max_storage_bytes=66000)
        header = constrained.append_page(header['ref'], binding, [('large.py', b'x' * 10000)],
                                         expected_cursor=header['cursor'], cursor='next')
        assert header['state'] == state
    before = store.path.read_bytes()
    assert store.strict_header(header['ref'], binding) == header
    assert store.path.read_bytes() == before
    if state != 'SEALED':
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_NOT_SEALED$'):
            store.strict_copy_page(header['ref'], binding)


def test_declared_incomplete_seal_cannot_supply_copy_pages(sample):
    store, binding = sample
    header = capture(store, binding, seal=False)
    store.seal(header['ref'], binding, expected_files=None, inventory_complete=False, gap_count=1)
    assert store.strict_header(header['ref'], binding)['coverage_complete'] is False
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_COVERAGE_INCOMPLETE$'):
        store.strict_copy_page(header['ref'], binding)


def test_anchor_mismatch_and_wrong_binding_are_not_reinterpreted(sample):
    store, binding = sample
    header = capture(store, binding)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_COPY_SOURCE_MISMATCH$'):
        store.strict_copy_page(header['ref'], binding, expected_header=dict(anchor(header), root_digest='f' * 64))
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_BINDING_MISMATCH$'):
        store.strict_header(header['ref'], replace(binding, owner=dict(host='cursor', session='b' * 64)))


@pytest.mark.parametrize('kwargs', [dict(after_seq=True), dict(after_seq=-1), dict(after_seq=3),
    dict(limit_files=0), dict(limit_files=257), dict(limit_bytes=0), dict(limit_bytes=8000001),
    dict(expected_header={}), dict(expected_header=dict(root_digest='a'*64,entry_count=True,source_bytes=0))])
def test_request_budgets_and_anchor_shape_are_exact(sample, kwargs):
    store, binding = sample
    header = capture(store, binding)
    with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_REQUEST_INVALID$'):
        store.strict_copy_page(header['ref'], binding, **kwargs)


def test_byte_budget_matches_append_and_never_fetches_an_oversized_body(sample, monkeypatch):
    store, binding = sample
    header = capture(store, binding, [('large.py', b'x' * 70000)])
    def forbidden(*args, **kwargs):
        pytest.fail('Body access happened before the page byte budget check')
    with monkeypatch.context() as scoped:
        scoped.setattr(SealedSnapshotReader, 'read_content', forbidden)
        with pytest.raises(SnapshotStoreError, match='^SNAPSHOT_PAGE_BYTE_BUDGET$'):
            store.strict_copy_page(header['ref'], binding, limit_bytes=1000)
    page = store.strict_copy_page(header['ref'], binding, limit_bytes=80000)
    assert page['entries'][0]['content'] == b'x' * 70000
    assert 70000 < page['payload_bytes'] <= 80000
    target_binding = replace(binding, task_ref='byte-copy')
    target = store.create(target_binding)
    copied = store.append_page(target['ref'], target_binding,
        [(item['path'],item['content'],item['metadata']) for item in page['entries']],
        expected_cursor=None,cursor='1')
    assert copied['source_bytes'] == 70000


def test_byte_limited_short_page_cannot_claim_the_complete_tail(sample):
    store,binding=sample
    header=capture(store,binding)
    original=store.strict_copy_page(header['ref'],binding)['entries'][0]
    payload={key:value for key,value in original.items() if key not in {'ref','seq','content'}}
    budget=original['size']+len(encode(payload))
    first=store.strict_copy_page(header['ref'],binding,limit_bytes=budget)
    assert first['next_seq']==1 and first['payload_bytes']==budget and not first['at_end']
    tail=store.strict_copy_page(header['ref'],binding,after_seq=1,limit_bytes=budget)
    assert tail['next_seq']==2 and tail['at_end'] and len(tail['entries'])==1


@pytest.mark.parametrize('damage,reason', [('hole','SNAPSHOT_HISTORY_UNAVAILABLE'),
    ('entry_mac','SNAPSHOT_RECORD_INVALID'), ('seq_type','SNAPSHOT_RECORD_INVALID'),
    ('body','SNAPSHOT_CONTENT_UNAVAILABLE')])
def test_each_selected_entry_and_original_body_are_verified(sample, damage, reason):
    store,binding=sample
    header=capture(store,binding)
    with sqlite3.connect(store.path) as db:
        if damage=='hole': db.execute('DELETE FROM entries WHERE ref=? AND seq=1',(header['ref'],))
        elif damage=='entry_mac': db.execute('UPDATE entries SET mac=? WHERE ref=?',('0'*64,header['ref']))
        elif damage=='seq_type': db.execute('UPDATE entries SET seq=? WHERE ref=? AND seq=1',(1.5,header['ref']))
        else: db.execute('UPDATE objects SET body=? WHERE hash=?',(b'changed',hashlib.sha256(b'original-one').hexdigest()))
    with pytest.raises(SnapshotStoreError,match='^'+reason+'$'):
        store.strict_copy_page(header['ref'],binding)


@pytest.mark.parametrize('table', ['captures','entries'])
def test_giant_damaged_record_is_sql_guarded_before_python_allocation(sample, table):
    store,binding=sample
    header=capture(store,binding)
    with sqlite3.connect(store.path) as db:
        db.execute(f'UPDATE {table} SET data=zeroblob(16000000) WHERE ref=?',(header['ref'],))
    tracemalloc.start()
    try:
        with pytest.raises(SnapshotStoreError,match='^SNAPSHOT_RECORD_INVALID$'):
            store.strict_copy_page(header['ref'],binding)
        peak=tracemalloc.get_traced_memory()[1]
    finally: tracemalloc.stop()
    assert peak<1000000


def test_empty_source_and_tail_are_explicit_without_appendable_empty_pages(sample):
    store,binding=sample
    header=capture(store,binding,[])
    page=store.strict_copy_page(header['ref'],binding)
    assert page['entries']==[] and page['next_seq']==0 and page['at_end'] and page['payload_bytes']==0


def test_1001_records_copy_all_pages_and_original_tail_after_reopen(sample):
    store,binding=sample
    header=store.create(binding)
    for first in range(0,1001,128):
        rows=[(f'file_{i:04}.py',f'original={i}\n'.encode()) for i in range(first,min(first+128,1001))]
        header=store.append_page(header['ref'],binding,rows,expected_cursor=header['cursor'],cursor=str(first+len(rows)))
    header=store.seal(header['ref'],binding,expected_files=1001,inventory_complete=True)
    seen,after=0,0
    while True:
        reopened=SnapshotStore(store.directory,workspace_root=store.root,key=KEY)
        page=reopened.strict_copy_page(header['ref'],binding,after_seq=after,limit_files=128,expected_header=anchor(header))
        for entry in page['entries']:
            assert entry['path']==f'file_{seen:04}.py' and entry['content']==f'original={seen}\n'.encode()
            seen+=1
        after=page['next_seq']
        if page['at_end']: break
    assert seen==after==1001
    assert store.strict_copy_page(header['ref'],binding,after_seq=1001)['entries']==[]
