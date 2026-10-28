"""Signed history and recovery boundaries for product comparison epochs."""
import hashlib
import hmac
from pathlib import Path
import shutil
import sqlite3

import pytest
from security_runtime.product_epoch_capture import platform_supported

requires_observation = pytest.mark.skipif(not platform_supported(), reason="Requires POSIX descriptor observations")

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.product_epoch_store import ProductEpochError
import security_runtime.product_epoch_store as epoch_storage


OWNER = dict(host='codex', session='a'*64)


@pytest.fixture
def current(tmp_path):
    root = tmp_path.resolve()/'source'
    root.mkdir()
    return ProductEpochService(HookStateStore(tmp_path.resolve()/'private'), root, now=lambda: 1000.0)


def finish(current):
    status = current.ensure(OWNER)
    for _ in range(1000):
        if status['state'] == 'SEALED':
            return status
        status = current.step(OWNER)
    pytest.fail('Observation failed to terminate')


def database_state(current):
    with sqlite3.connect(current.store.path) as db:
        return {name: db.execute(f'SELECT * FROM {name} ORDER BY rowid').fetchall()
                for name in ('store_identity', 'epochs', 'directories', 'members', 'observations')}


def test_absent_queries_and_rejected_owner_create_nothing(current):
    assert current.status()['state'] == 'NOT_STARTED'
    assert not current.hooks.directory.exists()
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.verify('pe1-'+'0'*32)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_OWNER_INVALID'):
        current.ensure(dict(host='codex', session='invented'))
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.lookup('pe1-'+'0'*32, ['not-yet.py'])
    assert not current.hooks.directory.exists()


@requires_observation
def test_binary_files_and_large_files_span_steps_without_retaining_body(current):
    raw = b'\xff\x00PRIVATE_RAW_BINARY_MARKER\xfe'*100
    (current.root/'binary.bin').write_bytes(raw)
    slow = ProductEpochService(current.hooks, current.root, now=current.now, policy=dict(step_bytes=64))
    first = slow.ensure(OWNER)
    result, turns = first, 0
    while result['state'] != 'SEALED' and turns < 500:
        result = slow.step(OWNER)
        turns += 1
    assert result['state'] == 'SEALED' and turns > len(raw)//64
    row = slow.lookup(result['epoch_ref'], ['binary.bin'])['results'][0]
    assert row['hash'] == hmac.new(current.hooks.key(current.root), b'hook-file-v1'+raw, hashlib.sha256).hexdigest()
    assert result['representation'] == 'HASH_ONLY' and result['body_retained'] is False
    for path in current.hooks.directory.rglob('*'):
        if path.is_file():
            assert b'PRIVATE_RAW_BINARY_MARKER' not in path.read_bytes()
    slow.close()


@requires_observation
def test_same_root_alias_and_policy_share_epoch_but_other_policy_keeps_history(current):
    (current.root/'source.py').write_bytes(b'first')
    early_peer = ProductEpochService(current.hooks, current.root, now=current.now)
    first = finish(current)
    assert early_peer.ensure(OWNER)['epoch_ref'] == first['epoch_ref']
    alias = ProductEpochService(current.hooks, current.root/'..'/'source', now=current.now)
    assert alias.root == alias.store.root == current.root
    assert alias.hooks.workspace_directory(alias.root) == current.hooks.workspace_directory(current.root)
    assert alias._writer_locks.workspace_directory(alias.root) == current._writer_locks.workspace_directory(current.root)
    with current.hooks.lock(current.root) as acquired:
        assert acquired
        with alias._locked() as alias_acquired:
            assert alias_acquired and current.hooks.lock_held(alias.root)
            assert current._writer_locks.lock_held(alias.root)
            joined = alias.ensure(dict(host='cursor', session='b'*64))
            assert joined['epoch_ref'] == first['epoch_ref'] and joined['state'] == 'SEALED'
    (current.root/'source.py').write_bytes(b'second')
    changed = ProductEpochService(current.hooks, current.root, now=current.now,
                                  policy=dict(ignored_names=['.git']))
    second = finish(changed)
    assert second['epoch_ref'] != first['epoch_ref']
    assert second['policy_digest'] != first['policy_digest']
    old = changed.verify(first['epoch_ref'])
    assert old['epoch_ref'] == first['epoch_ref'] and old['policy_digest'] == first['policy_digest']
    assert changed.lookup(first['epoch_ref'], ['source.py']) != changed.lookup(second['epoch_ref'], ['source.py'])


@pytest.mark.parametrize('missing', ['key', 'database'])
@requires_observation
def test_missing_history_is_not_rebuilt_from_changed_source(current, missing):
    (current.root/'source.py').write_bytes(b'original')
    first = finish(current)
    (current.root/'source.py').write_bytes(b'changed')
    path = current.store.path if missing == 'database' else current.hooks.workspace_directory(current.root)/'snapshot.key'
    path.unlink()
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.ensure(OWNER)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.lookup(first['epoch_ref'], ['source.py'])
    assert not path.exists()


@requires_observation
def test_replaced_root_rejects_existing_and_reopened_service(current):
    (current.root/'source.py').write_bytes(b'original')
    finish(current)
    current.root.rename(current.root.with_name('former-source'))
    current.root.mkdir()
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.status()
    reopened = ProductEpochService(current.hooks, current.root, now=current.now)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        reopened.ensure(OWNER)


@pytest.mark.parametrize('damage', ['head_mac', 'member_mac', 'observation_mac',
                                   'missing_member', 'missing_observation', 'missing_directory',
                                   'directory_done_column', 'head_policy_column', 'missing_head'])
@requires_observation
def test_missing_or_tampered_signed_graph_is_not_read_as_original_history(current, damage):
    (current.root/'source.py').write_bytes(b'original')
    result = finish(current)
    with sqlite3.connect(current.store.path) as db:
        if damage == 'head_mac':
            db.execute('UPDATE epochs SET mac=?', ('0'*64,))
        elif damage == 'member_mac':
            db.execute('UPDATE members SET mac=?', ('0'*64,))
        elif damage == 'observation_mac':
            db.execute('UPDATE observations SET mac=?', ('0'*64,))
        elif damage == 'missing_head':
            db.execute('DELETE FROM epochs')
        elif damage.startswith('missing_'):
            table = {'missing_member':'members', 'missing_observation':'observations',
                     'missing_directory':'directories'}[damage]
            db.execute(f'DELETE FROM {table}')
        elif damage == 'directory_done_column':
            db.execute('UPDATE directories SET done=0')
        else:
            db.execute('UPDATE epochs SET policy=?', ('0'*64,))
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.lookup(result['epoch_ref'], ['source.py'])
    if damage in {'missing_head', 'head_policy_column'}:
        with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
            current.ensure(OWNER)


@requires_observation
def test_restart_continues_original_job_and_reports_observation_interval(current):
    for index in range(10):
        (current.root/f'{index}.py').write_bytes(str(index).encode())
    slow = ProductEpochService(current.hooks, current.root, now=current.now, policy=dict(step_files=2))
    initial = slow.ensure(OWNER)
    first = slow.step(OWNER)
    assert not first['scope_closed'] and first['counts']['members'] == 2
    slow.close()
    reopened = ProductEpochService(current.hooks, current.root, now=current.now, policy=dict(step_files=2))
    assert reopened.ensure(OWNER)['epoch_ref'] == initial['epoch_ref']
    final = finish(reopened)
    assert final['counts']['members'] == final['counts']['observed'] == 10
    assert final['gaps']['observation_intervals'] >= 2
    assert final['project_inventory_complete'] is False


@requires_observation
def test_repeated_loss_of_partial_hash_context_becomes_gap_in_original_epoch(current):
    (current.root/'large.bin').write_bytes(b'unchanged binary body'*100)
    (current.root/'small.bin').write_bytes(b'small')
    policy = dict(step_bytes=64)
    worker = ProductEpochService(current.hooks, current.root, now=current.now, policy=policy)
    result = worker.ensure(OWNER)
    original_ref = result['epoch_ref']
    for _ in range(20):
        result = worker.step(OWNER)
        assert result['epoch_ref'] == original_ref
        worker.close()
        if result['state'] == 'SEALED':
            break
        worker = ProductEpochService(current.hooks, current.root, now=current.now, policy=policy)
    else:
        pytest.fail('Lost in-process hash state caused an unlimited retry loop')
    assert result['counts']['members'] == 2
    assert result['counts']['observed'] == result['counts']['gaps'] == 1
    assert worker.lookup(original_ref, ['large.bin'])['results'][0]['status'] == 'GAP'


@requires_observation
def test_failed_control_commit_rolls_back_members_and_replays_directory_safely(current, monkeypatch):
    (current.root/'source.py').write_bytes(b'original')
    initial = current.ensure(OWNER)
    before = database_state(current)
    original = current.store.save

    def fail_after_rows(db, key, header):
        assert db.execute('SELECT count(*) FROM members').fetchone()[0] == 1
        assert db.execute('SELECT count(*) FROM observations').fetchone()[0] == 1
        raise sqlite3.OperationalError('Fixture control publication failure')

    monkeypatch.setattr(current.store, 'save', fail_after_rows)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.step(OWNER)
    assert database_state(current) == before
    monkeypatch.setattr(current.store, 'save', original)
    result = finish(current)
    assert result['epoch_ref'] == initial['epoch_ref']
    assert result['counts']['members'] == result['counts']['observed'] == 1


@requires_observation
def test_capacity_failure_preserves_original_cursor_and_resumes(current, monkeypatch):
    (current.root/'source.py').write_bytes(b'original')
    initial = current.ensure(OWNER)
    before, original = database_state(current), current.store.save

    def full(db, key, header):
        error = sqlite3.OperationalError('Fixture disk full')
        error.sqlite_errorcode = sqlite3.SQLITE_FULL
        raise error

    monkeypatch.setattr(current.store, 'save', full)
    waiting = current.step(OWNER)
    assert waiting['state'] == 'WAITING_CAPACITY' and waiting['epoch_ref'] == initial['epoch_ref']
    assert waiting['counts']['members'] == 0
    assert database_state(current) == before
    monkeypatch.setattr(current.store, 'save', original)
    assert finish(current)['epoch_ref'] == initial['epoch_ref']


@requires_observation
def test_real_sqlite_page_capacity_pauses_without_losing_original_job(current, monkeypatch):
    for index in range(1000):
        (current.root/f'source_{index:04d}.py').write_bytes(b'body')
    initial = current.ensure(OWNER)
    before = database_state(current)
    ordinary_limit = epoch_storage.MAX_DATABASE_BYTES
    monkeypatch.setattr(epoch_storage, 'MAX_DATABASE_BYTES', current.store.path.stat().st_size)
    waiting = current.step(OWNER)
    assert waiting['state'] == 'WAITING_CAPACITY'
    assert waiting['epoch_ref'] == initial['epoch_ref'] and waiting['counts']['members'] == 0
    assert database_state(current) == before
    monkeypatch.setattr(epoch_storage, 'MAX_DATABASE_BYTES', ordinary_limit)
    result = finish(current)
    assert result['epoch_ref'] == initial['epoch_ref']
    assert result['counts']['observed'] == result['counts']['members'] == 1000


@requires_observation
def test_links_are_excluded_without_reading_outside_root(current, tmp_path):
    outside = tmp_path.resolve()/'outside'
    outside.mkdir()
    (outside/'secret.py').write_bytes(b'outside source')
    try:
        (current.root/'linked-dir').symlink_to(outside, target_is_directory=True)
        (current.root/'linked-file.py').symlink_to(outside/'secret.py')
    except OSError:
        pytest.skip('Platform cannot create links')
    (current.root/'safe.py').write_bytes(b'safe')
    result = finish(current)
    assert result['counts']['members'] == result['counts']['observed'] == 1
    row = current.lookup(result['epoch_ref'], ['linked-file.py'])['results'][0]
    assert row['status'] == 'FIRST_OBSERVED_ORDER_UNKNOWN' and 'hash' not in row


@requires_observation
def test_zero_scope_deadline_closes_unknown_denominator_without_following_files(current):
    (current.root/'source.py').write_bytes(b'original')
    immediate = ProductEpochService(current.hooks, current.root, now=current.now, policy=dict(scope_seconds=0))
    result = finish(immediate)
    assert result['scope_closed'] is True and result['scope_close_reason'] == 'DEADLINE'
    assert result['counts']['members'] == 0 and result['counts']['gaps'] == 1
    assert result['comparison_available'] is False


@requires_observation
def test_untrusted_directory_identity_index_cannot_hide_a_new_directory(current):
    for name in ('first', 'second'):
        (current.root/name).mkdir()
        (current.root/name/'source.py').write_bytes(name.encode())
    slow = ProductEpochService(current.hooks, current.root, now=current.now, policy=dict(step_files=1))
    slow.ensure(OWNER)
    slow.step(OWNER)
    with sqlite3.connect(slow.store.path) as db:
        seq, discovered = db.execute('SELECT seq,path FROM directories WHERE path!=\'\'').fetchone()
        other = 'second' if discovered == 'first' else 'first'
        info = (current.root/other).stat()
        db.execute('UPDATE directories SET dev=?,ino=? WHERE seq=?', (info.st_dev, info.st_ino, seq))
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        slow.step(OWNER)
    slow.close()


def test_missing_platform_capability_never_allocates_or_advances(current, monkeypatch):
    monkeypatch.setattr('security_runtime.product_epoch_service.platform_supported', lambda: False)
    assert current.ensure(OWNER)['state'] == 'PLATFORM_UNSUPPORTED'
    assert current.step(OWNER)['state'] == 'PLATFORM_UNSUPPORTED'
    assert current.status()['platform_supported'] is False
    assert not current.hooks.directory.exists()


@requires_observation
def test_lost_platform_capability_leaves_existing_job_unchanged(current, monkeypatch):
    current.ensure(OWNER)
    before = database_state(current)
    monkeypatch.setattr('security_runtime.product_epoch_service.platform_supported', lambda: False)
    assert current.step(OWNER)['state'] == 'PLATFORM_UNSUPPORTED'
    assert database_state(current) == before


@requires_observation
def test_readonly_rejects_external_wal_without_creating_sidecars(current):
    finish(current)
    with sqlite3.connect(current.store.path) as db:
        db.execute('PRAGMA journal_mode=WAL')
    db.close()
    assert not Path(str(current.store.path)+'-shm').exists()
    before = {path.name:path.read_bytes() for path in current.store.directory.iterdir()}
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.status()
    assert {path.name:path.read_bytes() for path in current.store.directory.iterdir()} == before


@requires_observation
def test_private_store_cannot_be_enumerated_as_source(current):
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_PRIVATE_DIRECTORY_REQUIRED'):
        ProductEpochService(HookStateStore(current.root/'private'), current.root)
    assert not (current.root/'private').exists()


@requires_observation
def test_writer_lock_creation_is_not_product_store_allocation(current):
    with current._writer_locks.lock(current.root) as acquired:
        assert acquired
        assert not current.store.directory.exists() and not current.store.marker.exists()
        assert not current.hooks.lock_held(current.root)
        assert current.status()['state'] == 'NOT_STARTED'
    assert current.ensure(OWNER)['epoch_ref'].startswith('pe1-')


@requires_observation
def test_replaced_private_directory_is_not_accepted_as_original_store(current):
    finish(current)
    original = current.store.directory.with_name('original-product-epochs')
    current.store.directory.rename(original)
    shutil.copytree(original, current.store.directory)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.status()
    reopened = ProductEpochService(current.hooks, current.root, now=current.now)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        reopened.status()


@pytest.mark.parametrize('damage', ['missing', 'corrupt'])
@requires_observation
def test_external_store_marker_is_required_for_existing_history(current, damage):
    result = finish(current)
    if damage == 'missing':
        current.store.marker.unlink()
    else:
        current.store.marker.write_bytes(b'{}')
    for service in (current, ProductEpochService(current.hooks, current.root, now=current.now)):
        with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
            service.status(result['epoch_ref'])
        with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
            service.ensure(OWNER)


@requires_observation
def test_first_allocation_crash_after_marker_publication_cannot_rebuild(current, monkeypatch):
    original = current.store._publish_marker

    def interrupt(key):
        original(key)
        raise ProductEpochError('PRODUCT_EPOCH_HISTORY_UNAVAILABLE')

    monkeypatch.setattr(current.store, '_publish_marker', interrupt)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.ensure(OWNER)
    assert current.store.marker.exists() and not current.store.path.exists()
    reopened = ProductEpochService(current.hooks, current.root, now=current.now)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        reopened.ensure(OWNER)
    assert not current.store.path.exists()


@requires_observation
def test_first_database_transaction_failure_does_not_restart_from_live_source(current, monkeypatch):
    def interrupt(*args):
        raise sqlite3.OperationalError('Fixture first allocation failure')

    monkeypatch.setattr(current.store, 'save', interrupt)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        current.ensure(OWNER)
    assert current.store.marker.exists()
    reopened = ProductEpochService(current.hooks, current.root, now=current.now)
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
        reopened.ensure(OWNER)


@pytest.mark.parametrize('policy', [dict(step_files=257), dict(step_bytes=8_000_001),
                                   dict(step_seconds=0), dict(scope_seconds=float('inf')),
                                   dict(ignored_names=['../source']), dict(unknown=True)])
@requires_observation
def test_invalid_policy_cannot_allocate_state(current, policy):
    with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_POLICY_INVALID'):
        ProductEpochService(current.hooks, current.root, policy=policy)
    assert not current.hooks.directory.exists()
