"""Real historical writers cannot replace a fenced legacy path or new shards."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from security_runtime.closeout_state import digest
from security_runtime.hook_state import HookStateStore, atomic_bytes
from security_runtime.ledger_partitions import LedgerCapacity, MAX_PARTITIONS
from security_runtime.tasks.risk_ledger import TaskRiskLedger

LEGACY_SOURCE_HASHES = {
    'v0.3.4':'5b6459f8b7a45c5c58c37276474a6de665e86090e254bce318a392f49c1f97ef',
    'a51a58d':'6fb546175e14030b5dfb5a078b8c49174c91d28d4ecdb9b7d9b8e7124d027bde',
    'b352731':'32bcee293ec5563d38bdf07f6808dcfa569ffdb7ca9b819ca4c420861314f5dc',
}


def record(ref, count):
    return dict(task_ref=ref, static=dict(scan_id='scan-'+ref, findings=[dict(id=str(i),
        title='Fixture candidate', category='code', file_path='app.py') for i in range(count)]),
        end=dict(hashes={'app.py': 'a'*64}))


@pytest.fixture
def sample(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'app.py').write_text('pass\n')
    hooks = HookStateStore(tmp_path/'private')
    return root, hooks, TaskRiskLedger(hooks, root)


def seed_legacy(root, hooks, rows):
    path = hooks.workspace_directory(root)/'task-risk-ledger.json'
    key = hooks.key(root)
    atomic_bytes(path, json.dumps(dict(contract='task-risk-ledger-v1', workspace=str(root),
        rows=rows, mac=digest(key, rows))).encode())
    return path


def test_read_does_not_migrate_or_create_key_and_migration_preserves_history(sample):
    root, hooks, ledger = sample
    assert ledger.read() == {}
    assert not hooks.workspace_directory(root).exists()
    legacy_rows = ledger.registration_rows(record('old', 837), ledger.read())
    old = seed_legacy(root, hooks, legacy_rows)
    before = old.read_bytes()
    assert ledger.read() == legacy_rows and old.is_file()
    assert not ledger.path.exists()
    with hooks.lock(root) as held:
        assert held
        ledger.register(record('new', 280))
    assert old.is_dir() and list(old.iterdir())
    assert len(ledger.read()) == 1117
    assert len(ledger.read('old')) == 837 and len(ledger.read('new')) == 280
    assert old.with_name(old.name+'.verified-backup').read_bytes() == before
    assert old.with_name(old.name+'.moved-backup').read_bytes() == before
    snapshot = {str(p): p.read_bytes() for p in old.parent.rglob('*') if p.is_file()}
    assert ledger.read() == {**legacy_rows, **ledger.read('new')}
    assert {str(p): p.read_bytes() for p in old.parent.rglob('*') if p.is_file()} == snapshot


@pytest.mark.parametrize('build', ['v0.3.4', 'a51a58d', 'b352731'])
def test_actual_old_process_reader_and_cached_bare_writer_are_fenced(sample, build, tmp_path):
    root, hooks, ledger = sample
    rows = ledger.registration_rows(record('old', 1), ledger.read())
    seed_legacy(root, hooks, rows)
    fixture = Path(__file__).parent/'fixtures'/'legacy_writers'/('ledger-'+build+'.py.txt')
    old_source = fixture.read_bytes()
    assert hashlib.sha256(old_source).hexdigest() == LEGACY_SOURCE_HASHES[build]
    source_file = tmp_path/'audited-ledger.py'
    source_file.write_bytes(old_source)
    cached = tmp_path/'cached.json'
    cached.write_text(json.dumps(rows))
    with hooks.lock(root) as held:
        assert held
        ledger.register(record('new', 1))
    before = ledger.path.read_bytes()
    # Execute exact historical class source in a separate process. Its imports
    # share only unchanged primitives; no historical save/read body is patched.
    script = '''import json,sys
from pathlib import Path
from security_runtime.hook_state import HookStateStore
ns={'__package__':'security_runtime','__name__':'security_runtime.audited_old_ledger'}
exec(Path(sys.argv[1]).read_text(),ns)
root=Path(sys.argv[2]); hooks=HookStateStore(Path(sys.argv[3])); ledger=ns['TaskRiskLedger'](hooks,root)
with hooks.lock(root) as held:
 assert held
 try: ledger.read()
 except (OSError,ValueError): pass
 else: raise AssertionError('old reader accepted fenced workspace')
try: ledger.save(json.loads(Path(sys.argv[4]).read_text()))
except (OSError,ValueError): pass
else: raise AssertionError('old cached writer replaced fenced workspace')
'''
    completed = subprocess.run([sys.executable,'-c',script,str(source_file),str(root),str(hooks.directory),str(cached)],
                               capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert ledger.path.read_bytes() == before and len(ledger.read()) == 2


@pytest.mark.parametrize('stage', ['journal', 'backup', 'move', 'receipt', 'seed', 'commit'])
def test_migration_fault_can_resume_without_discarding_authenticated_history(sample, monkeypatch, stage):
    root, hooks, ledger = sample
    rows = ledger.registration_rows(record('old', 1), ledger.read())
    seed_legacy(root, hooks, rows)
    import security_runtime.private_authority as module
    original_atomic, original_replace = module.atomic_bytes, module.os.replace
    fired = False

    def fail_atomic(path, raw):
        nonlocal fired
        path = Path(path)
        match = (stage == 'journal' and path == ledger.authority.journal or
            stage == 'backup' and path == ledger.authority.backup or
            stage == 'receipt' and path == ledger.authority.receipt or
            stage == 'seed' and path == ledger.path or
            stage == 'commit' and path == ledger.authority.journal and b'COMMITTED' in raw)
        # Journal case faults after PREPARED was durably written.
        result = original_atomic(path, raw)
        if match and not fired:
            fired = True
            raise OSError('fixture migration crash')
        return result

    def fail_move(source, target):
        nonlocal fired
        result = original_replace(source, target)
        if stage == 'move' and Path(source) == ledger.authority.old and not fired:
            fired = True
            raise OSError('fixture migration crash')
        return result

    monkeypatch.setattr(module, 'atomic_bytes', fail_atomic)
    monkeypatch.setattr(module.os, 'replace', fail_move)
    with hooks.lock(root) as held:
        assert held
        with pytest.raises(OSError, match='fixture migration crash'):
            ledger.register(record('new', 1))
    assert fired
    monkeypatch.setattr(module, 'atomic_bytes', original_atomic)
    monkeypatch.setattr(module.os, 'replace', original_replace)
    with hooks.lock(root) as held:
        assert held
        # A new write resumes an owned transition; an ordinary read never does.
        ledger.register(record('new', 1))
    assert len(ledger.read()) == 2 and ledger.read()['old:0'] == rows['old:0']


def test_stale_snapshot_and_unlocked_writes_cannot_publish(sample):
    root, hooks, ledger = sample
    with hooks.lock(root) as held:
        assert held and hooks.lock_held(root)
        ledger.register(record('one',1))
    rows = ledger.read()
    with pytest.raises(ValueError, match='workspace lock'):
        ledger.save(rows)
    with hooks.lock(root) as held:
        assert held
        with hooks.lock(root) as second:
            assert not second and hooks.lock_held(root)
        ledger.register(record('two',1))
        with pytest.raises(ValueError, match='changed concurrently'):
            ledger.save(rows)
    assert not hooks.lock_held(root) and len(ledger.read()) == 2


def test_per_partition_capacity_has_typed_counts_and_preserves_other_history(sample):
    root, hooks, ledger = sample
    with hooks.lock(root) as held:
        assert held
        ledger.register(record('one', 1000))
        ledger.register(record('two', 280))
        before = ledger.path.read_bytes()
        with pytest.raises(LedgerCapacity) as caught:
            ledger.register(record('one',1001))
    assert caught.value.reason_code == 'TASK_RISK_LEDGER_ROW_CAPACITY'
    assert (caught.value.count,caught.value.limit) == (1001,1000)
    assert ledger.path.read_bytes() == before and len(ledger.read()) == 1280


def test_unknown_or_changed_backup_is_preserved_and_blocks_recovery(sample):
    root, hooks, ledger = sample
    rows = ledger.registration_rows(record('old',1), ledger.read())
    seed_legacy(root,hooks,rows)
    ledger.authority.backup.write_text('unknown user file')
    with hooks.lock(root) as held:
        assert held
        with pytest.raises(ValueError, match='Unowned'):
            ledger.register(record('new',1))
    assert ledger.authority.backup.read_text() == 'unknown user file'
    assert ledger.authority.old.is_file() and not ledger.path.exists()


def test_multi_partition_candidate_failure_keeps_index_atomic_and_retry_collects_orphans(sample,monkeypatch):
    root,hooks,ledger = sample
    with hooks.lock(root) as held:
        assert held
        ledger.register(record('one',1))
        ledger.register(record('two',1))
    before = ledger.path.read_bytes()
    rows = ledger.read()
    for row in rows.values(): row['reason'] = 'new result'
    import security_runtime.ledger_partitions as module
    real_write = module.atomic_bytes
    writes = 0
    def fail_second(path, raw):
        nonlocal writes
        writes += 1
        if writes == 2: raise OSError('candidate shard failure')
        return real_write(path,raw)
    monkeypatch.setattr(module,'atomic_bytes',fail_second)
    with hooks.lock(root) as held:
        assert held
        with pytest.raises(OSError): ledger.save(rows)
    assert ledger.path.read_bytes() == before
    assert all('reason' not in row for row in ledger.read().values())
    monkeypatch.setattr(module,'atomic_bytes',real_write)
    with hooks.lock(root) as held:
        assert held
        ledger.save(rows)
    assert all(row['reason'] == 'new result' for row in ledger.read().values())
    assert len(list(ledger.partitions.directory.iterdir())) == 2


def test_partition_and_byte_capacities_are_typed_without_erasing_history(sample,monkeypatch):
    root,hooks,ledger = sample
    import security_runtime.ledger_partitions as module
    assert module.MAX_PARTITIONS == 256
    monkeypatch.setattr(module,'MAX_PARTITIONS',2)
    with hooks.lock(root) as held:
        assert held
        ledger.register(record('one',1))
        ledger.register(record('two',1))
        before = ledger.path.read_bytes()
        with pytest.raises(LedgerCapacity) as count:
            ledger.register(record('three',1))
        assert count.value.reason_code == 'TASK_RISK_LEDGER_PARTITION_CAPACITY'
        assert (count.value.count,count.value.limit) == (3,2)
        rows = ledger.read('one')
        rows['one:0']['reason'] = 'x'*2_000_000
        with pytest.raises(LedgerCapacity) as size: ledger.save(rows)
        assert size.value.reason_code == 'TASK_RISK_LEDGER_BYTE_CAPACITY'
        assert size.value.count > size.value.limit == 2_000_000
    assert ledger.path.read_bytes() == before and len(ledger.read()) == 2


def test_signed_legacy_change_after_prepared_is_preserved_and_cannot_be_guessed(sample,monkeypatch):
    root,hooks,ledger = sample
    rows = ledger.registration_rows(record('old',1),ledger.read())
    old = seed_legacy(root,hooks,rows)
    import security_runtime.private_authority as module
    original = module.atomic_bytes
    changed = None
    def race(path, raw):
        nonlocal changed
        result = original(path,raw)
        if Path(path) == ledger.authority.journal and b'PREPARED' in raw:
            next_rows = copy.deepcopy(dict(rows))
            next_rows['old:0']['reason'] = 'late supported legacy writer'
            seed_legacy(root,hooks,next_rows)
            changed = old.read_bytes()
        return result
    monkeypatch.setattr(module,'atomic_bytes',race)
    with hooks.lock(root) as held:
        assert held
        with pytest.raises(ValueError,match='changed before backup'):
            ledger.register(record('new',1))
    assert old.is_file() and old.read_bytes() == changed
    before = {str(p):p.read_bytes() for p in old.parent.rglob('*') if p.is_file()}
    with pytest.raises(ValueError,match='transition incomplete'): ledger.read()
    assert {str(p):p.read_bytes() for p in old.parent.rglob('*') if p.is_file()} == before
    assert not ledger.path.exists() and not ledger.authority.backup.exists()
