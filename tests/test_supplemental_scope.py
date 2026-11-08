"""Positive watch provenance permits absent supplements, never swallowed failures."""
from pathlib import Path
import pytest

from security_runtime.development_scope import separate_directories, watch_only_paths
from security_runtime.scan_request import ScanInputError
from test_development_check import check, execute  # noqa: F401


def watch(service, root, ref, names):
    store = service.store(root)
    with store.transaction() as db:
        store.append(db, store._get(db, ref), names, False, None, explicit=False)


def test_deleted_supplement_only_does_not_start_worker(check, monkeypatch):
    root, service, _, state = check
    ref = service.begin(root, 'temporary-only')['check_ref']
    watch(service, root, ref, ['temporary.tmp'])
    monkeypatch.setattr(service, '_wake', lambda *a: pytest.fail('unnecessary worker'))
    saved = service.finish(root, ref)
    assert saved['status'] == 'NO_OBSERVED_CHANGES' and saved['gaps'] == []
    assert saved['scope']['paths'] == []
    assert saved['scope']['skipped_missing_watch_paths'] == ['temporary.tmp']
    assert state['calls'] == 0


@pytest.mark.parametrize('direct_first', [True, False])
def test_direct_record_wins_over_watch_in_both_orders(check, direct_first):
    root, service, _, _ = check
    ref = service.begin(root, 'overlap')['check_ref']
    actions = [lambda: service.record(root, ref, ['removed.py']),
               lambda: watch(service, root, ref, ['removed.py'])]
    for action in actions if direct_first else reversed(actions):
        action()
    saved = service.finish(root, ref)
    assert saved['scope']['paths'] == ['removed.py']
    assert saved['scope']['explicit_paths'] == saved['scope']['watch_paths'] == ['removed.py']
    assert saved['scope']['skipped_missing_watch_paths'] == []


def test_legacy_missing_origin_is_not_assumed_to_be_watch(check):
    root, service, _, _ = check
    ref = service.begin(root, 'legacy')['check_ref']
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row.pop('watch_paths')
        store._put(db, ref, dict(row, observed_paths=['removed.py'], dirty_seq=1, state='DIRTY'))
    assert service.finish(root, ref)['scope']['paths'] == ['removed.py']


def test_shell_source_config_manifest_and_findings_survive(check, monkeypatch):
    root, service, runtime, state = check
    values = {'app.ts': 'const f = new Function(userInput);\n', '.env': 'SETTING=fixture\n',
              'requirements.txt': '', 'uv.lock': 'version = 1\n', 'debug.log': 'source text\n'}
    for name, value in values.items():
        (root/name).write_text(value)
    ref = service.begin(root, 'shell-edits')['check_ref']
    watch(service, root, ref, [*values, 'replace.tmp'])
    assert execute(check, monkeypatch) == 0
    saved = service.get(root, ref)
    assert saved['scanned_seq'] == saved['dirty_seq'] and saved['scan_id']
    assert state['calls'] == 1 and set(state['inputs'][0]) == set(values)
    assert 'DELETED_PATH_SEMANTICS_NOT_REVIEWED' not in saved['gaps']
    assert runtime.store.get_scan(saved['scan_id'])['findings']
    delivery = service.saved_result(root, ref, saved['scanned_seq'])['delivery']
    assert delivery['scope']['skipped_missing_watch_paths'] == ['replace.tmp']
    assert delivery['scope']['explicit_paths'] == []


def test_existing_watch_source_scan_failure_remains_failure(check, monkeypatch):
    root, service, runtime, _ = check
    ref = service.begin(root, 'shell-failure')['check_ref']
    watch(service, root, ref, ['app.ts'])
    def fail(*args, **kwargs):
        raise ScanInputError('SCAN_INPUT_NOT_REGULAR')
    monkeypatch.setattr(runtime, 'scan', fail)
    assert execute(check, monkeypatch) == 0
    assert service.get(root, ref)['status'] == 'FAILED'
    assert service.store(root).load(ref)['failure_diagnostic']['reason_code'] == 'SCAN_INPUT_NOT_REGULAR'


def test_inaccessible_watch_path_is_not_a_deleted_file(tmp_path, monkeypatch):
    def denied(*args, **kwargs):
        raise PermissionError('denied')
    monkeypatch.setattr('security_runtime.hook_state.no_links', denied)
    skipped = []
    files, _ = separate_directories(tmp_path, ['source.py'], watch_only={'source.py'}, missing_watch_paths=skipped)
    assert files == ['source.py'] and not skipped


def test_dangling_link_is_not_a_deleted_supplement(tmp_path):
    (tmp_path/'link').symlink_to(tmp_path/'absent')
    skipped = []
    files, _ = separate_directories(tmp_path, ['link'], watch_only={'link'}, missing_watch_paths=skipped)
    assert files == ['link'] and not skipped


def test_classification_reuses_existing_filesystem_probes(tmp_path, monkeypatch):
    (tmp_path/'app.py').write_text('value = 1')
    names = ['app.py', 'removed.tmp']
    original = Path.lstat
    calls = []
    def counted(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', counted)
    separate_directories(tmp_path, names)
    baseline = list(calls)
    calls.clear()
    separate_directories(tmp_path, names, watch_only=set(names), missing_watch_paths=[])
    assert calls == baseline


def test_new_batch_clears_watch_provenance_and_preserves_delivery(check, monkeypatch):
    root, service, _, _ = check
    ref = service.begin(root, 'new-round')['check_ref']
    watch(service, root, ref, ['app.ts', 'removed.tmp'])
    assert execute(check, monkeypatch) == 0
    old = service.get(root, ref)['scanned_seq']
    service.record(root, ref, ['app.ts'])
    row = service.store(root).load(ref)
    assert row['watch_paths'] == [] and row['skipped_missing_watch_paths'] == []
    assert watch_only_paths(row) == set()
    assert service.saved_result(root, ref, old)['delivery']['scope']['skipped_missing_watch_paths'] == ['removed.tmp']


def test_recreated_supplement_is_eligible_again(check):
    root, service, _, _ = check
    ref = service.begin(root, 'recreated')['check_ref']
    watch(service, root, ref, ['temporary.py'])
    assert service.finish(root, ref)['scope']['skipped_missing_watch_paths'] == ['temporary.py']
    (root/'temporary.py').write_text('value = 1')
    watch(service, root, ref, ['temporary.py'])
    result = service.finish(root, ref)
    assert result['scope']['paths'] == ['temporary.py']
    assert result['scope']['skipped_missing_watch_paths'] == []
