"""Synthetic metadata only. Real scanning and background launch are forbidden."""
import json
from types import SimpleNamespace

import pytest

from security_runtime.development_check import DevelopmentCheckService, clean_paths, record_hook
from security_runtime.development_continuation import context, stop
from security_runtime.development_delivery import publish
from security_runtime.development_file_watch import _Window
from security_runtime.development_check_worker import failure_diagnostic
from security_runtime.hook_state import HookStateStore
from security_runtime.scan_request import ScanInputError

OWNER = dict(host='codex', session='1'*64)


@pytest.fixture
def sample(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Real scan or background launch attempted')
    monkeypatch.setattr('security_runtime.runtime.SecurityRuntime.scan', forbidden)
    monkeypatch.setattr('security_runtime.development_check_worker.launch_worker', forbidden)
    root = tmp_path/'project'
    root.mkdir()
    service = DevelopmentCheckService(None, HookStateStore(tmp_path/'private'), owner=OWNER,
        scan_path_provider=tmp_path/'scans.db', launcher=forbidden)
    ref = service.begin(root, 'test-policy')['check_ref']
    return root, service, ref


@pytest.mark.parametrize('path', ['.test-tmp/run/a.py', '.test-tmp-run-123/cache.db',
                                  'nested/.test-tmp-context-1/current'])
def test_all_recording_entries_ignore_artifacts(sample, path):
    root, service, ref = sample
    assert clean_paths([path]) == ([], False)
    assert service.record(root, ref, [path])['dirty_seq'] == 0
    value = record_hook(service.hooks, root, OWNER, [path], scope_unknown=False,
                        scan_path=service.scan_path())
    assert value['dirty_seq'] == 0
    assert service.finish(root, ref)['status'] == 'NO_OBSERVED_CHANGES'


def test_source_and_rename_paths_remain(sample):
    root, service, ref = sample
    paths = ['tests/test_feature.py', 'src/old.py', 'src/new.py', 'config/app.db']
    result = service.record(root, ref, paths)
    assert result['scope']['paths'] == sorted(paths)
    assert result['dirty_seq'] == 1


def test_watch_filters_before_filesystem_checks(sample):
    root, service, ref = sample
    window = object.__new__(_Window)
    window.store = SimpleNamespace(root=root)
    window.private, window.ignored = root/'private', set()
    names, unknown = window.paths([(3, str(root/'.test-tmp/deleted/current')),
                                   (3, str(root/'tests/deleted.py'))])
    assert names == ['tests/deleted.py'] and not unknown


def test_closeout_filters_legacy_paths_without_scan(sample):
    root, service, ref = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, dirty_seq=1, state='DIRTY',
                                observed_paths=['.test-tmp/old/sample.py']))
    assert service.finish(root, ref)['status'] == 'NO_OBSERVED_CHANGES'


def saved(sample, seq=1, status='FAILED', diagnostic=None):
    root, service, ref = sample
    store = service.store(root)
    with store.transaction() as db:
        row = store._get(db, ref)
        row = store._put(db, ref, dict(row, state=status, dirty_seq=seq, scanned_seq=seq,
            reason_code='DEVELOPMENT_SCAN_FAILED', failure_diagnostic=diagnostic,
            observed_paths=['src/app.py'], finish_requested=True))
        publish(store, db, row)
    return store


def test_chat_and_stop_are_quiet_with_unread_failure(sample):
    root, service, ref = sample
    saved(sample)
    for turn in ('editing', 'explain', 'another-chat-turn'):
        assert stop(service.hooks, root, OWNER, turn_id=turn) is None
        assert context(service.hooks, root, OWNER) == ''
    value = service.saved_result(root, ref, 1)
    assert value['delivery']['delivery'] == 'PENDING'
    assert value['delivery']['user_consumption'] == 'UNKNOWN'


def test_opted_in_failure_reminder_is_durable_and_coalesced(sample):
    root, service, ref = sample
    saved(sample)
    assert stop(service.hooks, root, OWNER, allow_continuation=True)
    assert stop(service.hooks, root, OWNER, allow_continuation=True) is None
    saved(sample, 2)
    assert stop(service.hooks, root, OWNER, offered={(ref, 1)}, allow_continuation=True) is None
    saved(sample, 3, diagnostic={'stage': 'INPUT_SELECTION', 'reason_code': 'SCAN_INPUT_NOT_REGULAR'})
    assert stop(service.hooks, root, OWNER, allow_continuation=True, turn_id='changed-failure')
    assert not service.saved_result(root, ref, 3)['delivery']['host_report_submitted']


def test_diagnostic_does_not_expose_exception_text(sample):
    diagnostic = failure_diagnostic(ScanInputError('SCAN_INPUT_PRIVATE_PATH_BUDGET'), 'SCAN_EXECUTION')
    assert diagnostic['reason_code'] == 'SCAN_INPUT_PRIVATE_PATH_BUDGET'
    private = 'token=SECRET C:/private/source.py'
    assert private not in json.dumps(failure_diagnostic(PermissionError(private), 'SCAN_EXECUTION'))
    assert failure_diagnostic(ScanInputError(private))['reason_code'] == 'UNKNOWN'
    root, service, ref = sample
    saved(sample, diagnostic=diagnostic)
    assert service.get(root, ref)['failure_diagnostic'] == diagnostic
    assert service.saved_result(root, ref, 1)['delivery']['failure_diagnostic'] == diagnostic


def test_all_fixed_scan_input_codes_are_preserved():
    import ast
    from pathlib import Path
    from security_runtime.scan_request import SCAN_INPUT_REASON_CODES
    for code in SCAN_INPUT_REASON_CODES:
        assert failure_diagnostic(ScanInputError(code))['reason_code'] == code
    # A new literal exception code must not silently disappear at closeout.
    root = Path(__file__).resolve().parents[1] / 'src/security_runtime'
    for source in root.rglob('*.py'):
        tree = ast.parse(source.read_text(encoding='utf-8-sig'))
        for call in ast.walk(tree):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == 'ScanInputError' and call.args
                    and isinstance(call.args[0], ast.Constant)):
                assert call.args[0].value in SCAN_INPUT_REASON_CODES, source


@pytest.mark.parametrize('code', ['SCAN_INPUT_PRIVATE_token_SECRET',
                                  'SCAN_INPUT_SOURCE_CHANGED\nPRIVATE', ['private']])
def test_arbitrary_reason_codes_remain_private(code):
    assert failure_diagnostic(ScanInputError(code))['reason_code'] == 'UNKNOWN'


def test_capture_diagnostic_rejects_arbitrary_details():
    error = ScanInputError('SCAN_INPUT_VIEW_CHANGED')
    detail = dict(expected_count=2, actual_count=1, root_length=100, max_path_length=310,
                  missing_path_ids=['a' * 64], unexpected_path_ids=[])
    error.capture_diagnostic = detail
    assert failure_diagnostic(error)['capture'] == detail
    error.capture_diagnostic = dict(detail, missing_path_ids=['private/path.py'])
    assert 'capture' not in failure_diagnostic(error)
    error.capture_diagnostic = dict(detail, raw='secret')
    assert 'capture' not in failure_diagnostic(error)


def test_worker_persists_mock_failure_without_running_scanner(sample, monkeypatch):
    from security_runtime import development_check_worker as worker
    root, service, ref = sample
    store = service.store(root)
    service.record(root, ref, ['src/app.py'])
    ticket = 'a'*64
    with store.transaction() as db:
        row = store._get(db, ref)
        store._put(db, ref, dict(row, state='QUEUED', finish_requested=True))
        store._put(db, '$worker', dict(ticket=ticket, lease_until=store.now()+90,
                                      root_identity=row['root_identity']))
    diagnostic = failure_diagnostic(PermissionError('PRIVATE'), 'INPUT_SELECTION')
    def fail(*args, **kwargs):
        raise worker.DevelopmentScanFailure(diagnostic)
    monkeypatch.setattr(worker, '_scan', fail)
    monkeypatch.setattr(worker, '_release_capacity', lambda *a, **k: None)
    monkeypatch.setattr(worker, 'MAX_SCAN_ATTEMPTS', 1)
    worker.run_worker(root, service.hooks.directory, ticket, debounce_seconds=0, max_seconds=5)
    result = service.saved_result(root, ref, 1)
    assert result['delivery']['status'] == 'FAILED'
    assert result['delivery']['failure_diagnostic'] == diagnostic
