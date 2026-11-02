"""Directory notifications must not abort an otherwise bounded file check."""
import os
import pytest

from security_runtime.development_scope import separate_directories
from security_runtime.scan_input import scoped_request
from test_development_check import check, execute  # noqa: F401


def test_mixed_directory_and_file_checks_only_recorded_file(check, monkeypatch):
    root, service, _, state = check
    (root/'download').mkdir()
    (root/'download/unobserved.py').write_text('eval(input())\n')
    ref = service.begin(root, 'directory-event')['check_ref']
    service.record(root, ref, ['download', 'app.ts'])
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert result['scan_id'] and result['status'] != 'FAILED'
    assert result['scope']['paths'] == ['app.ts']
    assert result['scope']['directory_observations'] == ['download']
    assert state['calls'] == 1
    assert all('download/unobserved.py' not in paths for paths in state['inputs'])


def test_directory_only_finishes_without_scanner_or_pending_gap(check, monkeypatch):
    root, service, runtime, state = check
    (root/'empty').mkdir()
    monkeypatch.setattr(service, '_wake', lambda *a: pytest.fail('no worker needed'))
    ref = service.begin(root, 'directory-only')['check_ref']
    service.record(root, ref, ['empty'])
    result = service.finish(root, ref)
    assert result['status'] == 'NO_OBSERVED_CHANGES'
    assert result['scope']['directory_observations'] == ['empty']
    assert result['scope']['paths'] == [] and result['gaps'] == []
    assert state['calls'] == 0


def test_missing_file_remains_a_deleted_input(tmp_path):
    (tmp_path/'folder').mkdir()
    files, directories = separate_directories(tmp_path, ['folder', 'removed.py'])
    assert files == ['removed.py'] and directories == ['folder']
    assert scoped_request(tmp_path, files).absent_files == ('removed.py',)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX symlink and FIFO creation')
def test_links_and_special_files_are_not_silently_filtered(tmp_path):
    (tmp_path/'folder').mkdir()
    (tmp_path/'link').symlink_to(tmp_path/'folder', target_is_directory=True)
    os.mkfifo(tmp_path/'pipe')
    files, directories = separate_directories(tmp_path, ['link', 'pipe'])
    assert files == ['link', 'pipe'] and directories == []
    for name in files:
        with pytest.raises(ValueError):
            scoped_request(tmp_path, [name])


def test_classification_error_keeps_input_for_original_validator(tmp_path, monkeypatch):
    from security_runtime import hook_state
    (tmp_path/'folder').mkdir()
    def denied(*args):
        raise OSError('access denied')
    monkeypatch.setattr(hook_state, 'no_links', denied)
    assert separate_directories(tmp_path, ['folder']) == (['folder'], [])


def test_new_project_folder_and_new_file_are_both_handled(check, monkeypatch):
    root, service, _, state = check
    ref = service.begin(root, 'new-project-files')['check_ref']
    (root/'new-module').mkdir()
    (root/'new-module/entry.ts').write_text('export const value = 1;\n')
    service.record(root, ref, ['new-module', 'new-module/entry.ts'])
    assert execute(check, monkeypatch) == 0
    result = service.get(root, ref)
    assert result['scan_id'] and result['status'] != 'FAILED'
    assert result['scope']['paths'] == ['new-module/entry.ts']
    assert result['scope']['directory_observations'] == ['new-module']
    assert state['calls'] == 1
    assert all('new-module/entry.ts' in paths and 'app.ts' not in paths for paths in state['inputs'])
