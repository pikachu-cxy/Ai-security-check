"""Git Hook comparison and baseline use the detector's configured exclusions."""
import subprocess

import pytest

from security_runtime.hook_runtime import capture_snapshot
from test_hook_runtime import repo
from test_codex_integration import adapter


def generated(repo):
    folder = repo / 'generated'
    folder.mkdir()
    (folder / 'one.py').write_text('one = 1\n')
    (folder / 'two.py').write_text('two = 2\n')
    subprocess.run(['git', '-C', str(repo), 'add', 'generated'], check=True)
    return folder


def test_excluded_files_do_not_consume_hook_limit_or_change_snapshot(repo, monkeypatch):
    folder = generated(repo)
    monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'generated')
    monkeypatch.setattr('security_runtime.hook_runtime.MAX_FILES', 1)
    first = capture_snapshot(repo, b'a' * 32)
    assert set(first.file_digests) == {'A.java'}
    (folder / 'one.py').write_text('one = 99\n')
    (folder / 'two.py').unlink()
    after = capture_snapshot(repo, b'a' * 32)
    assert after == first and after.file_digests == first.file_digests


def test_removing_exclusion_reintroduces_files_and_limits(repo, monkeypatch):
    generated(repo)
    monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'generated')
    assert set(capture_snapshot(repo, b'a' * 32).file_digests) == {'A.java'}
    monkeypatch.delenv('SECURITY_RUNTIME_EXCLUDE_DIRS')
    current = capture_snapshot(repo, b'a' * 32)
    assert set(current.file_digests) == {'A.java', 'generated/one.py', 'generated/two.py'}
    monkeypatch.setattr('security_runtime.hook_runtime.MAX_FILES', 1)
    with pytest.raises(ValueError, match='budget'):
        capture_snapshot(repo, b'a' * 32)


def test_baseline_applies_exclusions_before_selected_file_limit(adapter, repo, monkeypatch):
    generated(repo)
    monkeypatch.setenv('SECURITY_RUNTIME_EXCLUDE_DIRS', 'generated')
    monkeypatch.setattr('security_runtime.hook_runtime.MAX_FILES', 1)
    snapshot = adapter.baselines.capture_session(repo, 'excluded-baseline')
    assert snapshot['last_result']['status'] == 'PRE_EXISTING_BASELINE'
    assert adapter.baselines.coordinator.runtime.calls == [('A.java',)]
