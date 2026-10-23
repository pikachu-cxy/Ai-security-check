"""Core Codex acceptance keeps running when optional Git dispatch is skipped."""
import json
from pathlib import Path

import pytest

from scripts.release import verify_artifact
from security_runtime.cli import main


@pytest.mark.parametrize('hooks,git_pre_commit', [(True, False), (True, True), (False, True), (False, False)])
def test_optional_gate_routing_and_explicit_evidence(tmp_path, monkeypatch, hooks, git_pre_commit):
    calls = []
    monkeypatch.setattr(verify_artifact, 'run', lambda command, **kwargs: calls.append(command))
    report = verify_artifact.verify_hook_acceptances(Path('runtime.exe'), tmp_path, {}, tmp_path / 'bundle.zip',
        hooks=hooks, git_pre_commit=git_pre_commit, codex_integration=True)
    assert Path(calls[-1][1]).name == 'codex_integration_acceptance.py'
    assert len(calls) == (2 if hooks or git_pre_commit else 1)
    if hooks or git_pre_commit:
        assert Path(calls[0][1]).name == 'hook_acceptance.py'
        assert ('--git-pre-commit' in calls[0]) == git_pre_commit
    assert report['git_precommit']['status'] == ('PASS' if git_pre_commit else 'SKIPPED')
    if not git_pre_commit:
        assert report['git_precommit']['reason']


def test_help_hides_git_hook_but_preserves_codex_entry(capsys):
    with pytest.raises(SystemExit) as result:
        main(['hooks', '--help'])
    assert result.value.code == 0
    help_text = capsys.readouterr().out
    assert 'pre-commit' not in help_text
    assert 'codex' in help_text


@pytest.mark.parametrize('action', ['install', 'status', 'repair', 'remove'])
def test_explicit_git_hook_compatibility(tmp_path, monkeypatch, capsys, action):
    import subprocess
    from security_runtime.hooks import GitHookManager
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    calls = []
    def execute(self, requested, policy='strict'):
        calls.append((requested, policy))
        return {'status': 'FIXTURE', 'path': str(self.path)}
    monkeypatch.setattr(GitHookManager, 'execute', execute)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path / 'state'))
    assert main(['hooks', action, 'pre-commit', '--path', str(tmp_path), '--gate', 'report', '--json']) == 0
    assert calls == [(action, 'report')]
    assert json.loads(capsys.readouterr().out)['status'] == 'FIXTURE'


def test_optional_gate_failure_is_not_reported_as_pass(tmp_path, monkeypatch):
    def fail(command, **kwargs):
        raise RuntimeError('fixture Git dispatch failed')
    monkeypatch.setattr(verify_artifact, 'run', fail)
    with pytest.raises(RuntimeError, match='fixture Git dispatch failed'):
        verify_artifact.verify_hook_acceptances(Path('runtime.exe'), tmp_path, {}, tmp_path / 'bundle.zip',
            hooks=True, git_pre_commit=True, codex_integration=True)


def test_optional_gate_still_requires_managed_engines(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['verify_artifact.py', 'fixture.zip', '--git-pre-commit'])
    with pytest.raises(SystemExit) as result:
        verify_artifact.main()
    assert result.value.code == 2
    assert '--git-pre-commit requires --full' in capsys.readouterr().err
