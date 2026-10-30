"""Generated output declarations are task-scoped, explicit and fail closed."""
import subprocess
from pathlib import Path

import pytest

from security_runtime.development_check import DevelopmentCheckService
from security_runtime.development_scope import output_roots, select_outputs
from security_runtime.hook_state import HookStateStore

OWNER = dict(host='codex', session='1' * 64)


@pytest.fixture
def sample(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    service = DevelopmentCheckService(None, HookStateStore(tmp_path / 'state'),
        owner=OWNER, scan_path_provider=tmp_path / 'scans.db',
        launcher=lambda *a: pytest.fail('Declaration must not launch a scan'))
    ref = service.begin(root, 'outputs')['check_ref']
    return root, service, ref


def test_arbitrary_names_deleted_outputs_and_source_overrides(sample):
    root, service, ref = sample
    names = ['unusual-output/removed.js', 'unusual-output/tracked.py',
             'unusual-output/edited.py', 'unusual-output-sibling/app.py', 'src/app.py']
    (root / 'unusual-output').mkdir()
    (root / names[1]).write_text('tracked source')
    subprocess.run(['git', '-C', str(root), 'add', '--', names[1]], check=True)
    service.declare_outputs(root, ref, ['unusual-output'])
    store = service.store(root)
    with store.transaction() as db:
        store.append(db, store._get(db, ref), names, False, None, explicit=False)
    service.record(root, ref, [names[2]])
    row = store.load(ref, OWNER)
    selected, facts = select_outputs(root, row)
    assert selected == sorted(names[1:])
    assert facts['excluded_paths'] == [names[0]]
    assert facts['protected_paths'] == sorted(names[1:3])
    assert row['observed_paths'] == sorted(names)


def test_declaration_replace_revoke_version_and_task_isolation(sample):
    root, service, ref = sample
    before = service.get(root, ref)['dirty_seq']
    first = service.declare_outputs(root, ref, ['random-output'])
    assert first['dirty_seq'] == before + 1
    assert service.declare_outputs(root, ref, ['random-output'])['dirty_seq'] == first['dirty_seq']
    other = service.begin(root, 'other')['check_ref']
    assert not service.store(root).load(other).get('generated_output_roots')
    service.declare_outputs(root, ref, [])
    assert not service.store(root).load(ref)['generated_output_roots']
    foreign = DevelopmentCheckService(None, service.hooks, owner=dict(host='codex', session='2' * 64),
        scan_path_provider=service.scan_path())
    with pytest.raises(Exception):
        foreign.declare_outputs(root, ref, ['random-output'])


@pytest.mark.parametrize('name', ['.', '..', '../outside', '/absolute', 'C:/outside',
                                 '.git', 'x/.git/y', 'out/*', 'out/../src', 'out/'])
def test_unsafe_output_roots_rejected(sample, name):
    root, service, ref = sample
    with pytest.raises(ValueError):
        service.declare_outputs(root, ref, [name])


def test_exact_generated_file_and_symlink_root(sample, monkeypatch):
    root, service, ref = sample
    (root/'generated.js').write_text('output')
    service.declare_outputs(root, ref, ['generated.js'])
    service.record(root, ref, ['generated.js'])
    selected, facts = select_outputs(root, service.store(root).load(ref, OWNER))
    assert selected == ['generated.js'] and not facts['excluded_paths']
    def reject(*args):
        raise ValueError('symlink')
    monkeypatch.setattr('security_runtime.hook_state.no_links', reject)
    with pytest.raises(ValueError):
        output_roots(root, ['linked'])


def test_git_failure_retains_inputs(sample, monkeypatch):
    root, service, ref = sample
    row = dict(observed_paths=['output/a.py'], generated_output_roots=['output'])
    def fail(*args, **kwargs):
        raise RuntimeError('Git unavailable')
    monkeypatch.setattr('security_runtime.git.GitService._run_bytes', fail)
    selected, facts = select_outputs(root, row)
    assert selected == row['observed_paths']
    assert facts['gaps'] == ['GENERATED_OUTPUT_SCOPE_UNVERIFIABLE']
    assert not facts['excluded_paths']


def test_no_declaration_never_queries_git(sample, monkeypatch):
    root, _, _ = sample
    monkeypatch.setattr('security_runtime.git.GitService', lambda *a: pytest.fail('unexpected Git'))
    selected, facts = select_outputs(root, dict(observed_paths=['src/new.py']))
    assert selected == ['src/new.py']
    assert not facts['gaps'] and not facts['excluded_paths']
