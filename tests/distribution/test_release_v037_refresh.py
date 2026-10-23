"""Bounded release publication guards; no network, native build or project scan."""
import copy
import json
from pathlib import Path

import pytest
import yaml

from scripts.release import refresh_release_v037 as refresh


@pytest.fixture
def publication(tmp_path, monkeypatch):
    work = tmp_path / 'dist/refresh-v037'
    for directory in ('previous', 'staged'):
        (work / directory).mkdir(parents=True)
    approval = dict(repository=refresh.REPOSITORY, tag=refresh.TAG, release_id=123,
        source_commit=refresh.SOURCE, original_tag_commit='a'*40,
        build_run_id=1, test_run_id=2, assets={})
    files, assets = {}, []
    for number, name in enumerate(sorted(refresh.names())):
        old, new = work / 'previous' / name, work / 'staged' / name
        old.write_bytes(('old:' + name).encode())
        new.write_bytes(('new:' + name).encode())
        approval['assets'][name] = dict(id=number, sha256=refresh.digest(old))
        files[name] = refresh.digest(new)
        assets.append(dict(id=number, name=name, digest='sha256:' + refresh.digest(old)))
    state = dict(id=123, tag_name=refresh.TAG, draft=False, immutable=False, body='old notes', assets=assets)
    (work / 'previous-release.json').write_text(json.dumps(state), encoding='utf-8')
    (work / 'release-notes.md').write_text('new notes', encoding='utf-8')
    (work / 'plan.json').write_text(json.dumps(dict(source_commit=refresh.SOURCE, files=files,
        notes_sha256=refresh.digest(work / 'release-notes.md'))), encoding='utf-8')
    calls, tag = [], [approval['original_tag_commit']]
    run = dict(head_sha=refresh.SOURCE, status='completed', conclusion='success')
    def api(path):
        if path.startswith('actions/runs/'):
            return copy.deepcopy(run)
        if path == f'releases/tags/{refresh.TAG}':
            return copy.deepcopy(state)
        if path == f'git/ref/tags/{refresh.TAG}':
            return dict(object=dict(type='commit', sha=tag[0]))
        raise AssertionError(path)
    def command(*args, **kwargs):
        calls.append(args)
        if args[:3] == ('gh', 'release', 'upload'):
            path = Path(args[4])
            state['assets'] = [row for row in state['assets'] if row['name'] != path.name]
            state['assets'].append(dict(id=100 + len(calls), name=path.name, digest='sha256:' + refresh.digest(path)))
        elif args[:2] == ('git', 'push'):
            assert args[-1] == f'--force-with-lease=refs/tags/{refresh.TAG}:{approval["original_tag_commit"]}'
            assert kwargs['cwd'] == tmp_path
            tag[0] = refresh.SOURCE
        elif args[:3] == ('gh', 'release', 'edit'):
            state['body'] = Path(args[-1]).read_text(encoding='utf-8')
        else:
            raise AssertionError(args)
    monkeypatch.setattr(refresh, 'api', api)
    monkeypatch.setattr(refresh, 'command', command)
    return tmp_path, approval, state, calls, tag, run


def test_complete_publication_and_retry_do_not_upload_or_retag_twice(publication):
    root, approval, _, calls, tag, _ = publication
    refresh.validate_approval(approval)
    refresh.publish(root, approval)
    uploads = [call for call in calls if call[:3] == ('gh', 'release', 'upload')]
    assert len(uploads) == len(refresh.names()) == 9
    assert tag[0] == refresh.SOURCE
    assert json.loads((root / 'dist/refresh-v037/publication.json').read_text())['status'] == 'PUBLISHED'
    refresh.publish(root, approval)
    assert len([call for call in calls if call[:3] == ('gh', 'release', 'upload')]) == 9
    assert len([call for call in calls if call[:2] == ('git', 'push')]) == 1


@pytest.mark.parametrize('change', ['asset', 'notes', 'backup', 'scope', 'release', 'tag', 'external-notes'])
def test_tampering_or_concurrent_changes_stop_before_writes(publication, change):
    root, approval, state, calls, tag, _ = publication
    work = root / 'dist/refresh-v037'
    name = sorted(refresh.names())[0]
    if change in ('asset', 'backup'):
        (work / ('staged' if change == 'asset' else 'previous') / name).write_bytes(b'changed')
    elif change == 'notes':
        (work / 'release-notes.md').write_text('changed')
    elif change == 'scope':
        plan = json.loads((work / 'plan.json').read_text())
        plan['files']['../unexpected'] = '0'*64
        (work / 'plan.json').write_text(json.dumps(plan))
    elif change == 'release':
        state['assets'][0]['digest'] = 'sha256:' + '0'*64
    elif change == 'tag':
        tag[0] = 'b'*40
    else:
        state['body'] = 'another author changed the notes'
    with pytest.raises(ValueError):
        refresh.publish(root, approval)
    assert not calls


@pytest.mark.parametrize('change', ['failed', 'cancelled', 'wrong-source', 'running'])
def test_failed_pending_or_wrong_ci_cannot_publish(publication, change):
    root, approval, _, calls, _, run = publication
    if change == 'wrong-source':
        run['head_sha'] = 'b'*40
    elif change == 'running':
        run['status'] = 'in_progress'
    else:
        run['conclusion'] = change
    with pytest.raises(ValueError):
        refresh.publish(root, approval)
    assert not calls


def test_partial_upload_can_resume_only_known_original_or_staged_bytes(publication):
    root, approval, state, _, _, _ = publication
    state['assets'].pop()
    refresh.publish(root, approval)
    assert {row['name'] for row in state['assets']} == refresh.names()


def test_workflow_has_backup_gate_before_write_permission_and_pins_source():
    root = Path(__file__).resolve().parents[2]
    workflow = yaml.load((root / '.github/workflows/refresh-v037.yml').read_text(), Loader=yaml.BaseLoader)
    assert workflow['permissions'] == {'contents': 'read'}
    stage, publish = workflow['jobs']['stage'], workflow['jobs']['publish']
    assert stage['permissions']['contents'] == 'read'
    assert publish['permissions']['contents'] == 'write' and publish['needs'] == 'stage'
    assert stage['steps'][-1]['uses'] == 'actions/upload-artifact@v4'
    assert stage['steps'][-1]['with']['retention-days'] == '90'
    assert stage['steps'][0]['with']['ref'] == publish['steps'][0]['with']['ref'] == refresh.SOURCE
    approval = json.loads((root / 'distribution/releases/v0.3.7-refresh.json').read_text())
    refresh.validate_approval(approval)
