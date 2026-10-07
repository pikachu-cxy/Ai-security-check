"""Strict native env anchor; bounded roots are corroboration, never cwd routing."""
import json
import os

import pytest

from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.recent_hooks import RecentHookStore, safe_fields
from test_cursor_host_adapter import payload
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_host_event_normalization import other_repo


@pytest.mark.parametrize('roots,state', [([], 'EMPTY_HOST_LIST'), (['relative-project'], 'UNVERIFIED_RELATIVE'),
    (['/host/project'] if os.name == 'nt' else ['./host/project'], 'UNVERIFIED_RELATIVE')])
def test_anchor_baseline_real_delta_same_bytes_stop_and_privacy(repo,tmp_path,monkeypatch,roots,state):
    home=tmp_path/'.cursor';home.mkdir();monkeypatch.chdir(home)
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    def run(event,**fields):
        return handle_cursor_event(payload(repo,event,workspace_roots=roots,**fields),core=core,
            project_dir=str(repo),store=store,bindings=bindings)[1]
    start=run('sessionStart',generation_id='')
    assert start['host_claim_status']=='VALID' and start['baseline_available']
    assert start['generation_state']=='NOT_YET_AVAILABLE'  # Prior generation contract is unchanged.
    assert start['cursor_workspace_anchor']=='CURSOR_PROJECT_DIR'
    assert start['cursor_project_dir_valid'] and start['cursor_project_dir_is_absolute']
    assert start['cursor_project_dir_canonicalized'] and start['session_claim_match']
    assert start['workspace_root_corroboration']==state and start['workspace_sources_match'] is None
    runtime.calls.clear()
    (repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    edit=run('afterFileEdit')
    assert edit['content_delta_detected'] and edit['workspace_mutation_observed'] and edit['scanner_run']
    assert edit['changed_file_count']==1 and runtime.calls==[('A.java',)]
    assert edit['file_path_absolute'] and edit['file_path_containment']
    runtime.calls.clear()
    assert run('afterFileEdit')['status']=='NO_CHANGE'
    assert run('afterShellExecution')['scanner_skipped_reason']=='READ_ONLY_ACTIVITY'
    assert run('stop')['host_claim_status']=='VALID' and not runtime.calls
    rows=store.recent(repo)['records']
    assert all(row['cursor_workspace_anchor']=='CURSOR_PROJECT_DIR' for row in rows)
    assert rows[0]['workspace_root_corroboration']==state
    assert not store.recent(home)['records']
    for raw in ('private-cursor-conversation','private-generation','secret-new','secret-output','git status',str(repo),*roots):
        assert raw.encode() not in store.path.read_bytes()
    assert '"workspace_roots":' not in json.dumps(rows)  # Exact raw field is not persisted.


@pytest.mark.parametrize('roots',[[],['relative-project']])
def test_missing_anchor_cannot_use_roots_or_cwd(repo,tmp_path,monkeypatch,roots):
    monkeypatch.chdir(repo)
    runtime=FakeRuntime();store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo,'sessionStart',workspace_roots=roots,generation_id=''),
        core=coordinator(tmp_path,runtime),store=store)
    assert result['reason']=='CURSOR_PROJECT_DIR_REQUIRED' and not result['scanner_run'] and not runtime.calls
    assert store.recent(unbound=True)['records'][0]['workspace_binding_reason']=='CURSOR_PROJECT_DIR_REQUIRED'


@pytest.mark.parametrize('anchor,reason',[('', 'RAW_PATH_NOT_ABSOLUTE'), ('relative-project','RAW_PATH_NOT_ABSOLUTE'),
    ('file:///private-project','URI_STYLE_PATH'), (None,'CURSOR_PROJECT_DIR_REQUIRED')])
def test_invalid_anchor_never_falls_back_to_absolute_roots(repo,tmp_path,anchor,reason):
    _,result=handle_cursor_event(payload(repo),project_dir=anchor,store=RecentHookStore(tmp_path/'recent.db'))
    assert result['host_claim_status']=='REJECTED' and result['reason']==reason and not result['scanner_run']
    assert result['cursor_project_dir_valid'] is False


@pytest.mark.parametrize('roots',[None,{},[None],[''],['x'*4097],['\n'],['\ud800'],['a','b']])
def test_roots_remain_bounded_typed_claims(repo,tmp_path,roots):
    _,result=handle_cursor_event(payload(repo,workspace_roots=roots),project_dir=str(repo),
        store=RecentHookStore(tmp_path/'recent.db'))
    assert result['reason']=='INVALID_HOST_CLAIMS' and 'workspace_roots' in result['invalid_claims']
    assert not result['scanner_run']
    if roots==['a','b']:
        assert result['workspace_rejection_reason']=='CURSOR_MULTI_ROOT_UNSUPPORTED'


def test_absolute_corroboration_mismatch_cannot_bind_session(repo,tmp_path):
    other=other_repo(tmp_path/'other');bindings=CursorBindings(tmp_path/'bindings')
    _,result=handle_cursor_event(payload(repo),project_dir=str(other),bindings=bindings,
        store=RecentHookStore(tmp_path/'recent.db'))
    assert result['reason']=='CURSOR_WORKSPACE_SOURCE_MISMATCH'
    assert result['workspace_root_corroboration']=='MISMATCH' and not result['workspace_claim_match']
    assert not bindings.base.joinpath('bindings.json').exists()


@pytest.mark.parametrize('kind',['outside','nested','relative','missing'])
def test_relative_roots_do_not_weaken_file_boundary(repo,tmp_path,kind):
    other=other_repo(tmp_path/'other');nested=other_repo(repo/'nested')
    file={'outside':str(other/'A.java'),'nested':str(nested/'A.java'),
        'relative':'A.java','missing':str(repo/'missing.java')}[kind]
    runtime=FakeRuntime()
    _,result=handle_cursor_event(payload(repo,workspace_roots=['relative-project'],file_path=file),
        project_dir=str(repo),core=coordinator(tmp_path,runtime),store=RecentHookStore(tmp_path/'recent.db'))
    assert result['host_claim_status']=='REJECTED' and not result['scanner_run'] and not runtime.calls


def test_relative_roots_never_get_resolved_or_grant_cross_session_binding(repo,tmp_path,monkeypatch):
    import security_runtime.cursor_workspace as workspace
    real=workspace.resolve_cursor_workspace;seen=[]
    def resolve(raw,**kw):
        seen.append(raw);return real(raw,**kw)
    monkeypatch.setattr(workspace,'resolve_cursor_workspace',resolve)
    bindings=CursorBindings(tmp_path/'bindings');bindings.accept(repo,'private-cursor-conversation')
    other=other_repo(tmp_path/'other');store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(other,'sessionStart',workspace_roots=['never-look-this-up'],generation_id=''),
        project_dir=str(other),bindings=bindings,store=store)
    assert seen==[str(other)]
    assert result['reason']=='WORKSPACE_SESSION_MISMATCH' and result['session_claim_match'] is False
    assert not result['scanner_run']


def test_missing_roots_claim_still_rejected_with_valid_anchor(repo,tmp_path):
    raw=payload(repo);raw.pop('workspace_roots')
    _,result=handle_cursor_event(raw,project_dir=str(repo),store=RecentHookStore(tmp_path/'recent.db'))
    assert result['reason']=='INVALID_HOST_CLAIMS' and result['missing_claims']==['workspace_roots']


def test_diagnostics_cannot_echo_arbitrary_anchor_or_root_metadata():
    result=safe_fields(dict(cursor_workspace_anchor='private-path',workspace_roots_state='private-roots',
        workspace_root_corroboration='secret',workspace_binding_reason='raw-command',
        cursor_project_dir_valid='yes',file_path_absolute='secret',workspace_root_relative='secret',
        cursor_project_dir='private-env',workspace_roots=['private-root']))
    assert all(v in ('UNKNOWN',None) for v in result.values())
    assert 'private-' not in json.dumps(result) and 'secret' not in json.dumps(result)
