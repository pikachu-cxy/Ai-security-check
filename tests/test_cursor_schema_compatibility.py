"""Public Cursor string[]/opaque generation contract; no Desktop attestation."""
import json
from pathlib import Path

import pytest

from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.recent_hooks import RecentHookStore, safe_fields
from test_cursor_host_adapter import payload
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_host_event_normalization import other_repo


@pytest.mark.parametrize('generation', ['turn: first/α', 'f46c47b4-f012-4569-8715-ecd1b29781ba',
    'x'*500, '${opaque-value}', 'not hex / not uuid'])
def test_generation_is_opaque(repo, generation):
    raw=payload(repo, generation_id=generation)
    diag=CursorHostEventAdapter().validate_claims(raw,'afterFileEdit')
    assert diag['host_claim_status']=='VALID'
    assert diag['generation_id_shape_valid'] and diag['generation_id_type_valid']
    assert diag['generation_id_validation_reason']=='VALID'
    assert diag['generation_id_length']==len(generation)
    assert generation not in diag.values()


@pytest.mark.parametrize('generation,reason', [('', 'EMPTY'), ('   ','EMPTY'),
    (None,'INVALID_TYPE'), (123,'INVALID_TYPE'), ('x'*501,'OVERSIZED'),
    ('\x00private','CONTROL_CHARACTER'), ('\ud800','INVALID_UNICODE'),
    (' '*501+'x','OVERSIZED')])
def test_invalid_generation_reason_and_privacy(repo,tmp_path,generation,reason):
    store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo,generation_id=generation),store=store)
    assert result['reason']=='INVALID_HOST_CLAIMS' and not result['scanner_run']
    row=store.recent(unbound=True)['records'][0]
    assert row['generation_id_validation_reason']==reason
    assert row['generation_id_shape_valid'] is False
    assert row['last_stage']=='CLAIMS_REJECTED'
    assert 'generation_id' not in row and 'private-cursor-conversation' not in json.dumps(row)


@pytest.mark.parametrize('roots,reason,rejection', [(['\n'], 'INVALID_ROOT',None),
    (['a','b'],'MULTI_ROOT_UNSUPPORTED','CURSOR_MULTI_ROOT_UNSUPPORTED'),
    (None,'INVALID_TYPE',None), ([None],'INVALID_ROOT',None),
    ([''],'INVALID_ROOT',None), (['x'*4097],'INVALID_ROOT',None)])
def test_root_shape_fail_closed(repo,tmp_path,roots,reason,rejection):
    _,result=handle_cursor_event(payload(repo,workspace_roots=roots),store=RecentHookStore(tmp_path/'recent.db'))
    assert result['workspace_roots_validation_reason']==reason
    assert result.get('workspace_rejection_reason')==rejection
    assert result['host_claim_status']=='INVALID' and not result['scanner_run']


@pytest.mark.parametrize('style', ['root','subdir','slash','case','trailing'])
def test_user_hook_cwd_is_never_workspace(repo,tmp_path,monkeypatch,style):
    home=tmp_path/'.cursor';home.mkdir();monkeypatch.chdir(home)
    sub=repo/'src';sub.mkdir(exist_ok=True)
    claim={'root':str(repo), 'subdir':str(sub), 'slash':str(repo).replace('\\','/'),
           'case':str(repo).upper() if __import__('os').name=='nt' else str(repo),
           'trailing':str(repo)+'/' }[style]
    diag={}
    resolved=CursorHostEventAdapter().resolve(payload(repo,workspace_roots=[claim]),
        project_dir=str(repo),diagnostics=diag)
    assert resolved==repo and resolved!=Path.cwd()
    assert diag['cursor_workspace_source']=='CORROBORATED' and diag['workspace_sources_match']
    assert diag['file_path_containment'] and str(repo) not in json.dumps(diag)


def test_source_conflict_observed_under_claimed_workspace(repo,tmp_path):
    other=other_repo(tmp_path/'other');store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo),project_dir=str(other),store=store)
    assert result['reason']=='CURSOR_WORKSPACE_SOURCE_MISMATCH' and not result['scanner_run']
    row=store.recent(other)['records'][0]
    assert row['workspace_sources_match'] is False and row['workspace_claim_match'] is False
    assert row['cursor_workspace_resolution_stage']=='WORKSPACE_ROOTS'
    assert row['session_claim_match'] is None and row['last_stage']=='CLAIMS_REJECTED'
    assert str(repo) not in json.dumps(row) and str(other) not in json.dumps(row)


def test_outside_file_and_nested_repo_have_distinct_reasons(repo,tmp_path):
    other=other_repo(tmp_path/'other');store=RecentHookStore(tmp_path/'recent.db')
    _,outside=handle_cursor_event(payload(repo,file_path=str(other/'A.java')),project_dir=str(repo),store=store)
    assert outside['reason']=='WORKSPACE_OUTSIDE_ALLOWED_ROOT' and outside['file_path_containment'] is False
    nested=other_repo(repo/'nested')
    _,inside=handle_cursor_event(payload(repo,file_path=str(nested/'A.java')),project_dir=str(repo),store=store)
    assert inside['reason']=='CURSOR_FILE_WORKSPACE_MISMATCH' and inside['file_path_containment'] is True
    assert not inside['scanner_run'] and not outside['scanner_run']


def test_session_start_then_edit_and_shell_from_user_config_cwd(repo,tmp_path,monkeypatch):
    home=tmp_path/'.cursor';home.mkdir();monkeypatch.chdir(home)
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    def run(event,**fields):
        return handle_cursor_event(payload(repo,event,generation_id='arbitrary / generation',**fields),
            project_dir=str(repo),core=core,store=store,bindings=bindings)[1]
    initial=run('sessionStart')
    assert initial['host_claim_status']=='VALID' and initial['session_claim_match']
    runtime.calls.clear()
    (repo/'A.java').write_bytes(b'class A { int timeout=2100; }\r\n')
    edit=run('afterFileEdit')
    assert edit['scanner_run'] and edit['changed_file_count']==1 and edit['content_delta_detected']
    assert edit['snapshot_available'] and edit['normalized_operation_class']=='DIRECT_FILE_MUTATION'
    runtime.calls.clear()
    assert run('afterShellExecution')['scanner_skipped_reason']=='READ_ONLY_ACTIVITY'
    assert not runtime.calls
    (repo/'A.java').write_bytes(b'class A { int timeout=2200; }\r\n')
    assert run('afterShellExecution',command='Set-Content A.java private-command')['scanner_run']
    assert runtime.calls==[('A.java',)]
    assert b'private-command' not in store.path.read_bytes()


def test_diagnostic_closed_fields_cannot_echo_payload():
    result=safe_fields(dict(cursor_workspace_source='raw-path',generation_id_validation_reason='secret',
        cursor_project_workspace_hash='raw',generation_id='secret',command='private-command',
        workspace_sources_match='yes',generation_id_length=10001))
    assert result['cursor_workspace_source']=='UNKNOWN'
    assert result['generation_id_validation_reason']=='UNKNOWN'
    assert result['cursor_project_workspace_hash'] is None
    assert result['workspace_sources_match'] is None and result['generation_id_length'] is None
    assert 'secret' not in json.dumps(result) and 'private-command' not in json.dumps(result)
