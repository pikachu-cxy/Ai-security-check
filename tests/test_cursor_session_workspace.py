"""Cursor session-before-generation and strict observable workspace ingress."""
import hashlib
import hmac
import json
import os
import subprocess
from pathlib import Path

import pytest

from security_runtime.cursor_event_adapter import CursorHostEventAdapter
from security_runtime.cursor_hook import CursorBindings, encode, handle_cursor_event
from security_runtime.cursor_workspace import git_probe, resolve_cursor_workspace
from security_runtime.hook_state import identity
from security_runtime.recent_hooks import RecentHookStore, safe_fields
from test_cursor_host_adapter import payload
from test_hook_runtime import repo, coordinator, FakeRuntime
from test_host_event_normalization import other_repo


@pytest.mark.parametrize('missing', [False, True])
def test_session_before_generation_establishes_baseline_then_real_delta(repo,tmp_path,missing):
    runtime=FakeRuntime();core=coordinator(tmp_path,runtime,cooldown_ms=0)
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    raw=payload(repo,'sessionStart',generation_id='')
    if missing:raw.pop('generation_id')
    def run(value):
        return handle_cursor_event(value,core=core,store=store,bindings=bindings,project_dir=str(repo))[1]
    start=run(raw)
    assert start['host_claim_status']=='VALID' and start['session_claim_match']
    assert start['generation_state']==start['generation_binding_status']=='NOT_YET_AVAILABLE'
    assert start['generation_id_validation_reason']=='NOT_YET_AVAILABLE'
    runtime.calls.clear()
    (repo/'A.java').write_bytes(b'class A { int timeout=2400; }\r\n')
    edit=run(payload(repo,generation_id='first-turn'))
    assert edit['generation_binding_status']=='OBSERVED' and edit['generation_state']=='AVAILABLE'
    assert edit['scanner_run'] and edit['snapshot_available'] and edit['content_delta_detected']
    assert edit['workspace_mutation_observed'] and edit['changed_file_count']==1
    assert edit['cursor_workspace_source']=='CORROBORATED' and edit['workspace_sources_match']
    assert edit['file_path_containment'] and runtime.calls==[('A.java',)]
    runtime.calls.clear()
    unchanged=run(payload(repo,generation_id='first-turn'))
    assert unchanged['generation_binding_status']=='UNCHANGED' and not runtime.calls
    next_turn=run(payload(repo,'afterShellExecution',generation_id='next-user-message'))
    assert next_turn['host_claim_status']=='VALID' and next_turn['generation_binding_status']=='UPDATED'
    assert next_turn['scanner_skipped_reason']=='READ_ONLY_ACTIVITY' and not runtime.calls
    stop=run(payload(repo,'stop',generation_id='next-user-message'))
    assert stop['host_claim_status']=='VALID' and stop['generation_binding_status']=='UNCHANGED'
    again=run(raw)
    assert again['generation_state']=='NOT_YET_AVAILABLE' and again['generation_binding_status']=='RETAINED'
    assert not runtime.calls  # Repeated sessionStart cannot replace the pre-edit comparison point.
    for secret in ('first-turn','next-user-message','private-cursor-conversation',str(repo)):
        assert secret not in bindings.base.joinpath('bindings.json').read_text()
        assert secret.encode() not in store.path.read_bytes()


@pytest.mark.parametrize('generation,reason', [(None,'INVALID_TYPE'), (42,'INVALID_TYPE'),
    ('x'*501,'OVERSIZED'), (' '*501,'OVERSIZED'), ('\n','CONTROL_CHARACTER'),
    ('\x00','CONTROL_CHARACTER'), ('\ud800','INVALID_UNICODE'), (' ','EMPTY')])
def test_session_malformed_generation_still_rejects(repo,tmp_path,generation,reason):
    store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo,'sessionStart',generation_id=generation),store=store)
    assert result['host_claim_status']=='INVALID' and 'generation_id' in result['invalid_claims']
    assert result['generation_id_validation_reason']==reason and not result['scanner_run']
    assert store.recent(unbound=True)['records'][0]['last_stage']=='CLAIMS_REJECTED'


@pytest.mark.parametrize('event',['afterFileEdit','afterShellExecution','stop'])
@pytest.mark.parametrize('missing',[False,True])
def test_generation_unavailable_never_spreads_to_activity(repo,event,missing):
    raw=payload(repo,event,generation_id='')
    if missing:raw.pop('generation_id')
    diag=CursorHostEventAdapter().validate_claims(raw,event)
    assert diag['host_claim_status']=='INVALID' and diag['generation_state']=='INVALID'
    assert 'generation_id' in diag['missing_claims']+diag['invalid_claims']


def test_binding_reload_legacy_migration_and_cross_workspace(repo,tmp_path):
    bindings=CursorBindings(tmp_path/'bindings')
    bindings.accept(repo,'same-session')
    path=bindings.base/'bindings.json';value=json.loads(path.read_bytes());value.pop('signature');value.pop('generations')
    key=bindings.store.key(bindings.base)
    path.write_bytes(encode({**value,'signature':hmac.new(key,encode(value),hashlib.sha256).hexdigest()}))
    migrated=CursorBindings(bindings.base)
    assert migrated.accept(repo,'same-session','generation-A')['generation_binding_status']=='OBSERVED'
    assert CursorBindings(bindings.base).accept(repo,'same-session','generation-B')['generation_binding_status']=='UPDATED'
    before=path.read_bytes()
    other=other_repo(tmp_path/'other')
    with pytest.raises(ValueError,match='SESSION_WORKSPACE_MISMATCH'):
        CursorBindings(bindings.base).accept(other,'same-session','generation-B')
    assert path.read_bytes()==before
    assert CursorBindings(bindings.base).accept(other,'other-session','generation-B')['generation_binding_status']=='OBSERVED'


@pytest.mark.parametrize('style',['native','forward','drivecase','trailing','subdir'])
def test_windows_repo_probe_path_variants(repo,tmp_path,monkeypatch,style):
    home=tmp_path/'.cursor';home.mkdir();monkeypatch.chdir(home)
    sub=repo/'src';sub.mkdir(exist_ok=True)
    text=str(repo)
    raw={'native':text,'forward':text.replace('\\','/'),
        'drivecase':text[0].swapcase()+text[1:] if os.name=='nt' else text,
        'trailing':text+os.sep,'subdir':str(sub)}[style]
    diag={};root=resolve_cursor_workspace(raw,diagnostics=diag)
    assert root==repo and root!=Path.cwd()
    assert diag['workspace_root_git_probe_status']=='OK'
    assert diag['workspace_root_git_repo_detected'] and diag['workspace_root_canonicalized']
    assert diag['workspace_root_is_absolute'] and diag['workspace_root_exists']
    assert diag['workspace_root_path_style']==('WINDOWS_NATIVE' if os.name=='nt' else 'POSIX')
    assert str(repo) not in json.dumps(diag)


@pytest.mark.parametrize('kind,reason',[('relative','RAW_PATH_NOT_ABSOLUTE'),
    ('uri','URI_STYLE_PATH'), ('absent','PATH_NOT_FOUND'), ('file','PATH_NOT_DIRECTORY'),
    ('drive-relative','WINDOWS_PATH_NORMALIZATION')])
def test_path_rejection_is_precise_before_git(repo,tmp_path,kind,reason):
    raw={'relative':'relative/private-name','uri':repo.as_uri(),
        'absent':str(tmp_path/'absent-private-name'),'file':str(repo/'A.java'),
        'drive-relative':'C:private-name'}[kind]
    store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo),project_dir=raw,store=store)
    assert result['reason']==reason and not result['scanner_run']
    row=store.recent(unbound=True)['records'][0]
    assert row['cursor_project_dir_resolution_reason']==reason
    assert row['cursor_project_dir_git_probe_status']=='NOT_RUN'
    assert row['cursor_project_dir_canonicalized'] is False and 'private-name' not in json.dumps(row)


@pytest.mark.parametrize('status,reason',[('DUBIOUS_OWNERSHIP','GIT_DUBIOUS_OWNERSHIP'),
    ('FAILED','GIT_ROOT_LOOKUP_FAILED'), ('TIMEOUT','GIT_ROOT_LOOKUP_FAILED'),
    ('UNAVAILABLE','GIT_ROOT_LOOKUP_FAILED')])
def test_git_failure_enum_does_not_fall_back_or_override_trust(repo,tmp_path,monkeypatch,status,reason):
    monkeypatch.setattr('security_runtime.cursor_workspace.git_probe',lambda root:(status,None))
    def forbidden(*a,**kw):raise AssertionError('canonical fallback must not mask probe failure')
    monkeypatch.setattr('security_runtime.cursor_workspace.resolve_workspace',forbidden)
    store=RecentHookStore(tmp_path/'recent.db')
    _,result=handle_cursor_event(payload(repo),project_dir=str(repo),store=store)
    assert result['reason']==reason and not result['scanner_run']
    row=store.recent(unbound=True)['records'][0]
    assert row['cursor_project_dir_resolution_step']=='GIT_PROBE'
    assert row['cursor_project_dir_git_probe_status']==status
    assert row['cursor_project_dir_resolution_reason']==reason


def test_git_probe_never_overrides_ownership_and_discards_output(repo,monkeypatch):
    import security_runtime.cursor_workspace as module
    seen=[]
    def run(argv,**kw):
        seen.append((argv,kw))
        kw['stderr'].write(b'fatal: detected dubious ownership in repository private-path secret')
        return subprocess.CompletedProcess(argv,128)
    monkeypatch.setenv('GIT_DIR','unrelated-repo');monkeypatch.setenv('GIT_WORK_TREE','unrelated-root')
    monkeypatch.setattr(module.subprocess,'run',run)
    assert git_probe(repo)==('DUBIOUS_OWNERSHIP',None)
    argv,kw=seen[0]
    assert 'safe.directory' not in repr(argv) and 'config' not in argv
    assert not any(key.upper().startswith('GIT_') for key in kw['env'])
    assert kw['stdin']==subprocess.DEVNULL and kw['timeout']==10


def test_non_git_source_compatibility_and_unrecognized_root(repo,tmp_path):
    source=tmp_path/'source';(source/'src').mkdir(parents=True)
    diag={};assert resolve_cursor_workspace(str(source),diagnostics=diag)==source
    assert diag['workspace_root_git_probe_status']=='NOT_REPOSITORY'
    assert diag['workspace_root_git_repo_detected'] is False and diag['workspace_root_canonicalized']
    empty=tmp_path/'empty';empty.mkdir()
    with pytest.raises(ValueError,match='ROOT_NOT_REPOSITORY'):
        resolve_cursor_workspace(str(empty),diagnostics=diag)
    assert diag['workspace_root_resolution_reason']=='ROOT_NOT_REPOSITORY'


def test_corroboration_nested_outside_and_cross_session_remain_closed(repo,tmp_path):
    other=other_repo(tmp_path/'other');nested=other_repo(repo/'nested')
    store=RecentHookStore(tmp_path/'recent.db');bindings=CursorBindings(tmp_path/'bindings')
    def run(raw,project):return handle_cursor_event(raw,project_dir=str(project),bindings=bindings,store=store)[1]
    conflict=run(payload(repo),other)
    assert conflict['cursor_project_dir_canonicalized'] and conflict['workspace_root_canonicalized']
    assert conflict['workspace_sources_match'] is False
    assert conflict['cursor_workspace_rejection_detail']=='CURSOR_PROJECT_DIR_MISMATCH'
    nesting=run(payload(repo,file_path=str(nested/'A.java')),repo)
    assert nesting['cursor_workspace_rejection_detail']=='NESTED_REPO_CONFLICT'
    outside=run(payload(repo,file_path=str(other/'A.java')),repo)
    assert outside['file_path_containment'] is False
    assert all(not r['scanner_run'] for r in (conflict,nesting,outside))
    bindings.accept(repo,'private-cursor-conversation','one')
    mismatch=run(payload(other,generation_id='two'),other)
    assert mismatch['reason']=='WORKSPACE_SESSION_MISMATCH' and not mismatch['scanner_run']
    assert mismatch['session_claim_match'] is False


def test_link_rejected_before_git(repo,tmp_path,monkeypatch):
    link=tmp_path/'junction'
    try:link.symlink_to(repo,target_is_directory=True)
    except OSError:
        assert os.name=='nt'
        result=subprocess.run(['cmd','/c','mklink','/J',str(link),str(repo)],capture_output=True)
        assert result.returncode==0,result.stderr
    def forbidden(*a):raise AssertionError('no Git on a link')
    monkeypatch.setattr('security_runtime.cursor_workspace.git_probe',forbidden)
    diag={}
    with pytest.raises(ValueError,match='LINK_OR_JUNCTION_REJECTED'):
        resolve_cursor_workspace(str(link),diagnostics=diag)
    assert diag['workspace_root_resolution_step']=='FILESYSTEM'


def test_git_root_must_agree_with_shared_resolver(repo,tmp_path,monkeypatch):
    other=other_repo(tmp_path/'other')
    monkeypatch.setattr('security_runtime.cursor_workspace.resolve_workspace',lambda *a,**kw:other)
    diag={}
    with pytest.raises(ValueError,match='REGISTERED_WORKSPACE_MISMATCH'):
        resolve_cursor_workspace(str(repo),diagnostics=diag)
    assert diag['workspace_root_canonicalized'] is False


def test_safe_path_and_generation_diagnostics_do_not_echo_raw_values():
    result=safe_fields(dict(workspace_root_resolution_reason='secret',workspace_root_path_style='raw-path',
        workspace_root_exists='yes',workspace_root_git_probe_status='stderr secret',
        generation_state='raw-generation',generation_binding_status='raw-session',
        generation_id='secret',workspace_roots=['private-root'],cursor_project_dir='private-env'))
    assert result['workspace_root_exists'] is None
    assert all(v=='UNKNOWN' for k,v in result.items() if k!='workspace_root_exists')
    assert 'secret' not in json.dumps(result) and 'private-' not in json.dumps(result)
