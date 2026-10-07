"""Policy does not imply Host execution capability; no scan proof is invented."""
from dataclasses import replace
import json
import os

import pytest

from test_hook_runtime import repo
from test_first_scan_attribution import harness, commit, start, edit
from test_remediation import FIXED, UNSAFE, setup
from test_cursor_host_adapter import payload
from security_runtime.cursor_hook import CursorBindings, handle_cursor_event
from security_runtime.host_events import HostCapabilities, VerifiedHostContext
from security_runtime.hook_state import identity
from security_runtime.recent_hooks import RecentHookStore, safe_fields
from security_runtime.remediation import RemediationService
from security_runtime.remediation_policy import RemediationConfig
from security_runtime.remediation_transport import AdvisoryTransportConfig, RemediationTransportConfig


def context(root, *, host='cursor', session='session'):
    return VerifiedHostContext(host, root, identity(os.path.normcase(str(root))), identity(session),
        None, HostCapabilities(), session)


def service(harness, *, transport=None):
    core, _, _, store = harness
    return RemediationService(store, hooks=core.store, transport=transport or AdvisoryTransportConfig())


def risk(repo, harness):
    core = harness[0]; commit(repo, FIXED); start(core, repo)
    return edit(core, repo)


def assert_offer(out, expected='AUTO_FIX'):
    assert out['status'] == 'REMEDIATION_OFFERED' and out['remediation_status'] == 'OFFERED'
    assert out['policy_decision'] == expected and out['action'] == 'ADVISE'
    assert out['remediation_execution_capability'] == 'ADVISORY_ONLY'
    assert out['remediation_transport_mode'] == 'ADVISORY'
    assert out['agent_continuation_available'] is False
    assert out['verification_status'] == 'NOT_VERIFIED' and not out['automatic_execution']
    assert out['remediation_workspace_source'] == 'VERIFIED_HOST_CONTEXT'
    assert out['advisory_fix_context']['authorization']['edit_authorized'] is False
    assert not set(out) & {'prepare', 'verify', 'grant_id', 'remediation_ref', 'confirmation_ref', 'agent_fix_ticket'}


def test_cursor_first_attributed_tls_offers_without_grant(repo, harness, tmp_path):
    core = harness[0]; commit(repo, FIXED)
    bindings = CursorBindings(tmp_path/'binding')
    recent = RecentHookStore(tmp_path/'recent.db')
    def hook(event):
        return handle_cursor_event(payload(repo, event), core=core, bindings=bindings,
            project_dir=str(repo), store=recent)
    assert not hook('sessionStart')[1]['scanner_run']
    (repo/'A.java').write_bytes(UNSAFE.encode()); before = (repo/'A.java').read_bytes()
    native, out = hook('afterFileEdit')
    assert native == {}  # Frozen Cursor schema; no fictional post-edit context field.
    assert out['first_scan_attribution_status'] == 'FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert_offer(out['remediation'])
    assert out['remediation']['policy_authorization_kind'] == 'POLICY_AUTO'
    assert out['continuation_status'] == 'PENDING_CURSOR_CONTINUATION_CAPABILITY'
    assert (repo/'A.java').read_bytes() == before
    row = recent.recent(repo)['records'][0]
    for key in ('policy_decision', 'remediation_status', 'remediation_execution_capability',
                'remediation_transport_mode', 'agent_continuation_available', 'remediation_workspace_source'):
        assert row[key] == out['remediation'][key]
    assert 'advisory_fix_context' not in row and str(repo) not in json.dumps(row)


@pytest.mark.parametrize('mode,expected', [('report_only','ADVISE'), ('ask_before_fix','CONFIRM_REQUIRED')])
def test_non_auto_policy_preserved(repo, harness, mode, expected):
    result = risk(repo, harness); svc = service(harness); svc.config.write(mode)
    out = svc.on_hook(result, repo, 'session', host='cursor', workspace_context=context(repo))
    assert_offer(out, expected)
    assert not list(svc.state.workspace_directory(repo).glob('*.json'))
    assert svc.prepared == set() and svc.authorized == {} and not svc.continuation.handoffs


def test_cursor_uses_actual_user_policy_config(repo, harness, tmp_path, monkeypatch):
    policy = RemediationConfig(tmp_path/'user-policy.json'); policy.write('report_only')
    monkeypatch.setattr(RemediationConfig, '__init__', lambda self, path=None: setattr(self, 'path', policy.path))
    core = harness[0]; commit(repo, FIXED)
    bindings = CursorBindings(tmp_path/'bindings')
    def hook(event):
        return handle_cursor_event(payload(repo,event),core=core,bindings=bindings,
            project_dir=str(repo),store=RecentHookStore(tmp_path/'recent.db'))[1]
    hook('sessionStart'); (repo/'A.java').write_bytes(UNSAFE.encode())
    assert_offer(hook('afterFileEdit')['remediation'], 'ADVISE')


@pytest.mark.parametrize('bad', ['missing', 'workspace', 'session', 'host'])
def test_verified_workspace_context_required(repo, harness, tmp_path, bad):
    result=risk(repo,harness); svc=service(harness); ctx=context(repo)
    if bad == 'missing':ctx=None
    elif bad == 'workspace':
        other=tmp_path/'other'; other.mkdir();ctx=context(other)
    elif bad == 'session':ctx=context(repo,session='wrong')
    else:ctx=context(repo,host='generic')
    out=svc.on_hook(result,repo,'session',host='cursor',workspace_context=ctx)
    assert out['reason_code'] == ('VERIFIED_WORKSPACE_CONTEXT_REQUIRED' if bad=='missing'
                                 else 'VERIFIED_WORKSPACE_CONTEXT_MISMATCH')
    assert out['verification_status']=='INCONCLUSIVE' and out['remediation_workspace_source']=='UNAVAILABLE'
    assert not svc.state.workspace_directory(repo).exists()


def test_generic_advisory_capability_reuses_same_flow(repo,harness):
    result=risk(repo,harness)
    svc=service(harness,transport=RemediationTransportConfig(
        supports_advisory_remediation=True,supports_agent_continuation=False))
    out=svc.on_hook(result,repo,'generic-session',host='generic',
        workspace_context=context(repo,host='generic',session='generic-session'))
    assert_offer(out)


def test_offer_no_source_secret_or_raw_host_ids(repo,harness):
    result=risk(repo,harness);svc=service(harness)
    scan=svc.store.get_scan(result['scan_id']); finding=scan['findings'][0]
    # Hook/scanner arbitrary prose must never become advisory guidance.
    finding['description']='PRIVATE_SECRET_CANARY'; finding['raw_data']={'source':'PRIVATE_SOURCE_CANARY'}
    svc.store.get_scan=lambda _:scan
    out=svc.on_hook(result,repo,'PRIVATE_HOST_ID',host='generic',
        workspace_context=context(repo,host='generic',session='PRIVATE_HOST_ID'))
    assert_offer(out)
    encoded=json.dumps(out,ensure_ascii=True)
    for raw in ('PRIVATE_HOST_ID','PRIVATE_SECRET_CANARY','PRIVATE_SOURCE_CANARY', 'setHostnameVerifier((hostname, session) -> true)'):
        assert raw not in encoded
    facts=out['advisory_fix_context']
    assert facts['finding']['finding_id']==finding['id'] and facts['target']['file_identity']==identity('A.java')
    assert facts['verification_requirement']=='REAL_ORIGINAL_RULE_FILE_SCANNER_RECHECK_REQUIRED'


def test_no_execution_capability_fails_closed(repo,harness):
    result=risk(repo,harness);svc=service(harness,transport=RemediationTransportConfig(
        supports_advisory_remediation=False,supports_agent_continuation=False))
    out=svc.on_hook(result,repo,'session',host='cursor',workspace_context=context(repo))
    assert out['reason_code']=='REMEDIATION_EXECUTION_UNAVAILABLE'
    assert out['remediation_execution_capability']=='UNAVAILABLE'


def test_transport_does_not_have_policy_path_or_read():
    cfg=AdvisoryTransportConfig()
    assert not hasattr(cfg,'path') and not hasattr(cfg,'read') and not cfg.supports_write
    with pytest.raises(ValueError): RemediationTransportConfig(supports_write=True)
    with pytest.raises(ValueError): RemediationTransportConfig(supports_agent_continuation='yes')


def test_advisory_cannot_issue_or_resume_grant(repo,harness):
    result=risk(repo,harness);svc=service(harness)
    assert svc._allowed({'authorization_kind':'POLICY_AUTO'}, b'key') is False
    with pytest.raises(ValueError,match='AGENT_CONTINUATION_UNAVAILABLE'):
        svc._grant(None,{},None)
    # Capability cannot be asserted by scanner/host result fields.
    result['supports_agent_continuation']=True
    assert_offer(svc.on_hook(result,repo,'session',host='cursor',workspace_context=context(repo)))


def test_stale_advisory_task_does_not_offer(repo,harness,monkeypatch):
    result=risk(repo,harness);svc=service(harness)
    monkeypatch.setattr(svc,'_fix',lambda: type('Stale',(),{'_resolve':lambda *a: ({'status':'REFRESH_REQUIRED'},None,[])})())
    out=svc.on_hook(result,repo,'session',host='cursor',workspace_context=context(repo))
    assert out['reason_code']=='ADVISORY_CONTEXT_NOT_CURRENT'
    assert out['remediation_status']=='INCONCLUSIVE'


def test_policy_storage_is_explicit_and_confirmation_revision_preserved(tmp_path):
    config=RemediationConfig(tmp_path/'policy.json')
    assert config.managed_paths()==(config.path,) and config.revision() is None
    config.write('smart_auto')
    assert config.revision()==config.path.stat().st_mtime_ns


def test_diagnostics_closed_no_advisory_payload_or_path():
    out=safe_fields({'policy_decision':'SECRET', 'remediation_status':'OFFERED',
        'agent_continuation_available':'true', 'advisory_fix_context':{'source':'CANARY'},
        'workspace_path':'PRIVATE_PATH'})
    assert out=={'policy_decision':'UNKNOWN','remediation_status':'OFFERED','agent_continuation_available':None}


def test_advisory_does_not_resume_or_mutate_existing_agent_episode(setup):
    root, runtime, _, live, hook, grant = setup
    assert grant['remediation']['action'] == 'AUTO_FIX'
    path = live.state.path(root, 'codex', 'session'); before = path.read_bytes()
    (root/'A.java').write_bytes(UNSAFE.replace('1000', '2400').encode())
    from security_runtime.hook_runtime import HookCoordinator
    from security_runtime.hooks import HookEvent
    result = HookCoordinator(runtime, live.hooks, cooldown_ms=0).handle(
        HookEvent.FILE_CHANGED, root, 'codex', 'session')
    advisory = RemediationService(live.store, registry=live.registry, hooks=live.hooks,
        directory=live.state.directory, transport=AdvisoryTransportConfig())
    out = advisory.on_hook(result, root, 'session', host='codex',
        workspace_context=context(root, host='codex'))
    assert out['action'] != 'AUTO_FIX' and not out.get('prepare')
    assert path.read_bytes() == before and not advisory.prepared


def test_invalid_policy_file_is_not_bypassed_for_advisory(repo,harness):
    result=risk(repo,harness);svc=service(harness)
    svc.config.path.write_text('{"remediation":{"mode":"INVALID"}}')
    out=svc.on_hook(result,repo,'session',host='cursor',workspace_context=context(repo))
    assert out['remediation_status']=='INCONCLUSIVE' and 'advisory_fix_context' not in out
