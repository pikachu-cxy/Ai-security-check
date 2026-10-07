"""The Host owns edits; Runtime offers/validates a single exact REMOVE plan."""
import copy
import json
from pathlib import Path

import pytest

from test_remediation import setup, args, prepare, UNSAFE, FIXED, CANARY
from test_hook_runtime import repo
from test_remediation_episodes import record, recur
from security_runtime.fast_fix import HOST_CONTRACT, sha, removal
from security_runtime.hook_timing import RemediationCycles


def offer(setup):
    root, _, _, service, _, grant=setup
    service.fast_fix.host_contract=HOST_CONTRACT  # Trusted test embedding, not Host claims.
    output=copy.deepcopy(grant['remediation'])
    with service.state.lock(root) as acquired:
        assert acquired
        state=record(setup)
        service.fast_fix.offer(output,root,state,service.state.key(root))
    assert output['fast_fix']['status']=='FAST_FIX_PLAN_READY',output
    service.cycles.set_fix_path(root,output['episode_id'],'DETERMINISTIC_FAST_FIX')
    service.cycles.mark(root,output['episode_id'],'fast_fix_plan_ready')
    return output['fast_fix_plan']


def simulated_host_apply(setup, plan, *, before_cas=None):
    """Disposable single-writer fixture; not a production atomic edit adapter."""
    root, _, _, service, _, _=setup
    with service.state.lock(root) as acquired:
        assert acquired
        result=service.fast_fix.validate_and_claim(plan,root)
        if result['status']!='FAST_FIX_APPLY_AUTHORIZED': return result
        target=root/plan['target_path']
        if before_cas: before_cas()
        source=target.read_bytes()
        left,right=plan['byte_range']['start'],plan['byte_range']['end']
        # Host must CAS too; Runtime attestation never permits a forced patch.
        if (sha(source)!=plan['expected_file_sha256'] or
                sha(source[left:right])!=plan['expected_segment_sha256']):
            return {'status':'FAST_FIX_STALE','reason_code':'FAST_FIX_CONCURRENT_MODIFICATION'}
        new=source[:left]+source[right:]
        assert sha(new)==plan['expected_result_sha256']
        target.write_bytes(new)  # Only the simulated Host writes.
        return result


def close(setup,plan):
    assert simulated_host_apply(setup,plan)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    setup[1].findings=setup[2].findings=[]
    return setup[4]()


def test_default_codex_cannot_claim_atomic_fast_apply(setup):
    decision=setup[-1]['remediation']
    assert decision['fix_path']=='AGENT_FIX'
    assert decision['fast_fix']['fallback_reason']=='FAST_FIX_HOST_CAPABILITY_UNAVAILABLE'
    assert not decision['fast_fix']['eligible'] and not decision['fast_fix']['plan_ready']
    assert 'fast_fix_plan' not in decision
    assert prepare(setup)['status']=='READY_FOR_HOST_FIX'


def test_exact_plan_no_source_no_prepare_no_deep(setup,monkeypatch):
    plan=offer(setup)
    raw=setup[0].joinpath('A.java').read_bytes()
    left,right=plan['byte_range']['start'],plan['byte_range']['end']
    assert raw[left:right].strip()==b'connection.setHostnameVerifier((hostname, session) -> true);'
    assert plan['expected_file_sha256']==sha(raw)
    assert plan['operation']=='DETERMINISTIC_REMOVE' and plan['replacement']==''
    assert plan['task_ref']==args(setup)['task_ref']
    assert plan['remediation_ref']==args(setup)['remediation_ref']
    assert plan['rule_id']=='ai-security.java.trust-all-hostname'
    assert not plan['result_contract']['deep_verification_authorized']
    assert CANARY not in json.dumps(plan) and 'context' not in plan
    monkeypatch.setattr(setup[3],'prepare',lambda *a,**k:pytest.fail('prepare must not run'))
    result=close(setup,plan)
    decision=result['remediation']
    assert decision['fix_path']=='DETERMINISTIC_FAST_FIX'
    assert decision['fast_fix']['host_fast_edit_observed']
    assert decision['security_verification']['status']=='SCANNER_VERIFIED_RESOLVED'
    assert decision['security_verification']['phase']=='CLOSED'
    assert record(setup)['attempt_count']==1
    assert setup[0].joinpath('A.java').read_bytes()==raw[:left]+raw[right:]
    assert len(setup[2].calls)==1  # Real production path keeps its distinct recheck.
    points=result['remediation_cycle_timepoints_ms']
    assert points['prepare_task_fix_started'] is points['prepare_task_fix_finished'] is None
    breakdown=result['remediation_cycle_breakdown_ms']
    assert breakdown['prepare_fix'] is None and breakdown['host_fix_window'] is None
    assert breakdown['host_fast_apply_window']>=0
    assert abs(sum(v for v in breakdown.values() if v is not None)-result['remediation_cycle_wall_ms'])<=.01
    assert result['remediation_cycle_breakdown_measurement']['status']=='OBSERVED'
    assert record(setup)['resolution']['binding']['grant_id']==plan['grant_id']


@pytest.mark.parametrize('field,value,reason',[
    ('episode_id','0'*64,'FAST_FIX_EPISODE_MISMATCH'),
    ('workspace_id','0'*64,'FAST_FIX_WORKSPACE_MISMATCH'),
    ('remediation_ref','invalid','FAST_FIX_REMEDIATION_MISMATCH'),
    ('task_ref','invalid','FAST_FIX_REMEDIATION_MISMATCH'),
    ('grant_id','0'*64,'FAST_FIX_REMEDIATION_MISMATCH'),
    ('rule_id','other.rule','FAST_FIX_UNSUPPORTED_RULE'),
    ('target_path','../foreign.java','FAST_FIX_PLAN_TAMPERED'),
    ('operation','REPLACE_ALL','FAST_FIX_PLAN_TAMPERED'),
    ('replacement','danger','FAST_FIX_PLAN_TAMPERED'),
    ('expected_file_sha256','0'*64,'FAST_FIX_PLAN_TAMPERED'),
    ('byte_range',{'start':0,'end':999},'FAST_FIX_PLAN_TAMPERED'),
    ('expires_in_seconds',999999,'FAST_FIX_PLAN_TAMPERED'),
    ('expires_in_seconds',900.0,'FAST_FIX_PLAN_TAMPERED'),
    ('result_contract',{'required':'POST_TOOL_USE_REAL_SCANNER_PROOF',
        'success':'SCANNER_VERIFIED_RESOLVED','stage':'CLOSED','next_action':'RETURN_TO_HOST',
        'production_correctness':'UNKNOWN','deep_verification_authorized':0},'FAST_FIX_PLAN_TAMPERED'),
])
def test_tampered_plan_never_applies(setup,field,value,reason):
    plan=offer(setup); plan[field]=value
    before=setup[0].joinpath('A.java').read_bytes()
    result=simulated_host_apply(setup,plan)
    assert result['reason_code']==reason
    assert setup[0].joinpath('A.java').read_bytes()==before
    assert not setup[3].prepared


@pytest.mark.parametrize('change,reason',[
    ('target','FAST_FIX_EXPECTED_BYTES_MISMATCH'),
    ('other','FAST_FIX_STALE_SNAPSHOT'),
    ('ignored','FAST_FIX_CONCURRENT_MODIFICATION'),
])
def test_changes_before_claim_fail_closed(setup,change,reason):
    plan=offer(setup); root=setup[0]
    if change=='target': root.joinpath('A.java').write_text(UNSAFE+'// moved offset\n')
    elif change=='other': root.joinpath('Other.java').write_text('class Other {}')
    else:
        root.joinpath('.gitignore').write_text('ignored.txt\n')
        # Existing ignore bytes were not authorized either.
        root.joinpath('ignored.txt').write_text('changed')
        # Snapshot includes .gitignore: use Git metadata exclusions to isolate preservation.
        root.joinpath('.gitignore').unlink()
        root.joinpath('.git/info/exclude').write_text('ignored.txt\n')
    before=root.joinpath('A.java').read_bytes()
    result=simulated_host_apply(setup,plan)
    assert result['status']=='FAST_FIX_STALE' and result['reason_code']==reason
    assert root.joinpath('A.java').read_bytes()==before


def test_host_cas_rejects_change_after_authority_check(setup):
    plan=offer(setup)
    changed=UNSAFE+'// concurrent edit\n'
    result=simulated_host_apply(setup,plan,before_cas=lambda:setup[0].joinpath('A.java').write_text(changed))
    assert result['reason_code']=='FAST_FIX_CONCURRENT_MODIFICATION'
    assert setup[0].joinpath('A.java').read_text()==changed
    assert record(setup)['phase']!='CLOSED'


def test_wrong_root_never_accesses_target(setup,tmp_path):
    plan=offer(setup)
    result=setup[3].fast_fix.validate_and_claim(plan,tmp_path/'other')
    assert result['reason_code']=='FAST_FIX_WORKSPACE_MISMATCH'
    assert not (tmp_path/'other').exists()


def test_expiration_policy_and_replay_cannot_authorize(setup):
    plan=offer(setup); fast=setup[3].fast_fix; item=fast.items[plan['plan_ref']]
    original=fast.clock; fast.clock=lambda:item['deadline']
    assert simulated_host_apply(setup,plan)['reason_code']=='FAST_FIX_AUTHORIZATION_EXPIRED_OR_CONSUMED'
    fast.clock=original
    setup[3].config.write('report_only')
    assert simulated_host_apply(setup,plan)['reason_code']=='FAST_FIX_AUTHORIZATION_INVALID'
    setup[3].config.path.unlink()
    # Configuration identity includes revision: issue a fresh plan after restoring policy.
    fresh=offer(setup)
    assert simulated_host_apply(setup,fresh)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    assert simulated_host_apply(setup,fresh)['reason_code']=='FAST_FIX_AUTHORIZATION_EXPIRED_OR_CONSUMED'


def test_recurrence_old_plan_old_grant_cannot_apply(setup):
    first=offer(setup); assert close(setup,first)['remediation']['next_action']=='RETURN_TO_HOST'
    new=recur(setup)['remediation']
    second=new['fast_fix_plan']
    assert second['episode_id']!=first['episode_id']
    assert second['remediation_ref']!=first['remediation_ref']
    assert second['plan_ref']!=first['plan_ref']
    assert new['episode_number']==2
    assert simulated_host_apply(setup,first)['status']!='FAST_FIX_APPLY_AUTHORIZED'
    assert close(setup,second)['remediation']['security_verification']['phase']=='CLOSED'


def test_reconnect_loses_plan_and_attestation_not_budget(setup):
    from security_runtime.remediation import RemediationService
    plan=offer(setup); service=setup[3]
    restarted=RemediationService(service.store,registry=service.registry,hooks=service.hooks,
                                 fast_fix_host_contract=HOST_CONTRACT)
    result=restarted.fast_fix.validate_and_claim(plan,setup[0])
    assert result['reason_code']=='FAST_FIX_AUTHORIZATION_UNKNOWN_OR_RECONNECTED'
    assert restarted.cycles.result(setup[0],plan['episode_id'])['remediation_cycle_wall_ms'] is None
    assert record(setup)['attempt_count']==1


@pytest.mark.parametrize('variant',['duplicate','multiline','comment','mixed'])
def test_ambiguous_or_broader_source_is_not_fast_eligible(tmp_path,variant):
    source=UNSAFE
    statement='connection.setHostnameVerifier((hostname, session) -> true);'
    if variant=='duplicate':source=source.replace(statement,statement+'\n  '+statement)
    elif variant=='multiline':source=source.replace('-> true','->\n true')
    elif variant=='comment':source=source.replace(statement,statement+' // keep this comment')
    else:source=source.replace(statement,statement+' connection.connect();')
    (tmp_path/'A.java').write_text(source)
    with pytest.raises(ValueError):removal(tmp_path,'A.java',b'k'*32,6)


def test_host_bridge_unavailable_and_unused_plan_agent_fallback(setup):
    plan=offer(setup)
    packet=prepare(setup)
    assert packet['status']=='READY_FOR_HOST_FIX'
    assert simulated_host_apply(setup,plan)['status']!='FAST_FIX_APPLY_AUTHORIZED'
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings=setup[2].findings=[]
    assert setup[4]()['remediation']['security_verification']['phase']=='CLOSED'


def test_false_host_edit_or_nonexact_patch_cannot_close(setup):
    plan=offer(setup)
    assert simulated_host_apply(setup,plan)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    setup[0].joinpath('A.java').write_text(FIXED+'// extra change not in plan\n')
    setup[1].findings=setup[2].findings=[]
    result=setup[4]()
    assert result['remediation']['verification']['reason_code']=='FAST_FIX_POST_EDIT_NOT_EXACT'
    assert record(setup)['phase']=='ESCALATED'


def test_scanner_failure_cannot_be_replaced_by_plan_or_host_report(setup):
    from security_runtime.models import RunStatus
    plan=offer(setup)
    assert simulated_host_apply(setup,plan)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    setup[1].findings=setup[2].findings=[]
    setup[2].status=RunStatus.FAILED
    # LocalProvider uses its fail flag rather than a forged status claim.
    original=setup[2].scan
    def failed(*args):
        found,run=original(*args);run.status=RunStatus.FAILED;return found,run
    setup[2].scan=failed
    result=setup[4]()
    assert result['remediation']['reason_code']=='VERIFICATION_INCONCLUSIVE'
    assert record(setup)['phase']!='CLOSED'


@pytest.mark.parametrize('missing',['rule','confirmation','file','checksum','engine'])
def test_fast_fix_still_requires_canonical_original_rule_proof(setup,missing):
    from types import SimpleNamespace
    from security_runtime.remediation_policy import RULE
    plan=offer(setup)
    assert simulated_host_apply(setup,plan)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    setup[1].findings=setup[2].findings=[]
    proof=SimpleNamespace(rules=[SimpleNamespace(rule_id=RULE,rule_version='0.1')],
        pack=SimpleNamespace(descriptor=SimpleNamespace(rule_pack_id='ai-security-core',version='0.1'),checksum='a'*64),
        confirmed_rules={RULE},scanned_files={'A.java'},errored_files=set(),unscoped_error=False)
    setup[2].engine_provider=SimpleNamespace(engine_id='semgrep')
    if missing=='rule':proof.rules=[]
    elif missing=='confirmation':proof.confirmed_rules.clear()
    elif missing=='file':proof.scanned_files.clear()
    elif missing=='checksum':proof.pack.checksum='b'*64
    else:setup[2].engine_provider.engine_id='other-engine'
    setup[2].plan_rules=lambda *args:proof
    output=setup[4]()
    assert output['remediation']['verification']['verification_status']=='INCONCLUSIVE'
    assert record(setup)['phase']=='ESCALATED'


@pytest.mark.parametrize('bad',[True,float('nan'),float('inf'),-1])
def test_fast_fix_invalid_clock_never_authorizes(setup,bad):
    plan=offer(setup)
    setup[3].fast_fix.clock=lambda:bad
    assert simulated_host_apply(setup,plan)['status']!='FAST_FIX_APPLY_AUTHORIZED'
    assert not setup[3].prepared


def test_explicit_verify_cannot_bypass_exact_remove_contract(setup):
    plan=offer(setup)
    assert simulated_host_apply(setup,plan)['status']=='FAST_FIX_APPLY_AUTHORIZED'
    setup[0].joinpath('A.java').write_text(FIXED+'// unrelated\n')
    values=args(setup)
    result=setup[3].verify(values['remediation_ref'],values['task_ref'],setup[0])
    assert result['reason_code']=='FAST_FIX_POST_EDIT_NOT_EXACT'
    assert not setup[2].calls
    assert record(setup)['phase']!='CLOSED'


@pytest.mark.parametrize('newline',['\n','\r\n'])
def test_utf8_and_newline_byte_offsets_preserve_unrelated_bytes(tmp_path,newline):
    raw=UNSAFE.replace('class A','// 中文说明\nclass A').replace('\n',newline).encode()
    (tmp_path/'A.java').write_bytes(raw)
    plan=removal(tmp_path,'A.java',b'k'*32,7)
    left,right=plan['byte_range']['start'],plan['byte_range']['end']
    assert raw[left:right].strip()==b'connection.setHostnameVerifier((hostname, session) -> true);'
    result=raw[:left]+raw[right:]
    assert b'\xe4\xb8\xad' in result and b'setConnectTimeout' in result
    assert sha(result)==plan['expected_result_sha256']


def test_fast_plan_and_timing_never_persist_source_or_bearers(setup):
    before=setup[3].state.path(setup[0],'codex','session').read_bytes()
    plan=offer(setup)
    assert before==setup[3].state.path(setup[0],'codex','session').read_bytes()
    assert plan['plan_ref'].encode() not in before and plan['remediation_ref'].encode() not in before
    assert CANARY not in json.dumps(plan)
