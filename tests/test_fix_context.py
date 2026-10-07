"""Compact facts do not authorize edits or replace original scanner proof."""
import copy
import json
import os

import pytest

from test_hook_runtime import repo
from test_remediation import setup, args as original_args, UNSAFE, FIXED, CANARY
from test_remediation_episodes import record, recur
from security_runtime.fix_context import build, encoded, field_count, MAX_BYTES, VERSION
from security_runtime.hook_state import identity


def args(setup):
    return {**original_args(setup),
            'security_context_ref':setup[-1]['remediation']['security_fix_context_ref']}


def test_hook_context_is_small_bound_source_free_and_not_authority(setup):
    root,_,_,service,_,hook=setup
    grant=hook['remediation'];context=grant['security_fix_context'];state=record(setup)
    assert grant['fix_path']=='AGENT_FIX'
    assert grant['fast_fix']['fallback_reason']=='FAST_FIX_HOST_CAPABILITY_UNAVAILABLE'
    assert context['version']==VERSION
    assert context['binding']['workspace_id']==identity(os.path.normcase(str(root)))
    assert context['binding']['episode_id']==state['episode_id']
    assert context['binding']['grant_id']==state['token_hash']
    assert context['target']['file']=='A.java' and context['target']['line_start']==6
    assert context['target']['symbol'] is None
    assert context['what']['cwe']==['CWE-295']
    assert context['recommendation']['operation']=='REMOVE_TRUST_ALL_HOSTNAME_OVERRIDE'
    assert context['authorization']['context_is_not_credential']
    diagnostics=grant['security_context_diagnostics']
    assert diagnostics['security_context_size_bytes']==len(encoded(context))<=MAX_BYTES
    assert diagnostics['security_context_field_count']==field_count(context)
    assert diagnostics['target_count']==diagnostics['allowed_scope_count']==1
    assert diagnostics['host_file_read_count'] is diagnostics['host_search_count'] is diagnostics['host_token_count'] is None
    assert not service.prepared
    assert CANARY not in json.dumps(context) and UNSAFE not in json.dumps(context)
    assert 'connection' not in encoded(context).decode()  # No receiver/source snippet.
    assert args(setup)['security_context_ref']==grant['security_fix_context_ref']
    assert 'security_context_ref' not in grant['verify']['arguments']


def test_prepare_reuses_matching_context_without_repeating_facts(setup):
    data=args(setup);service=setup[3];root=setup[0]
    before=service.state.path(root,'codex','session').read_bytes()
    output=service.prepare(data['remediation_ref'],data['task_ref'],root,
                           security_context_ref=data['security_context_ref'])
    assert output['status']=='READY_FOR_HOST_FIX'
    assert output['security_context_status']=='REUSE_HOOK_CONTEXT'
    assert output['security_fix_context_ref']==data['security_context_ref']
    assert 'security_fix_context' not in output
    assert not {'root_cause','existing_reviews','regression_requirements','recommended_changes'} & output.keys()
    assert output['bounded_evidence'][0]['context'][0]['trust']=='UNTRUSTED_CODE'
    assert not {'source_text','code','content'} & output['bounded_evidence'][0]['context'][0].keys()
    assert UNSAFE not in json.dumps(output) and CANARY not in json.dumps(output)
    assert output['verification_plan']['arguments']['remediation_ref']==data['remediation_ref']
    assert record(setup)['token_hash'] in service.prepared
    assert before==service.state.path(root,'codex','session').read_bytes()


def test_legacy_prepare_without_hint_receives_inline_current_context(setup):
    data=args(setup)
    output=setup[3].prepare(data['remediation_ref'],data['task_ref'],setup[0])
    assert output['status']=='READY_FOR_HOST_FIX'
    assert output['security_context_status']=='INLINE'
    assert output['security_fix_context']==setup[-1]['remediation']['security_fix_context']


@pytest.mark.parametrize('bad',['old-context',{},True,'x'*10000])
def test_untrusted_hint_never_skips_preparation_or_attests(setup,bad):
    data=args(setup)
    output=setup[3].prepare(data['remediation_ref'],data['task_ref'],setup[0],security_context_ref=bad)
    assert output['reason_code']=='SECURITY_FIX_CONTEXT_REFRESH_REQUIRED'
    assert not setup[3].prepared and record(setup)['phase']=='OFFERED'
    assert not record(setup)['resolution']


@pytest.mark.parametrize('claim',['task','grant','target','family','scan','workspace','episode','snapshot'])
def test_context_builder_rejects_wrong_objects(setup,tmp_path,claim):
    root=setup[0];state=copy.deepcopy(record(setup));data=dict(args(setup))
    if claim=='task':data['task_ref']='wrong'
    elif claim=='grant':data['remediation_ref']='wrong'
    elif claim=='target':state['target']='Other.java'
    elif claim=='family':state['family_key']='wrong'
    elif claim=='scan':state['origin_scan_id']='wrong'
    elif claim=='episode':state['episode_id']='0'*64
    elif claim=='snapshot':state['last_snapshot_digest']='0'*64
    else:root=tmp_path/'other'
    with pytest.raises((ValueError,FileNotFoundError)):
        build(setup[3],root,state,data)


def test_stale_source_cannot_attest_with_old_context(setup):
    data=args(setup)
    setup[0].joinpath('A.java').write_text(UNSAFE+'// moved\n')
    output=setup[3].prepare(data['remediation_ref'],data['task_ref'],setup[0],security_context_ref=data['security_context_ref'])
    assert output['reason_code']=='REPAIR_GRANT_STALE'
    assert not setup[3].prepared


def test_review_annotation_is_not_scanner_or_grant_authority(setup,monkeypatch):
    service=setup[3];fix=service._fix();original=fix._resolve
    def changed(*args):
        result,scan,members=original(*args)
        result['task']['members'][0]['review_status']='VALID'
        return result,scan,members
    monkeypatch.setattr(fix,'_resolve',changed)
    monkeypatch.setattr(service,'_fix',lambda:fix)
    context,reference,_=build(service,setup[0],record(setup),args(setup))
    assert reference==setup[-1]['remediation']['security_fix_context_ref']
    assert context==setup[-1]['remediation']['security_fix_context']
    data=args(setup)
    output=service.prepare(data['remediation_ref'],data['task_ref'],setup[0])
    # This deliberately incomplete review lacks ai_review. Original TaskFix
    # preparation still rejects it; informational context must not bypass that.
    assert output.get('status')!='READY_FOR_HOST_FIX' and not service.prepared


def test_untrusted_scanner_and_source_text_are_not_context_fields(setup,monkeypatch):
    service=setup[3];fix=service._fix();original=fix._resolve
    def contaminated(*args):
        resolved,scan,members=original(*args)
        members[0].update(description=CANARY,evidence=CANARY,fix_advice=CANARY)
        members[0]['technical_details'].update(cwe=[CANARY],symbol=CANARY,dataflow=CANARY)
        return resolved,scan,members
    monkeypatch.setattr(fix,'_resolve',contaminated);monkeypatch.setattr(service,'_fix',lambda:fix)
    context,_,_=build(service,setup[0],record(setup),args(setup))
    assert CANARY not in encoded(context).decode()
    assert context['target']['symbol'] is None and context['why']['source_to_sink'] is None


def test_compact_fix_still_runs_original_scanner_and_no_deep(setup,monkeypatch):
    service=setup[3];data=args(setup)
    prepared=service.prepare(data['remediation_ref'],data['task_ref'],setup[0],security_context_ref=data['security_context_ref'])
    assert prepared['status']=='READY_FOR_HOST_FIX'
    monkeypatch.setattr(service,'functional_receipt',lambda *a:pytest.fail('No Deep verification'))
    setup[0].joinpath('A.java').write_text(FIXED)
    setup[1].findings=setup[2].findings=[]
    resolved=setup[4]()
    assert setup[2].calls and resolved['remediation']['security_verification']['status']=='SCANNER_VERIFIED_RESOLVED'
    assert record(setup)['phase']=='CLOSED'
    assert not resolved['execution']['target_build']


def test_recurrence_new_context_and_old_refs_do_not_authorize(setup):
    first=args(setup);service=setup[3];root=setup[0]
    service.prepare(first['remediation_ref'],first['task_ref'],root,security_context_ref=first['security_context_ref'])
    root.joinpath('A.java').write_text(FIXED);setup[1].findings=setup[2].findings=[]
    assert setup[4]()['remediation']['security_verification']['phase']=='CLOSED'
    second=recur(setup)['remediation'];data={**second['prepare']['arguments'],
        'security_context_ref':second['security_fix_context_ref']}
    assert data['security_context_ref']!=first['security_context_ref']
    assert second['security_fix_context']['binding']['episode_id']!=setup[-1]['remediation']['episode_id']
    assert service.prepare(first['remediation_ref'],first['task_ref'],root).get('status')!='READY_FOR_HOST_FIX'
    assert service.prepare(data['remediation_ref'],data['task_ref'],root,
        security_context_ref=first['security_context_ref'])['reason_code']=='SECURITY_FIX_CONTEXT_REFRESH_REQUIRED'
    assert service.prepare(data['remediation_ref'],data['task_ref'],root,
        security_context_ref=data['security_context_ref'])['status']=='READY_FOR_HOST_FIX'


def test_context_does_not_turn_failed_scanner_into_resolution(setup):
    from security_runtime.models import RunStatus
    data=args(setup);service=setup[3]
    assert service.prepare(data['remediation_ref'],data['task_ref'],setup[0],
        security_context_ref=data['security_context_ref'])['status']=='READY_FOR_HOST_FIX'
    setup[0].joinpath('A.java').write_text(FIXED);setup[1].findings=setup[2].findings=[]
    original=setup[2].scan
    def failed(*args):
        findings,run=original(*args);run.status=RunStatus.FAILED;return findings,run
    setup[2].scan=failed
    assert setup[4]()['remediation']['reason_code']=='VERIFICATION_INCONCLUSIVE'
    assert record(setup)['phase']!='CLOSED'
