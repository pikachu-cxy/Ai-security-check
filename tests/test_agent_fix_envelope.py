"""Exact original byte variants, never formatter/whitespace tolerance."""
import copy
import json

import pytest

from security_runtime.agent_fix_envelope import build_envelope, verify_envelope, byte_modes
from security_runtime.fast_fix import removal, sha
from test_agent_fix_ticket import inline_setup, ticket
from test_hook_runtime import repo
from test_remediation import UNSAFE, CANARY
from test_remediation_episodes import record

STATEMENT = b'connection.setHostnameVerifier((hostname, session) -> true);'


def source(eol=b'\n', bom=False, *, blank=True):
    # Non-ASCII bytes before the statement catch character/byte offset mixing.
    raw = ('// 中文 canary '+CANARY+'\n'+UNSAFE).encode().replace(b'\n', eol)
    raw = raw.replace(STATEMENT + eol, STATEMENT + eol + (eol if blank else b''))
    return (b'\xef\xbb\xbf' if bom else b'') + raw


def plan(tmp_path, raw):
    target=tmp_path/'A.java';target.write_bytes(raw)
    edit=removal(tmp_path,'A.java',b'k'*32,7)
    return edit,build_envelope(raw,edit)


def check(raw, edit, envelope):
    return verify_envelope(raw,envelope,original_sha256=edit['expected_file_sha256'],
                           canonical_result_sha256=edit['expected_result_sha256'])


@pytest.mark.parametrize('eol', [b'\n',b'\r\n'])
@pytest.mark.parametrize('bom', [False,True])
@pytest.mark.parametrize('variant', ['line','statement','line_and_empty'])
def test_exact_raw_variants(tmp_path,eol,bom,variant):
    raw=source(eol,bom);edit,envelope=plan(tmp_path,raw)
    left,right=edit['byte_range']['start'],edit['byte_range']['end']
    if variant=='line': result=raw[:left]+raw[right:]
    elif variant=='statement': result=raw.replace(STATEMENT,b'',1)
    else: result=raw[:left]+raw[right+len(eol):]
    out=check(result,edit,envelope)
    assert out['status']=='MATCHED' and not out['outside_envelope_changed']
    assert out['accepted_variant']=={'line':'REMOVE_LINE','statement':'REMOVE_STATEMENT','line_and_empty':'REMOVE_LINE_AND_EMPTY_LINE'}[variant]
    assert result.startswith(b'\xef\xbb\xbf')==bom
    assert (tmp_path/'A.java').read_bytes()==raw  # Runtime only reads/plans.
    left2,right2=envelope['byte_range']['start'],envelope['byte_range']['end']
    assert result[:left2]==raw[:left2] and result.endswith(raw[right2:])
    assert sha(raw[left:right])==edit['expected_segment_sha256']
    assert raw[envelope['statement_byte_range']['start']:envelope['statement_byte_range']['end']]==STATEMENT
    assert CANARY not in json.dumps(envelope) and STATEMENT.decode() not in json.dumps(envelope)


def test_mixed_eols_are_preserved_not_normalized(tmp_path):
    raw=source(b'\r\n',True).replace(STATEMENT+b'\r\n\r\n',STATEMENT+b'\n\n')
    edit,envelope=plan(tmp_path,raw)
    left,right=edit['byte_range']['start'],edit['byte_range']['end']
    assert envelope['line_ending_mode']=='MIXED'
    result=raw[:left]+raw[right+1:]
    assert check(result,edit,envelope)['status']=='MATCHED'
    changed=result.replace(b'\r\n',b'\n')
    assert check(changed,edit,envelope)['subreason']=='LINE_ENDING_IDENTITY_MISMATCH'


@pytest.mark.parametrize('change', ['neighbor_code','neighbor_comment','format','second_line','previous_empty',
                                    'additional_empty','new_indent','new_trailing','range_drift','restore_with_other_edit',
                                    'bom_removed','invalid_utf8'])
def test_unauthorized_bytes_are_not_variants(tmp_path,change):
    raw=source(b'\r\n',True);edit,envelope=plan(tmp_path,raw)
    left,right=edit['byte_range']['start'],edit['byte_range']['end']
    result=raw[:left]+raw[right:]
    if change=='neighbor_code': result=result.replace(b'1000',b'2000')
    elif change=='neighbor_comment': result=result.replace(CANARY.encode(),b'changed')
    elif change=='format': result=result.replace(b'  ',b'    ')
    elif change=='second_line': result=result.replace(b'  connection.setConnectTimeout(1000);\r\n',b'')
    elif change=='previous_empty': result=result[:left-1]+result[left:]  # Prefix byte deletion.
    elif change=='additional_empty': result=result[:left]+b'\r\n'+result[left:]
    elif change=='new_indent': result=raw.replace(STATEMENT,b'\t',1)
    elif change=='new_trailing': result=raw.replace(STATEMENT,b' ',1)
    elif change=='range_drift': result=b''
    elif change=='restore_with_other_edit': result=raw.replace(CANARY.encode(),b'changed')
    elif change=='bom_removed': result=result[3:]
    else: result=result[:left]+b'\xff'+result[left:]
    out=check(result,edit,envelope)
    assert out['status']=='REJECTED' and out['subreason']


def test_no_following_empty_line_is_not_an_extra_scope(tmp_path):
    raw=source(blank=False);edit,envelope=plan(tmp_path,raw)
    assert envelope['following_empty_line_bytes']==0 and len(envelope['variants'])==2
    assert envelope['byte_range']==edit['byte_range']
    assert check(raw,edit,envelope)['subreason']=='TARGET_PREIMAGE_NOT_REMOVED'


@pytest.mark.parametrize('following',[b' \n',b'// neighboring comment\n',b'\n\n'])
def test_envelope_never_includes_indented_comment_or_second_blank(tmp_path,following):
    raw=source(blank=False).replace(STATEMENT+b'\n',STATEMENT+b'\n'+following)
    edit,envelope=plan(tmp_path,raw)
    extension=1 if following==b'\n\n' else 0
    assert envelope['byte_range']['end']==edit['byte_range']['end']+extension
    left,right=edit['byte_range']['start'],edit['byte_range']['end']
    result=raw[:left]+raw[right+len(following):]
    assert check(result,edit,envelope)['status']=='REJECTED'


@pytest.mark.parametrize('field',['expected_file_sha256','expected_segment_sha256','expected_result_sha256'])
def test_builder_cannot_mix_pre_post_images(tmp_path,field):
    raw=source();edit,_=plan(tmp_path,raw);edit[field]='0'*64
    with pytest.raises(ValueError,match='INLINE_PREPARATION_STALE'): build_envelope(raw,edit)


def test_result_hash_mismatch_is_a_rejection(tmp_path):
    raw=source();edit,envelope=plan(tmp_path,raw)
    left,right=edit['byte_range']['start'],edit['byte_range']['end'];result=raw[:left]+raw[right:]
    bad=copy.deepcopy(envelope);bad['variants'][0]['result_sha256']='0'*64
    assert check(result,edit,bad)['subreason']=='RESULT_HASH_MISMATCH'


@pytest.mark.parametrize('eol',[b'\n',b'\r\n'])
@pytest.mark.parametrize('bom',[False,True])
@pytest.mark.parametrize('variant',['statement','line_and_empty'])
def test_hook_closes_only_current_envelope_and_real_proof(inline_setup,eol,bom,variant):
    data=inline_setup
    # Close existing fixture then establish a new Episode with this raw encoding.
    from test_agent_fix_ticket import fix
    fix(data)
    original_finding=data[1].store.get_scan(ticket(data)['origin_scan_id'])['findings'][0]
    from security_runtime.models import Finding
    raw=UNSAFE.encode().replace(b'\n',eol).replace(STATEMENT+eol,STATEMENT+eol+eol)
    if bom: raw=b'\xef\xbb\xbf'+raw
    data[0].joinpath('A.java').write_bytes(raw)
    data[1].findings=data[2].findings=[Finding(**original_finding)]
    grant=data[4]()['remediation'];t=grant['agent_fix_ticket']
    env=t['edit_envelope'];left,right=env['byte_range']['start'],env['byte_range']['end']
    result=raw.replace(STATEMENT,b'',1) if variant=='statement' else raw[:left]+raw[right:]
    data[0].joinpath('A.java').write_bytes(result);data[1].findings=data[2].findings=[]
    out=data[4]();decision=out['remediation']
    assert decision['reason_code']=='SCANNER_VERIFIED_RESOLVED' and record(data)['phase']=='CLOSED'
    assert decision['security_verification']['task_ref']==t['task_ref']
    assert decision['security_verification']['grant_id']==t['grant_id']
    diag=decision['agent_fix_ticket_diagnostics']
    assert diag['prepare_task_fix_call_count']==0 and diag['exact_target_verification']['status']=='MATCHED'
    assert data[2].calls and out['remediation_cycle_wall_ms'] is not None
    assert decision['next_action']=='RETURN_TO_HOST' and result==data[0].joinpath('A.java').read_bytes()


@pytest.mark.parametrize('field',['byte_range','prefix_sha256','suffix_sha256','variants'])
def test_signed_envelope_tampering_cannot_close(inline_setup,field):
    from test_agent_fix_ticket import fix
    data=inline_setup;t=ticket(data);item=data[3].agent_tickets.items[t['grant_id']]
    item['ticket']['edit_envelope'][field]={} if field=='byte_range' else [] if field=='variants' else '0'*64
    out=fix(data)['remediation']
    assert out['agent_fix_ticket_diagnostics']['ticket_stale_reason']=='TICKET_BINDING_CHANGED'
    assert record(data)['resolution'] is None


def test_production_diagnostics_are_source_free_and_neighbor_edit_rejected(inline_setup):
    from test_agent_fix_ticket import fix
    data=inline_setup;out=fix(data,suffix='// '+CANARY+'\n')['remediation']
    diag=out['agent_fix_ticket_diagnostics']['exact_target_verification']
    assert diag['outside_envelope_changed'] and diag['subreason']=='OUTSIDE_EDIT_ENVELOPE_CHANGED'
    assert CANARY not in json.dumps(diag) and 'diff' not in diag
    assert record(data)['resolution'] is None


@pytest.mark.parametrize('status',['FAILED','UNAVAILABLE'])
def test_statement_variant_cannot_replace_scanner_proof(inline_setup,status):
    data=inline_setup;target=data[0]/'A.java'
    target.write_bytes(target.read_bytes().replace(STATEMENT,b'',1))
    data[1].findings=data[2].findings=[];data[2].status=status
    out=data[4]()['remediation']
    assert out['agent_fix_ticket_diagnostics']['exact_target_verification']['status']=='MATCHED'
    assert out['verification']['verification_status']=='INCONCLUSIVE'
    assert record(data)['resolution'] is None and record(data)['phase']=='ESCALATED'
