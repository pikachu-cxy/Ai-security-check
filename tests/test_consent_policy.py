"""A detector, legacy preference or old token cannot stand in for user consent."""
import copy
import pytest

from test_hook_runtime import repo
from test_remediation import setup
from security_runtime.fast_fix import HOST_CONTRACT
from security_runtime.fix_context import build

def test_ambiguous_continuation_is_not_repair_approval():
    from security_runtime.host_guidance import HOST_INSTRUCTIONS
    from security_runtime.review_skill import skill_files
    assert 'is analysis, not repair' in HOST_INSTRUCTIONS
    assert 'approval. Clarify whether to fix before editing' in HOST_INSTRUCTIONS
    assert 'For explicit fix intent 修复它/把它修掉/修第一项' in HOST_INSTRUCTIONS
    skill = skill_files()['SKILL.md'].decode('utf-8')
    assert "'处理这个问题' is not repair approval" in skill
    assert 'Silence is never approval' in skill

@pytest.mark.parametrize('setup', ['smart_auto', 'ask_before_fix'], indirect=True)
def test_unconfirmed_hook_cannot_issue_any_edit_handoff(setup):
    root, _, provider, service, _, hook = setup
    out = hook['remediation']
    before = (root/'A.java').read_bytes()
    assert out['action'] == 'CONFIRM_REQUIRED'
    assert out['confirmation']['approval_source'] == 'EXPLICIT_USER_REPLY_REQUIRED'
    assert not {'prepare', 'verify', 'fast_fix_plan', 'agent_fix_ticket'} & out.keys()
    path = service.state.path(root, 'codex', 'session')
    key = service.state.key(root)
    record = next(iter(service._read(path, key).values()))
    with pytest.raises(ValueError, match='EXPLICIT_USER_CONSENT_REQUIRED'):
        service._grant(path, record, service._snapshot(root))
    forged = copy.deepcopy(record)
    forged.update(authorization_kind='POLICY_AUTO', token_hash='0'*64)
    service.authorized['0'*64] = float('inf')
    assert not service._allowed(forged, key)
    fake = {'action':'AUTO_FIX', 'reason_code':'USER_APPROVED_REPAIR'}
    service.fast_fix.host_contract = HOST_CONTRACT
    service.fast_fix.offer(fake, root, forged, key)
    assert 'fast_fix_plan' not in fake and not service.fast_fix.items
    with pytest.raises(ValueError, match='SECURITY_FIX_CONTEXT_BINDING_MISMATCH'):
        build(service, root, forged, {})
    assert not service.agent_tickets.items and not service.prepared
    assert not provider.calls and (root/'A.java').read_bytes() == before

@pytest.mark.parametrize('setup', ['smart_auto', 'ask_before_fix'], indirect=True)
def test_declining_keeps_source_and_all_edit_capabilities_unissued(setup):
    root, _, provider, service, _, hook = setup
    pending = hook['remediation']; before = (root/'A.java').read_bytes()
    service.agent_tickets.enabled = True
    service.fast_fix.host_contract = HOST_CONTRACT
    denied = service.confirm(pending['confirmation_ref'], pending['task_ref'], root, approve=False)
    assert denied['status'] == 'DECLINED'
    assert not service.prepared and not service.authorized
    assert not service.fast_fix.items and not service.agent_tickets.items
    assert not provider.calls and (root/'A.java').read_bytes() == before
