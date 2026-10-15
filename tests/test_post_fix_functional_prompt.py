"""Personal repair completion hides optional testing and preserves security proof."""
import copy
import json

import pytest

from security_runtime.functional_feedback import pending_feedback
from security_runtime.functional_verification import FunctionalVerificationService, result
from security_runtime.hook_reply_context import CONTROL_DELIMITER, render_hook_context
from security_runtime.remediation import RemediationService
from test_remediation import setup, prepare, args, FIXED
from test_hook_runtime import repo
from test_remediation_episodes import record
from test_functional_host import report


def complete(values, *, explicit=False):
    root, runtime, provider, service, hook, _ = values
    prepare(values)
    root.joinpath('A.java').write_text(FIXED)
    runtime.findings = provider.findings = []
    if explicit:
        return service.verify(**dict(ref=args(values)['remediation_ref'],
            task_ref=args(values)['task_ref'], root=root))
    return hook()


@pytest.mark.parametrize('explicit', [False, True])
def test_security_resolution_hides_verifier_without_discovery_or_execution(setup, monkeypatch, explicit):
    def forbidden(*a, **kw):
        pytest.fail('Personal repair completion must not discover or execute tests')
    monkeypatch.setattr(FunctionalVerificationService, 'prepare', forbidden)
    monkeypatch.setattr(FunctionalVerificationService, 'run', forbidden)
    from security_runtime.functional_verifiers import FunctionalVerifierRegistry
    monkeypatch.setattr(FunctionalVerifierRegistry, 'detect', forbidden)
    output = complete(setup, explicit=explicit)
    data = output if explicit else output['remediation']
    assert not {'functional_verification_offer', 'functional_verification'} & data.keys()
    assert data['verification_summary'] == {'security': '原问题安全复查已通过。'}
    assert '执行功能验证' not in json.dumps(output, ensure_ascii=False)
    assert '核对验证条件' not in json.dumps(output, ensure_ascii=False)
    if not explicit:
        assert output.get('continue', True) is True
        assert '原规则的重新检查' in output['systemMessage']
        text = output['hookSpecificOutput']['additionalContext']
        assert '不暂停原开发任务' in text
        assert '修复／忽略' not in text.split(CONTROL_DELIMITER)[0]
    checked = setup[3].verify(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0])
    assert 'functional_verification_offer' not in checked
    assert 'user_feedback' not in checked
    assert not checked['runtime_observed_execution']['scanner_recheck']
    assert 'functional_notice_episode' not in record(setup)
    # A process restart cannot expose testing or resurrect execution consent.
    restarted = RemediationService(setup[3].store, registry=setup[3].registry,
        hooks=setup[3].hooks, config=setup[3].config)
    again = restarted.verify(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0])
    assert 'functional_verification_offer' not in again
    assert restarted.functional_receipt(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0]) is None


def test_still_present_has_no_functional_offer(setup):
    prepare(setup)
    out = setup[3].verify(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0])
    assert out['verification_status'] != 'SCANNER_VERIFIED_RESOLVED'
    assert 'functional_verification_offer' not in out


def test_legacy_offer_cannot_restore_personal_hook_prompt_or_interrupt(setup, monkeypatch):
    from security_runtime.codex_mcp_hook import codex_hook_output
    monkeypatch.setattr(setup[3], '_functional_offer', lambda *a, **kw: {
        'functional_verification_offer': {'notify': True},
        'user_feedback': {'message': '执行功能验证／稍后', 'choices': ['执行功能验证', '稍后']}})
    output = complete(setup)
    visible = codex_hook_output(output)
    assert output.get('continue', True) is True
    assert '原规则的重新检查' in output['systemMessage']
    assert '执行功能验证' not in json.dumps(visible, ensure_ascii=False)
    assert 'functional_verification_offer' not in output['hookSpecificOutput']['additionalContext']


@pytest.mark.parametrize('code,status', [(0, 'PASSED'), (1, 'FAILED')])
def test_user_selected_verification_reuses_existing_flow_and_separate_results(setup, monkeypatch, code, status):
    complete(setup)
    service = FunctionalVerificationService(setup[3])
    plan = service.prepare(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0], bound_workspace=setup[0])
    assert plan['status'] == 'FUNCTIONAL_VERIFICATION_READY'
    out = service.run(plan['functional_ref'], execution_result=report(plan, code), bound_workspace=setup[0])
    assert out['functional_verification']['status'] == status
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    checked = setup[3].verify(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0])
    merged = service.finalize(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0], checked)
    assert merged['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert merged['functional_verification']['status'] == status
    assert not merged.get('functional_verification_offer')
    assert not merged['user_feedback']['choices']
    assert '安全复查：' in merged['user_feedback']['message']
    assert '功能验证：' in merged['user_feedback']['message']
    if code == 0:
        assert '业务功能测试尚未验证' in merged['verification_summary']['functional']
    else:
        assert '不能确定是否由本次修复造成' in merged['verification_summary']['functional']
    # Matching cached preparation must not invoke a compiler/test command again.
    reused = service.prepare(args(setup)['remediation_ref'], args(setup)['task_ref'], setup[0], bound_workspace=setup[0])
    assert reused['functional_verification']['reused']


@pytest.mark.parametrize('status', ['NOT_AVAILABLE', 'PARTIAL', 'INCONCLUSIVE'])
def test_missing_partial_unknown_checks_never_look_passed(status):
    out = result(status)
    assert '通过' not in out['verification_summary']['functional'] or '不能视为通过' in out['verification_summary']['functional']
    assert out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert not out['user_feedback']['choices']


def test_legacy_offer_is_not_forwarded_through_personal_hook_context():
    arguments = {'task_ref': 'original-task', 'remediation_ref': 'exact-original-ref', 'workspace_path': 'original-root'}
    decision = dict(action='NONE', reason_code='SCANNER_VERIFIED_RESOLVED',
        functional_verification_offer={'notify': True, 'continuation': {
            'tool': 'prepare_functional_verification', 'arguments': arguments}},
        functional_verification={'status': 'NOT_RUN'},
        verification_summary={'security': '原问题安全复查已通过。', 'functional': '尚未执行'})
    original = copy.deepcopy(decision)
    text = render_hook_context({'status': 'SCANNED'}, decision, '原问题安全复查已通过。')
    notice, control = text.split(CONTROL_DELIMITER)
    control = json.loads(control)
    assert 'exact-original-ref' not in text
    assert 'functional_verification' not in text
    assert '执行功能验证' not in notice
    assert control['remediation']['verification_summary'] == {'security': '原问题安全复查已通过。'}
    assert decision == original


@pytest.mark.parametrize('notify', [False, True])
def test_pending_feedback_is_security_only_even_for_legacy_callers(notify):
    repeated = pending_feedback(arguments={'task_ref': 'old'}, notify=notify)
    assert repeated == {'verification_summary': {'security': '原问题安全复查已通过。'}}


def test_expired_context_explains_next_step_without_new_repair_or_execution():
    out = result('INCONCLUSIVE', reason='SECURITY_RECEIPT_REQUIRED_REFRESH')
    assert '需核对当前代码和执行条件' in out['user_feedback']['message']
    assert '不会重新修复' in out['user_feedback']['message']
    assert not out['user_feedback']['choices'] and 'handoff' not in out
