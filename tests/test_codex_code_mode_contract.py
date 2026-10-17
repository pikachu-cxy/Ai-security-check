"""Documented event contract simulation; not Codex internals or Desktop proof.

Reference: https://learn.chatgpt.com/docs/hooks#tool-calls-from-code-mode
The model-visible feedback and nested promise rejection are distinct effects.
"""
import json
from pathlib import Path

import pytest

from test_hook_runtime import repo
from test_remediation import setup, prepare, CANARY, UNSAFE, FIXED
from test_host_continuation import stop
from test_host_orchestration import AUTO_INTERACTION, CONFIRM_INTERACTION, QUESTION
from security_runtime.codex_mcp_hook import codex_hook_output
from security_runtime.codex_integration import product_hooks
from hook_feedback_test_helpers import assert_operational_context


def documented_posttool_effect(output):
    """Small specification oracle, not an implementation of the Host executor."""
    return {
        'nested_promise_rejected': output.get('decision') == 'block',
        'model_feedback': output.get('reason') if output.get('decision') == 'block'
                          else output.get('stopReason') if output.get('continue') is False else None,
    }


def test_auto_feedback_does_not_reject_completed_edit_and_retains_authority(setup, monkeypatch):
    root, runtime, provider, service, hook, approved = setup
    # The lifecycle fixture starts after approval and intentionally strips the
    # pending wire response. Project the already approved grant through a fresh
    # Hook response rather than treating that synthetic fixture as Host output.
    approved_decision = dict(approved['remediation'], feedback_required=True)
    monkeypatch.setattr(service, 'on_hook', lambda *args, **kwargs: approved_decision)
    result = hook()
    data = result['remediation']; wire = codex_hook_output(result)
    assert data['action'] == 'AUTO_FIX' and data['interaction'] == AUTO_INTERACTION
    assert not {'decision', 'reason'} & wire.keys()
    assert wire['continue'] is False and wire['systemMessage']
    assert '修复确认' in wire['stopReason'] and '重新检查' in wire['stopReason']
    assert wire['systemMessage'] == wire['stopReason']
    for internal in ('SECURITY_AUTO_REMEDIATION_AUTHORIZED', 'SECURITY_FIX_REQUIRED',
                     'AUTO_FIX', 'prepare_task_fix', 'remediation.prepare', 'security_fix_context'):
        assert internal not in wire['stopReason']
    assert data['security_context_status'] == 'READY'
    assert data['guidance'] not in wire['stopReason']  # Full instructions only once.
    assert len(wire['stopReason']) < 8000
    context = assert_operational_context(wire, data)
    assert context['grant_id'] == data['grant_id']
    assert data['prepare']['mcp_tool'] == 'prepare_task_fix'
    assert data['prepare']['arguments'] == data['verify']['arguments']
    assert data['grant_id'] and all(data['prepare']['arguments'].values())
    assert set(data['prepare']['arguments']) == {'task_ref', 'remediation_ref'}
    # Old output rejected the completed nested tool. New output delivers the
    # original authority without that rejection; structured context retains
    # the handoff while user feedback only explains the next step.
    old = documented_posttool_effect({'decision': 'block', 'reason': data['guidance']})
    new = documented_posttool_effect(wire)
    assert old['nested_promise_rejected'] is True
    assert new['nested_promise_rejected'] is False
    assert new['model_feedback'] == wire['stopReason']
    assert new['model_feedback'] == wire['systemMessage']
    assert (root / 'A.java').read_text() == UNSAFE
    assert not provider.calls and not service.prepared  # transport never fixes/executes
    assert CANARY not in json.dumps(result) and UNSAFE not in json.dumps(result)


@pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)
def test_confirm_feedback_still_requires_human_reply(setup):
    result = setup[-1]; data = result['remediation']; wire = codex_hook_output(result)
    assert data['action'] == 'CONFIRM_REQUIRED' and data['interaction'] == CONFIRM_INTERACTION
    assert wire['continue'] is False and not {'decision', 'reason'} & wire.keys()
    assert QUESTION in wire['stopReason'] and '回复“暂不处理”' in wire['stopReason']
    assert 'WAIT' in data['guidance'] and 'WAIT' not in wire['stopReason']
    assert wire['stopReason'] == data['user_feedback']['message']
    context = assert_operational_context(wire, data)
    assert not {'prepare', 'verify', 'remediation_ref', 'grant_id'} & context.keys()
    assert not {'prepare', 'verify', 'remediation_ref'} & data.keys()
    assert documented_posttool_effect(wire)['nested_promise_rejected'] is False


@pytest.mark.parametrize('setup', ['report_only'], indirect=True)
def test_advisory_choice_stops_for_feedback_without_rejecting_edit_or_granting_repair(setup):
    root, _, provider, service, _, result = setup
    decision = result['remediation']
    assert result['status'] == result['last_check_status'] == 'SCANNED'
    assert result['scanner_run'] is True
    assert decision['action'] == 'ADVISE' and decision['feedback_required'] is False
    wire = codex_hook_output(result)
    assert wire['continue'] is False and 'decision' not in wire and 'reason' not in wire
    assert wire['stopReason'] == wire['systemMessage'] == decision['user_feedback']['message']
    assert QUESTION in wire['stopReason'] and '回复“稍后处理”' in wire['stopReason']
    effect = documented_posttool_effect(wire)
    assert effect == {'nested_promise_rejected': False, 'model_feedback': wire['stopReason']}
    context = assert_operational_context(wire, decision)
    assert not {'prepare', 'verify', 'confirmation_ref', 'remediation_ref', 'grant_id'} & context.keys()
    assert not service.authorized and not service.prepared and not provider.calls
    assert (root / 'A.java').read_text() == UNSAFE


def test_none_verified_repair_has_no_artificial_stopping_or_renewed_grant(setup):
    before = setup[-1]['remediation']['grant_id']
    assert prepare(setup)['status'] == 'READY_FOR_HOST_FIX'
    (setup[0] / 'A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    result = setup[4]()
    assert result['remediation']['action'] == 'NONE'
    wire = codex_hook_output(result)
    context = assert_operational_context(wire, result['remediation'])
    assert context['security_verification'] == result['remediation']['security_verification']
    assert wire['systemMessage'] == '这个问题已修复，并通过了原规则的重新检查。'
    assert not {'decision', 'reason', 'continue', 'stopReason'} & wire.keys()
    assert documented_posttool_effect(wire) == {'nested_promise_rejected': False, 'model_feedback': None}
    rows = setup[3]._read(setup[3].state.path(setup[0], 'codex', 'session'), setup[3].state.key(setup[0]))
    assert len(rows) == 1 and next(iter(rows.values()))['token_hash'] == before


def test_stop_keeps_event_specific_block_and_original_handoff(setup):
    result = stop(setup); wire = codex_hook_output(result)
    assert set(wire) == {'decision', 'reason'}
    assert wire['decision'] == 'block' and wire['reason']
    assert 'continue' not in result
    assert json.loads(wire['reason'][wire['reason'].index('{'):]) == setup[-1]['remediation']['prepare']
    assert not any(result['execution'].values())


def test_hook_definition_abi_is_exact_frozen_document():
    golden = Path(__file__).resolve().parents[1] / 'docs/continuation-hooks-example.json'
    assert product_hooks() == json.loads(golden.read_bytes())
