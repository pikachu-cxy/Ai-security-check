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


def documented_posttool_effect(output):
    """Small specification oracle, not an implementation of the Host executor."""
    return {
        'nested_promise_rejected': output.get('decision') == 'block',
        'model_feedback': output.get('reason') if output.get('decision') == 'block'
                          else output.get('stopReason') if output.get('continue') is False else None,
    }


def test_auto_feedback_does_not_reject_completed_edit_and_retains_authority(setup):
    root, runtime, provider, service, _, result = setup
    data = result['remediation']; wire = codex_hook_output(result)
    assert data['action'] == 'AUTO_FIX' and data['interaction'] == AUTO_INTERACTION
    assert not {'decision', 'reason'} & wire.keys()
    assert wire['continue'] is False and wire['systemMessage']
    assert 'The preceding edit already executed successfully.' in wire['stopReason']
    assert 'Do not retry or repeat it.' in wire['stopReason']
    assert 'Runtime has authorized remediation, not the original insecure edit.' in wire['stopReason']
    assert 'Immediately call prepare_task_fix.' in wire['stopReason']
    assert wire['stopReason'].endswith(data['guidance'])
    assert len(wire['stopReason']) < 8000
    context = json.loads(wire['hookSpecificOutput']['additionalContext'])
    assert context['remediation'] == data
    assert data['prepare']['mcp_tool'] == 'prepare_task_fix'
    assert data['prepare']['arguments'] == data['verify']['arguments']
    assert data['grant_id'] and all(data['prepare']['arguments'].values())
    assert set(data['prepare']['arguments']) == {'task_ref', 'remediation_ref'}
    # Old output rejected the completed nested tool. New output delivers the
    # same original authority guidance without that rejection, per the docs.
    old = documented_posttool_effect({'decision': 'block', 'reason': data['guidance']})
    new = documented_posttool_effect(wire)
    assert old['nested_promise_rejected'] is True
    assert new['nested_promise_rejected'] is False
    assert new['model_feedback'] == wire['stopReason']
    assert 'prepare_task_fix' in new['model_feedback']
    assert (root / 'A.java').read_text() == UNSAFE
    assert not provider.calls and not service.prepared  # transport never fixes/executes
    assert CANARY not in json.dumps(result) and UNSAFE not in json.dumps(result)


@pytest.mark.parametrize('setup', ['ask_before_fix'], indirect=True)
def test_confirm_feedback_still_requires_human_reply(setup):
    result = setup[-1]; data = result['remediation']; wire = codex_hook_output(result)
    assert data['action'] == 'CONFIRM_REQUIRED' and data['interaction'] == CONFIRM_INTERACTION
    assert wire['continue'] is False and not {'decision', 'reason'} & wire.keys()
    assert QUESTION in wire['stopReason'] and 'WAIT' in wire['stopReason']
    assert not {'prepare', 'verify', 'remediation_ref'} & data.keys()
    assert documented_posttool_effect(wire)['nested_promise_rejected'] is False


def test_none_verified_repair_has_no_artificial_stopping_or_renewed_grant(setup):
    before = setup[-1]['remediation']['grant_id']
    assert prepare(setup)['status'] == 'READY_FOR_HOST_FIX'
    (setup[0] / 'A.java').write_text(FIXED)
    setup[1].findings = setup[2].findings = []
    result = setup[4]()
    assert result['remediation']['action'] == 'NONE'
    wire = codex_hook_output(result)
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
