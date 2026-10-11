"""Read the machine-only handoff behind the required plain Hook notice."""
import json


INTERNAL_CONTROL_DELIMITER = '\n\n内部控制（仅供工具使用，不展示给用户）\n'
OPERATIONAL_FIELDS = (
    'task_ref', 'confirmation_ref', 'remediation_ref', 'grant_id',
    'authorization_kind', 'prepare', 'verify', 'interaction', 'confirmation',
    'confirmation_recovery', 'fix_handoff', 'agent_fix_ticket',
    'security_fix_context_ref', 'security_verification',
)


def internal_context(output):
    context = output['hookSpecificOutput']['additionalContext']
    notice, delimiter, serialized = context.partition(INTERNAL_CONTROL_DELIMITER)
    assert delimiter, 'Hook context must put the user notice before internal control'
    assert notice.startswith('用户提示\n')
    control = json.loads(serialized)
    assert isinstance(control, dict)
    return control


def assert_operational_context(output, decision):
    control = internal_context(output).get('remediation', {})
    for field in OPERATIONAL_FIELDS:
        if field in decision:
            assert control[field] == decision[field], field
    if 'security_fix_context' in control:
        assert control['security_fix_context'] == decision['security_fix_context']
    assert not {'feedback_required', 'user_feedback'} & control.keys()
    return control
