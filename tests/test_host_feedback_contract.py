"""The installed Skill and live instructions preserve the Hook reply contract."""
import pytest

from security_runtime.host_guidance import HOST_INSTRUCTIONS
from security_runtime.review_skill import skill_files


@pytest.fixture(params=['live', 'skill'])
def guidance(request):
    if request.param == 'live':
        text = HOST_INSTRUCTIONS
    else:
        text = skill_files()['SKILL.md'].decode('utf-8')
    return ' '.join(text.split())


def test_event_user_notice_is_required_without_diagnostic_substitution(guidance):
    assert '用户呈现规则（必须遵守）' in guidance
    assert 'MUST present the event-specific 用户提示' in guidance
    assert 'user_feedback.message' in guidance
    assert 'location/problem/conditional impact/recommendation' in guidance
    assert 'pending 修复/忽略 choice' in guidance
    assert 'Formatting and file links may be adapted' in guidance or (
        'formatting and file links may be adapted' in guidance)
    assert 'replace them with diagnostics' in guidance or (
        'replace them with internal diagnostics' in guidance)


def test_internal_control_and_diagnostics_are_not_an_ordinary_user_report(guidance):
    assert 'internal_control' in guidance and 'machine-only' in guidance
    for internal in ('ADVISE', 'EPISODE_ALREADY_EXISTS', 'INCONCLUSIVE'):
        assert internal in guidance
    assert 'grant identifiers' in guidance
    assert 'scanner/tool names and tool-call' in guidance
    assert 'explicit user request for' in guidance or 'explicit request for' in guidance
    assert 'technical diagnostics' in guidance


def test_observation_only_is_not_an_implicit_ignore(guidance):
    assert '先不要修复/保留改动/观察 Hook prohibits immediate repair' in guidance
    assert 'NOT an implicit' in guidance
    assert '忽略 choice or permission to omit' in guidance
    assert "decline on the user's behalf" in guidance
    assert 'postpone repair or observe Hook is not that refusal' in guidance


def test_prompting_does_not_undo_edits_or_replace_consent(guidance):
    assert 'continue=false/stopReason presentation signal' in guidance
    assert 'reject or undo' in guidance
    assert 'grant' in guidance or 'authorization' in guidance
    assert ('If repair is already approved for that scope, continue without asking again' in guidance or
            'If repair approval already exists for that exact scope, continue without this question' in guidance)
    assert 'never recover them' in guidance or 'retain original refs inside' in guidance
