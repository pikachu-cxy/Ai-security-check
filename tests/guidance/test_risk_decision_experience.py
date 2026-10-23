"""The actual native candidate pair exercises handling through public surfaces.

No project JavaScript, external scanner or model is executed. Assessments here
exercise storage of known bounded code evidence, not an AI accuracy benchmark.
"""
import copy
import uuid
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.findings import FindingNormalizer
from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.models import ScanContext, ScanMode, ScanResult, TargetProfile
from security_runtime.guidance.risk_decision_guidance import RISK_DECISION_GUIDANCE
from security_runtime.review_skill import skill_files
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.storage import SQLiteStore
from security_runtime.hook_state import HookStateStore
from security_runtime.tasks.security import TaskSecurityService
from test_finding_feedback_mcp import call, make_server


SOURCE = '''export function echoText(body) {
  const Function = (text) => () => text;
  return Function(body)();
}

export function executeText(body) {
  return globalThis.Function(body)();
}
'''


@pytest.fixture
def experience(tmp_path, monkeypatch):
    import security_runtime.finding_feedback as feedback
    monkeypatch.setattr(feedback, 'build_identity', lambda: {'build_id': 'stable-experience-build'})
    root = tmp_path/'project'
    root.mkdir()
    source = root/'fp_case.js'
    source.write_text(SOURCE, encoding='utf-8')
    store = SQLiteStore(tmp_path/'state/scans.db')

    def scan():
        adapter = NativeFunctionScanner()
        context = ScanContext(str(root), ScanMode.RELEASE, ('fp_case.js',))
        context = replace(context, rule_plan=adapter.plan_rules(None, context))
        findings, run = adapter.scan(context, FindingNormalizer(root))
        assert len(findings) == 2
        result = ScanResult(uuid.uuid4().hex, 'release',
            TargetProfile(str(root), languages=['JavaScript'], files=['fp_case.js']),
            'COMPLETED', findings, [run], '', 'REVIEW', 1)
        store.save(result)
        return result

    return root, store, scan


def assess(server, scan_id, finding, verdict, claim):
    packet = call(server, 'prepare_finding_feedback', scan_id=scan_id, finding_id=finding.id)
    return call(server, 'submit_finding_feedback', scan_id=scan_id, finding_id=finding.id,
        feedback_session=packet['feedback_session'], context_hash=packet['packet']['context_hash'],
        verdict=verdict, reason=claim, context_complete=True, confidence='HIGH', unknowns=[],
        evidence_refs=[dict(file='fp_case.js', start_line=max(1,finding.line_start-2),
                            end_line=finding.line_end+1, claim=claim)])


def test_actual_candidate_pair_human_choice_survives_ai_disagreement_and_rescan(experience, tmp_path):
    root, store, scan = experience
    first = scan()
    before = copy.deepcopy(store.get_scan(first.scan_id))
    server, _ = make_server(store, tmp_path)
    risky = first.findings[1]
    assessed = assess(server, first.scan_id, risky, 'STILL_RISK',
        'The exported function calls the native constructor with its body argument and invokes the result.')
    assert assessed['state'] == 'STILL_RISK'
    excluded = call(server, 'set_finding_disposition', scan_id=first.scan_id,
        finding_id=risky.id, disposition='EXCLUDE', user_requested=True)
    assert excluded['reminder_suppressed']
    assert excluded['agent_review']['verdict'] == 'STILL_RISK'
    assert not excluded['technical_false_positive']
    assert not excluded['repair_authorized']
    assert store.get_scan(first.scan_id) == before
    assert (root/'fp_case.js').read_text(encoding='utf-8') == SOURCE

    # Recreate both services and a scan: the user decision is not in memory.
    second = scan()
    restarted = FindingFeedbackService(SQLiteStore(store.path), root)
    states = restarted.presentations(second.scan_id)
    assert sum(state['reminder_suppressed'] for state in states.values()) == 1
    assert states[second.findings[1].id]['agent_review']['verdict'] == 'STILL_RISK'
    summary = SecuritySummaryService(store).get(root, second.scan_id, details=True)
    assert summary['risk_handling']['pending_finding_count'] == 1
    assert summary['risk_handling']['excluded_by_user'] == 1
    assert summary['false_positive_feedback']['technical_false_positive_count'] == 0
    assert sum(task['active_finding_count'] for task in summary['tasks']) == 1


def test_native_pair_review_then_only_material_change_reopens(experience, tmp_path):
    root, store, scan = experience
    first = scan()
    server, _ = make_server(store, tmp_path)
    safe = first.findings[0]
    reviewed = assess(server, first.scan_id, safe, 'FALSE_POSITIVE',
        'The local const Function only returns a closure which returns its captured text; no code is compiled.')
    assert reviewed['technical_false_positive'] and reviewed['reminder_suppressed']

    # A comment moves both scanner IDs; the equivalent occurrence keeps its decision.
    path = root/'fp_case.js'
    path.write_text('// a harmless comment\n'+SOURCE, encoding='utf-8')
    moved = scan()
    state = FindingFeedbackService(store, root).status(moved.scan_id, moved.findings[0].id)
    assert state['reminder_suppressed'] and state['technical_false_positive']
    assert not FindingFeedbackService(store, root).status(moved.scan_id, moved.findings[1].id)['reminder_suppressed']

    # The local binding now compiles and invokes body: the original counterevidence is gone.
    path.write_text(('// a harmless comment\n'+SOURCE).replace(
        'const Function = (text) => () => text;', 'const Function = globalThis.Function;'), encoding='utf-8')
    changed = scan()
    current_server, _ = make_server(store, tmp_path)
    current = assess(current_server, changed.scan_id, changed.findings[0], 'STILL_RISK',
        'The local binding has changed to the native constructor; body is now compiled and the result invoked.')
    assert not current['reminder_suppressed']
    assert all(not value['reminder_suppressed'] for value in
        FindingFeedbackService(store, root).presentations(changed.scan_id).values())


def test_installation_delivers_same_decision_policy_as_runtime():
    from security_runtime.guidance.host_guidance import RUNTIME_WORKFLOW, REQUIRED_GUIDANCE_TOOLS
    assert RISK_DECISION_GUIDANCE not in RUNTIME_WORKFLOW
    assert 'topic=risk-decisions' in RUNTIME_WORKFLOW
    assert RISK_DECISION_GUIDANCE in skill_files()['references/risk-decisions.md'].decode('utf-8')
    assert {'set_finding_disposition','set_task_risk_disposition'} <= REQUIRED_GUIDANCE_TOOLS


def test_callable_runtime_projects_saved_scanner_handling_immediately(experience, tmp_path):
    root, store, scan = experience
    result = scan()
    feedback = FindingFeedbackService(store, root)
    for finding in result.findings:
        feedback.set_disposition(result.scan_id, finding.id, 'EXCLUDE', user_requested=True)
    tasks = TaskSecurityService(lambda: SimpleNamespace(store=store), HookStateStore(tmp_path/'hooks'))
    ref = tasks.begin(root, 'scanner-handling')['task_ref']
    record = tasks.load(root, ref)
    record.update(phase='INCOMPLETE', skip_reason='Fixture omits host assessment.',
                  static=dict(scan_id=result.scan_id, findings=[asdict(f) for f in result.findings]))
    view = tasks._view(record)
    assert view['risk_handling']['excluded_by_user'] == 2
    assert view['risk_handling']['pending_finding_count'] == 0
    assert '回复' not in view['development_summary']
    assert len(view['static']['findings']) == 2


def test_begin_does_not_initialize_lazy_scanner_just_to_read_handling(experience, tmp_path):
    root, _, _ = experience
    def factory():
        pytest.fail('A task without a scan must not initialize the scanner runtime')
    tasks = TaskSecurityService(factory, HookStateStore(tmp_path/'hooks'))
    result = tasks.begin(root, 'no-scan-handling')
    assert result['status'] == 'ACTIVE' and not result['scanner_run']


def test_unreadable_handling_counts_are_unknown_and_do_not_repeat_decisions(experience, tmp_path, monkeypatch):
    root, store, scan = experience
    result = scan()
    tasks = TaskSecurityService(lambda: SimpleNamespace(store=store), HookStateStore(tmp_path/'hooks'))
    ref = tasks.begin(root, 'unavailable-handling')['task_ref']
    record = tasks.load(root, ref)
    record.update(phase='INCOMPLETE', skip_reason='Fixture omits host assessment.',
                  static=dict(scan_id=result.scan_id, findings=[asdict(f) for f in result.findings]))
    def unavailable(_):
        raise OSError('Disposition storage unavailable')
    monkeypatch.setattr(tasks, '_current_handling', unavailable)
    view = tasks._view(record)
    assert view['handling_unavailable']
    assert not view['risk_handling']['counts_available']
    assert view['risk_handling']['pending_finding_count'] is None
    assert view['risk_handling']['pending'] is None
    assert view['risk_handling']['unknown_finding_count'] == 2
    assert '无法读取' in view['development_summary'] and '回复' not in view['development_summary']


@pytest.mark.parametrize('action', ['DEFER', 'EXCLUDE'])
def test_inactive_user_choices_do_not_override_current_ai_count(action):
    from security_runtime.guidance.risk_decision_guidance import handling_counts
    counts = handling_counts({'finding': dict(handling_status='EXCLUDED', reminder_suppressed=True,
        disposition=dict(disposition=action, active=False, expired=True))})
    assert counts['excluded_by_agent'] == 1
    assert counts['deferred'] == counts['excluded_by_user'] == 0
