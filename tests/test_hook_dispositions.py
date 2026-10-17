"""Real persisted choices remain effective through Hook and reminder adapters."""
import copy
from types import SimpleNamespace

import pytest

from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.hook_user_feedback import scan_status_message
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.remediation import RemediationService
from security_runtime.risk_disposition import DispositionUnavailable, RiskDispositionStore
from security_runtime.storage import SQLiteStore
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.verification_policy import scanner_process_observed
from test_hook_runtime import repo  # noqa: F401


class SavedHookRuntime:
    """Deterministic scanner fixture; persistence and consumers are production."""
    def __init__(self, store):
        self.store, self.findings, self.calls = store, [], []

    def scan(self, root, mode, **kwargs):
        self.calls.append(tuple(kwargs['_hook_scope']))
        scanner_process_observed()
        for finding in self.findings:
            finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, finding.file_path)
        code = ScannerRun('semgrep', '1.0', 'SUCCESS', 1, provider='semgrep',
                          capabilities=['CODE_SAST'])
        runs = [code]
        if any(finding.category == 'dependency' for finding in self.findings):
            runs.append(ScannerRun('osv-scanner', '1.0', 'SUCCESS', 1,
                provider='osv-scanner', capabilities=['DEPENDENCY_VULN'],
                dependency_inventory=dict(vulnerability_db_freshness='FRESH')))
        rules = {finding.technical_details['rule_id'] for finding in self.findings
                 if finding.category != 'dependency'} | {'fixture.rule'}
        plan = SimpleNamespace(rules=[SimpleNamespace(rule_id=rule, rule_version='1') for rule in rules],
            pack=SimpleNamespace(checksum='a'*64), confirmed_rules=rules,
            scanned_files=set(kwargs['_hook_scope']), errored_files=set(), unscoped_error=False)
        kwargs['_hook_observer'](self.findings, runs, {'semgrep': plan})
        scan = ScanResult('hook-scan-'+str(len(self.calls)), mode,
            TargetProfile(str(root), files=list(kwargs['_hook_scope'])), 'COMPLETED',
            list(self.findings), runs, 'advisory', 'REVIEW', 1,
            capability_results=dict(CODE_SAST='EXECUTED', DEPENDENCY_VULN='EXECUTED'),
            execution_state='EXECUTED')
        self.store.save(scan)
        return scan


def environment(root, tmp_path):
    (root/'app.py').write_text('def query(db, value):\n    db.execute(value)\n')
    (root/'requirements.txt').write_text('fixture-package==1.0\nother-package==2.0\n')
    store = SQLiteStore(tmp_path/'db'/'scans.db')
    runtime = SavedHookRuntime(store)
    hooks = HookStateStore(tmp_path/'hooks')
    core = HookCoordinator(runtime, hooks, cooldown_ms=0)
    core.handle('SESSION_START', root, 'codex', 'session')
    return store, runtime, core, RemediationService(store, hooks=hooks)


def candidate(root, *, dependency=False, other=False):
    if dependency:
        finding = FindingNormalizer(root).dependency(scanner='osv-scanner',
            package='other-package' if other else 'fixture-package',
            version='2.0' if other else '1.0', ecosystem='pypi', manifest='requirements.txt',
            vulnerability_id='CVE-2099-0002' if other else 'CVE-2099-0001')
    else:
        finding = FindingNormalizer(root).make(scanner='semgrep', category='sql-injection',
            title='Synthetic risk', description='Requires review', severity='HIGH', confidence='MEDIUM',
            file_path='app.py', line=2, rule_id='fixture.rule')
        finding.technical_details.update(engine='semgrep', rule_version='1')
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, finding.file_path)
    return finding


def next_scan(root, runtime, core, findings, *, fresh_family=False):
    if fresh_family:
        runtime.findings = []
        core.handle('SESSION_START', root, 'codex', 'new-session')
    runtime.findings = findings
    path = root/('requirements.txt' if any(f.category == 'dependency' for f in findings) else 'app.py')
    path.write_text(path.read_text()+'\n# harmless movement\n')
    return core.handle('FILE_CHANGED', root, 'codex', 'new-session' if fresh_family else 'session')


@pytest.mark.parametrize('disposition', ['EXCLUDE', 'DEFER'])
def test_code_choice_filters_hook_advice_without_altering_raw_delta(repo, tmp_path, disposition):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo)
    first = next_scan(repo, runtime, core, [finding])
    FindingFeedbackService(store, repo).set_disposition(first['scan_id'], finding.id,
        disposition, user_requested=True)
    current = next_scan(repo, runtime, core, [finding], fresh_family=True)
    assert current['delta']['new'] == 1
    assert current['finding_feedback_projection']['folded_finding_ids'] == [finding.id]
    original = copy.deepcopy(current['delta'])
    output = remediation.on_hook(current, repo, 'new-session', host='codex')
    assert output['action'] == 'NONE' and not output.get('user_feedback')
    assert current['delta'] == original
    assert len(store.get_scan(current['scan_id'])['findings']) == 1
    assert '已修复' not in scan_status_message(current)


@pytest.mark.parametrize('disposition', ['EXCLUDE', 'DEFER'])
def test_dependency_choice_filters_current_candidates_and_downstream_advice(repo, tmp_path, disposition):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo, dependency=True)
    first = next_scan(repo, runtime, core, [finding])
    FindingFeedbackService(store, repo).set_disposition(first['scan_id'], finding.id,
        disposition, user_requested=True)
    current = next_scan(repo, runtime, core, [finding])
    assert current['current_dependency_finding_ids'] == [finding.id]
    assert current['active_dependency_finding_ids'] == []
    assert 'dependency_user_feedback' not in current
    output = remediation.on_hook(current, repo, 'session', host='codex')
    assert output['action'] == 'NONE' and not output.get('user_feedback')
    assert len(store.get_scan(current['scan_id'])['findings']) == 1


def test_excluded_dependency_does_not_hide_another_pending_dependency(repo, tmp_path):
    store, runtime, core, remediation = environment(repo, tmp_path)
    one, other = candidate(repo, dependency=True), candidate(repo, dependency=True, other=True)
    first = next_scan(repo, runtime, core, [one, other])
    FindingFeedbackService(store, repo).set_disposition(first['scan_id'], one.id,
        'EXCLUDE', user_requested=True)
    current = next_scan(repo, runtime, core, [one, other])
    assert set(current['current_dependency_finding_ids']) == {one.id, other.id}
    assert current['active_dependency_finding_ids'] == [other.id]
    feedback = current['dependency_user_feedback']
    assert feedback['finding_count'] == 1 and feedback['choices'] == ['修复', '稍后处理']
    assert feedback['secondary_choices'] == ['请复核', '不再提醒此项']
    output = remediation.on_hook(current, repo, 'session', host='codex')
    assert 'other-package' in output['user_feedback']['message']
    assert 'fixture-package' not in output['user_feedback']['message']


@pytest.mark.parametrize('dependency', [False, True])
def test_unreadable_decisions_keep_findings_without_repeated_choices(repo, tmp_path, monkeypatch, dependency):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo, dependency=dependency)
    first = next_scan(repo, runtime, core, [finding])
    feedback = FindingFeedbackService(store, repo)
    feedback.set_disposition(first['scan_id'], finding.id, 'EXCLUDE', user_requested=True)
    feedback.set_disposition(first['scan_id'], finding.id, 'RESTORE', user_requested=True)
    def unreadable(*args, **kwargs):
        raise DispositionUnavailable('Test-only storage unavailability')
    monkeypatch.setattr(RiskDispositionStore, '_read', unreadable)
    current = next_scan(repo, runtime, core, [finding], fresh_family=not dependency)
    assert current['handling_unavailable'] and not current['handling_user_feedback']['choices']
    assert current['active_dependency_finding_ids'] == []
    assert 'dependency_user_feedback' not in current
    original_delta = copy.deepcopy(current['delta'])
    output = remediation.on_hook(current, repo, 'new-session' if not dependency else 'session', host='codex')
    assert output['handling_unavailable'] and not output['user_feedback']['choices']
    assert not output['user_feedback'].get('selection_required')
    assert '原告警和处理记录保留' in output['user_feedback']['message']
    assert '请选择' not in output['user_feedback']['message']
    assert '已修复' not in output['user_feedback']['message']
    assert current['delta'] == original_delta
    assert len(store.get_scan(current['scan_id'])['findings']) == 1


def test_downstream_read_failure_does_not_fall_back_to_old_risk_choices(repo, tmp_path, monkeypatch):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo)
    current = next_scan(repo, runtime, core, [finding])
    def unreadable(*args, **kwargs):
        raise DispositionUnavailable('Test-only downstream unavailability')
    monkeypatch.setattr(RiskDispositionStore, '_read', unreadable)
    original = copy.deepcopy(current)
    output = remediation.on_hook(current, repo, 'session', host='codex')
    assert output['handling_unavailable'] and not output['user_feedback']['choices']
    direct = remediation._advisory_feedback(dict(action='ADVISE'), current, repo)
    assert direct['handling_unavailable'] and not direct['choices']
    assert current == original


def test_multiple_pending_dependencies_use_new_product_choices(repo, tmp_path):
    _, runtime, core, remediation = environment(repo, tmp_path)
    findings = [candidate(repo, dependency=True), candidate(repo, dependency=True, other=True)]
    current = next_scan(repo, runtime, core, findings)
    feedback = current['dependency_user_feedback']
    assert feedback['selection_required'] and feedback['choices'] == []
    assert '稍后处理' in feedback['message'] and '不再提醒此项' not in feedback['message']
    assert all('不再提醒此项' in item['secondary_choices'] for item in feedback['items'])
    assert '误报意见会进一步复核' not in feedback['message']
    output = remediation.on_hook(current, repo, 'session', host='codex')
    assert output['user_feedback']['selection_required']
    assert '稍后处理' in output['user_feedback']['message']


@pytest.mark.parametrize('disposition', ['EXCLUDE', 'DEFER'])
def test_historical_fallback_never_reintroduces_user_handled_finding(repo, tmp_path, disposition):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo)
    first = next_scan(repo, runtime, core, [finding])
    task = SecuritySummaryService(store).get(repo, first['scan_id'], details=True)['tasks'][0]
    FindingFeedbackService(store, repo).set_disposition(first['scan_id'], finding.id,
        disposition, user_requested=True)
    output = dict(action='ESCALATE', finding_family=finding.equivalence_key,
        verification=dict(verification_status='INCONCLUSIVE'), task_ref=task['task_ref'])
    # A current match removed by handling must never enter historical fallback.
    assert remediation._advisory_feedback(output, first, repo) is None
    # The same rule also applies when no current occurrence was observed.
    runtime.findings = []
    (repo/'app.py').write_text((repo/'app.py').read_text()+'\n# unchanged rule scope\n')
    current = core.handle('FILE_CHANGED', repo, 'codex', 'session')
    assert remediation._advisory_feedback(output, current, repo) is None
    assert store.get_scan(first['scan_id'])['findings'][0]['id'] == finding.id


def test_pending_historical_fallback_retains_original_facts_after_empty_rescan(repo, tmp_path):
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo)
    first = next_scan(repo, runtime, core, [finding])
    task = SecuritySummaryService(store).get(repo, first['scan_id'], details=True)['tasks'][0]
    runtime.findings = []
    (repo/'app.py').write_text((repo/'app.py').read_text()+'\n# original-rule check unconfirmed\n')
    current = core.handle('FILE_CHANGED', repo, 'codex', 'session')
    output = dict(action='ESCALATE', finding_family=finding.equivalence_key,
        verification=dict(verification_status='INCONCLUSIVE'), task_ref=task['task_ref'])
    feedback = remediation._advisory_feedback(output, current, repo)
    assert feedback['location'] == {'file': 'app.py', 'line': 2}
    assert feedback['title'].startswith('待复查的原安全问题')
    assert '原问题位置' in feedback['message'] and 'app.py' in feedback['message']
    assert '重新检查未能确认结果' in feedback['message']
    assert '建议修复' in feedback['message'] and feedback['impact'] in feedback['message']
    assert '发现安全风险' not in feedback['message']
    assert feedback['choices'] == ['修复', '稍后处理']


def test_codex_full_coverage_retains_non_choice_handling_notice(repo, tmp_path, monkeypatch):
    from security_runtime.codex_mcp_hook import handle_codex_hook, codex_hook_output
    from security_runtime.integration_state import WorkspaceBinding
    from security_runtime.risk_decision_guidance import HANDLING_UNAVAILABLE_MESSAGE
    store, runtime, core, remediation = environment(repo, tmp_path)
    finding = candidate(repo)
    first = next_scan(repo, runtime, core, [finding])
    FindingFeedbackService(store, repo).set_disposition(first['scan_id'], finding.id,
        'RESTORE', user_requested=True)
    def unreadable(*args, **kwargs):
        raise DispositionUnavailable('Test-only storage unavailability')
    monkeypatch.setattr(RiskDispositionStore, '_read', unreadable)
    (repo/'app.py').write_text((repo/'app.py').read_text()+'\n# next mutation\n')
    result = handle_codex_hook('PostToolUse', str(repo), 'session', 'apply_patch',
        binding=WorkspaceBinding.create(repo, 'generic-mcp'), coordinator=core, remediation=remediation)
    wire = codex_hook_output(result)
    assert result['coverage'] == 'FULL'
    assert wire['systemMessage'] == HANDLING_UNAVAILABLE_MESSAGE
    assert 'stopReason' not in wire and wire.get('continue') is not False


def test_no_current_findings_do_not_create_a_handling_read_failure_notice(repo, tmp_path, monkeypatch):
    _, runtime, core, remediation = environment(repo, tmp_path)
    def should_not_read(*args, **kwargs):
        pytest.fail('No reminder decision is needed without current findings or historical fallback')
    monkeypatch.setattr(RiskDispositionStore, '_read', should_not_read)
    (repo/'app.py').write_text((repo/'app.py').read_text()+'\n# benign edit\n')
    current = core.handle('FILE_CHANGED', repo, 'codex', 'session')
    assert current['status'] == 'SCANNED'
    assert not current.get('handling_unavailable')
    assert not current.get('handling_user_feedback')
    output = remediation.on_hook(current, repo, 'session', host='codex')
    assert output['action'] == 'NONE' and not output.get('user_feedback')
