"""Simulated scanner responses and Hook deltas; never real host Hook acceptance."""
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.hook_runtime import covered, family_delta, family_multiset
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessResult
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry
from security_runtime.toolchain import ResolvedTool, ToolStatus
from security_runtime.verification import VerificationService

RULES = ('generic-api-key', 'github-pat')


@pytest.fixture
def secret_engine(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    root.mkdir()
    path = root / 'fixture.ts'
    path.write_text('export const PUBLIC_FAKE_FIXTURE = "fixture-canary";\n', encoding='utf-8')
    binary = tmp_path / 'gitleaks.exe'
    binary.write_bytes(b'simulated-engine-8.30.0')
    adapter = GitleaksAdapter()
    monkeypatch.delenv('GITLEAKS_CONFIG', raising=False)
    monkeypatch.delenv('GITLEAKS_CONFIG_TOML', raising=False)
    monkeypatch.setattr(adapter.tool_manager, 'ensure', lambda *a, **k:
                        ResolvedTool('gitleaks', '8.30.0', str(binary), None, ToolStatus.READY))
    state = {'rules': RULES, 'skip': False, 'failed': False, 'missing_report': False,
             'mutate': False, 'bytes_delta': 0, 'calls': 0, 'report_version': '8.30.0'}

    def execute(argv, cwd, timeout):
        from security_runtime.verification_policy import scanner_process_observed
        scanner_process_observed()
        state['calls'] += 1
        target = Path(argv[2])
        files = [target] if target.is_file() else sorted(p for p in target.rglob('*') if p.is_file())
        items = []
        for file in files:
            if 'fixture-canary' in file.read_text(encoding='utf-8'):
                items.extend({'File': str(file), 'RuleID': rule, 'StartLine': 1,
                              'EndLine': 1, 'Description': 'Public fake fixture'} for rule in RULES)
        if argv[argv.index('--report-format') + 1] == 'sarif':
            payload = {'version': '2.1.0', 'runs': [{'tool': {'driver': {
                'name': 'gitleaks', 'semanticVersion': state['report_version'],
                'rules': [{'id': rule} for rule in state['rules']]}},
                'results': [{'ruleId': item['RuleID'], 'locations': [{'physicalLocation': {
                    'artifactLocation': {'uri': item['File']},
                    'region': {'startLine': 1, 'endLine': 1}}}]} for item in items]}]}
        else:
            payload = items
        if not state['missing_report']:
            Path(argv[argv.index('--report-path') + 1]).write_text(json.dumps(payload), encoding='utf-8')
        if state['mutate']:
            path.write_text('// changed during scan\n', encoding='utf-8')
        total = sum(file.stat().st_size for file in files) + state['bytes_delta']
        log = '\n'.join('TRC scanning path path=' + str(file) for file in files)
        log += f'\nINF scanned ~{total} bytes ({total} bytes) in 1ms\n'
        if state['skip']:
            log += 'TRC skipping file: rule allowlist\n'
        return ProcessResult(2 if state['failed'] else 0, '', log, 1)

    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    return root, path, adapter, state, binary


def original(secret_engine):
    root, _, adapter, _, _ = secret_engine
    findings, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, ('fixture.ts',)), FindingNormalizer(root))
    assert run.status == 'SUCCESS', (run.error_code, run.diagnostic_detail, run.error_summary)
    assert len(findings) == 2
    return findings, run


def recheck(secret_engine, findings, run):
    root, _, adapter, _, _ = secret_engine
    scan = {'target_profile': {'files': ['fixture.ts']}, 'scanner_runs': [asdict(run)]}
    return VerificationService(ScannerRegistry([adapter])).verify_many(root, [asdict(f) for f in findings], scan)


def test_removed_fixture_resolves_original_rules_and_automatic_delta(secret_engine):
    findings, old_run = original(secret_engine)
    root, path, adapter, state, _ = secret_engine
    path.write_text('// public fake fixture removed; explanation retained\n', encoding='utf-8')
    results = recheck(secret_engine, findings, old_run)
    assert len(results) == 2
    assert all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in results)
    assert state['calls'] == 2  # Recheck once for both original rule families.
    previous = family_multiset(findings, [old_run], {})
    current, run = adapter.scan(ScanContext(str(root), ScanMode.QUICK, ('fixture.ts',)), FindingNormalizer(root))
    retained, delta = family_delta(previous, family_multiset(current, [run], {}), lambda f: covered(f, [run], {}))
    assert delta['resolved'] == 2 and not retained


def test_moved_fixture_still_present(secret_engine):
    findings, run = original(secret_engine)
    secret_engine[1].write_text('\n\nexport const PUBLIC_FAKE_FIXTURE = "fixture-canary";\n', encoding='utf-8')
    assert all(r['verification_status'] == 'STILL_PRESENT' for r in recheck(secret_engine, findings, run))


@pytest.mark.parametrize('change', ['disabled_rule', 'skip', 'failed', 'missing_report',
                                  'mutate', 'wrong_bytes', 'changed_binary', 'custom_config', 'ignore_file',
                                  'binary_replacement', 'empty_replacement'])
def test_incomplete_or_changed_proof_never_closes(secret_engine, monkeypatch, change):
    findings, run = original(secret_engine)
    root, path, _, state, binary = secret_engine
    path.write_text('// cleared public fixture\n', encoding='utf-8')
    if change == 'disabled_rule':
        state['rules'] = ()
    elif change == 'wrong_bytes':
        state['bytes_delta'] = -1
    elif change == 'changed_binary':
        binary.write_bytes(b'changed-engine-same-version')
    elif change == 'custom_config':
        monkeypatch.setenv('GITLEAKS_CONFIG', str(root / 'custom.toml'))
    elif change == 'ignore_file':
        (root / '.gitleaksignore').write_text('fixture.ts:github-pat:1\n', encoding='utf-8')
    elif change == 'binary_replacement':
        path.write_bytes(b'\x00\x00binary replacement')
    elif change == 'empty_replacement':
        path.write_bytes(b'')
    else:
        state[change] = True
    results = recheck(secret_engine, findings, run)
    assert all(r['status'] == 'INCONCLUSIVE' for r in results)


def test_legacy_record_without_identity_remains_unconfirmed(secret_engine):
    findings, run = original(secret_engine)
    for finding in findings:
        for field in ('rule_pack', 'rule_pack_version', 'rule_pack_checksum', 'rule_version', 'engine'):
            finding.technical_details.pop(field, None)
    secret_engine[1].write_text('// cleared public fixture\n', encoding='utf-8')
    assert all(r['status'] == 'INCONCLUSIVE' for r in recheck(secret_engine, findings, run))


def test_proof_contains_no_source_or_credential_value(secret_engine):
    findings, run = original(secret_engine)
    assert 'fixture-canary' not in json.dumps(asdict(run))
    assert 'fixture-canary' not in json.dumps([asdict(f) for f in findings])


def test_static_sarif_version_cannot_override_actual_executed_engine(secret_engine):
    secret_engine[3]['report_version'] = 'static-report-version'
    findings, run = original(secret_engine)
    secret_engine[1].write_text('// cleared public fixture\n', encoding='utf-8')
    assert all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in recheck(secret_engine, findings, run))
    assert run.scanner_diagnostics['secret_coverage']['engine_version'] == '8.30.0'


@pytest.mark.parametrize('status,expected', [('SCANNER_VERIFIED_RESOLVED', '已确认关闭'),
    ('STILL_PRESENT', '仍检出'), ('INCONCLUSIVE', '暂未确认关闭')])
def test_feedback_distinguishes_recheck_outcomes(status, expected):
    from security_runtime.hook_user_feedback import secret_verification_feedback
    result = {'verification_status': status, 'original_evidence': {'file_path': 'fixture.ts', 'line_start': 1},
        'scanner_runs': [{'status': 'SUCCESS'}], 'current_evidence': []}
    feedback = secret_verification_feedback([result])
    assert expected in feedback['message'] and 'fixture.ts' in feedback['message']
    assert feedback['choices'] == []
    assert status not in feedback['message']


def test_partial_sast_does_not_hide_confirmed_secret_resolution():
    from security_runtime.hook_user_feedback import scan_status_message
    result = {'status': 'PARTIAL', 'coverage': 'PARTIAL', 'delta': {'families': [
        {'file_path': 'fixture.ts', 'status': 'RESOLVED_FAMILY'}]}}
    message = scan_status_message(result)
    assert '已从持续风险记录中关闭' in message and '仍有范围未确认' in message


def test_zero_candidates_without_proof_is_explained_as_unconfirmed():
    from security_runtime.hook_user_feedback import scan_status_message
    result = {'status': 'PARTIAL', 'coverage': 'PARTIAL', 'delta': {'families': [
        {'file_path': 'fixture.ts', 'status': 'UNCONFIRMED_ABSENCE'}]}}
    message = scan_status_message(result)
    assert '当前未再检出' in message and '缺少' in message and '关闭确认尚未完成' in message
