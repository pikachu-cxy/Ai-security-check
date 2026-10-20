"""Synthetic fixtures only; local excerpts are presentation, never scanner truth."""
import copy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import (LocalEvidenceService, MAX_FILE_BYTES,
    snapshot_fingerprint, WorkspaceReader, attach_local_evidence)
from security_runtime.scanners import SemgrepAdapter
from security_runtime.finding_quality import FindingQualityService
from security_runtime.storage import SQLiteStore
from security_runtime.models import ScanResult, TargetProfile


def fixture(root, name='src/App.java', text='class App {\n void run() {\n Runtime.getRuntime().exec(cmd);\n }\n}\n', captured=True):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    finding = asdict(FindingNormalizer(root).make(scanner='semgrep', category='command-injection',
        title='Synthetic command', description='Synthetic', severity='HIGH', confidence='HIGH',
        file_path=name, line=3, evidence='requires login', rule_id='fixture.command'))
    if captured:
        finding['technical_details']['evidence_locator'] = dict(
            **snapshot_fingerprint(root, name), start_column=2, end_column=35, scanner_fingerprint='a'*64)
    scan = dict(target_profile=dict(path=str(root)), findings=[finding])
    return path, finding, scan


@pytest.mark.parametrize('windows', [False, True])
def test_local_match_exact_relative_and_windows_path(tmp_path, windows):
    _, finding, scan = fixture(tmp_path)
    if windows:
        finding['file_path'] = 'src\\App.java'
    before = copy.deepcopy(scan)
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'EXACT' and result['current_context'] is None
    assert result['original_evidence']['matched_code'] == ' Runtime.getRuntime().exec(cmd);'
    assert result['original_evidence']['context_before'] == ['class App {', ' void run() {']
    assert result['locator']['relative_path'] == 'src/App.java' and result['locator']['start_column'] == 2
    assert scan == before


def test_legacy_snapshot_returns_current_context_not_original(tmp_path):
    _, finding, scan = fixture(tmp_path, captured=False)
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'UNAVAILABLE'
    assert result['reason'] == 'SNAPSHOT_FINGERPRINT_MISSING'
    assert result['original_evidence'] is None
    assert 'exec(cmd)' in result['current_context']['matched_code']


def test_modified_and_deleted_files(tmp_path):
    path, finding, scan = fixture(tmp_path)
    path.write_text(path.read_text()+'// changed\n')
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'STALE' and result['original_evidence'] is None
    assert result['reason'] == 'FILE_CHANGED_SINCE_SCAN' and result['current_context']
    path.unlink()
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'MISSING' and not result['current_context']


@pytest.mark.parametrize('name', ['../outside.java', 'src/../../outside.java', '..\\outside.java',
    'C:\\private\\outside.java', '/outside.java', '\\\\server\\private\\file', 'src/App.java:secret'])
def test_workspace_escape_rejected_before_any_read(tmp_path, monkeypatch, name):
    _, finding, scan = fixture(tmp_path)
    finding['file_path'] = name
    def forbidden(*args):
        raise AssertionError('Unsafe locator must not open a file')
    monkeypatch.setattr('security_runtime.local_evidence.os.open', forbidden)
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'UNAVAILABLE' and result['reason'] == 'UNSAFE_PATH'


def test_symlink_escape_is_not_read(tmp_path):
    path, finding, scan = fixture(tmp_path/'workspace')
    outside = tmp_path/'outside.java'; outside.write_text('PRIVATE OUTSIDE CONTENT')
    path.unlink()
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip('Windows symlink creation privilege unavailable; junction test covers Windows links')
    result = LocalEvidenceService(scan).detail(finding)
    assert result['reason'] == 'LINK_NOT_ALLOWED'
    assert 'PRIVATE OUTSIDE CONTENT' not in json.dumps(result)


def test_symlink_boundary_without_creation_privilege(tmp_path, monkeypatch):
    path, finding, scan = fixture(tmp_path)
    original = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda p: p == path or original(p))
    monkeypatch.setattr('security_runtime.local_evidence.os.open', lambda *args: pytest.fail('Link must not open'))
    assert LocalEvidenceService(scan).detail(finding)['reason'] == 'LINK_NOT_ALLOWED'


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows junction boundary')
def test_windows_junction_escape(tmp_path):
    import subprocess
    root = tmp_path/'workspace'; root.mkdir()
    outside = tmp_path/'outside'; outside.mkdir(); (outside/'App.java').write_text('PRIVATE OUTSIDE')
    link = root/'src'
    # Fixed synthetic paths, native PowerShell only; no cross-shell file moves.
    script = tmp_path/'junction.ps1'
    script.write_text('param($linkPath, $targetPath)\nNew-Item -ItemType Junction -Path $linkPath -Target $targetPath | Out-Null\n')
    result = subprocess.run(['powershell', '-NoProfile', '-File', str(script), str(link), str(outside)], capture_output=True)
    if result.returncode:
        pytest.fail('Unable to create test junction')
    try:
        scan = dict(target_profile=dict(path=str(root)), findings=[])
        finding = dict(file_path='src/App.java', line_start=1, line_end=1,
            category='code', technical_details={}, scanner_sources=['semgrep'])
        assert LocalEvidenceService(scan).detail(finding)['reason'] == 'LINK_NOT_ALLOWED'
    finally:
        link.rmdir()  # Removes junction itself, never recursively touches target.


@pytest.mark.parametrize('content,reason', [(b'x'*(MAX_FILE_BYTES+1), 'FILE_TOO_LARGE'),
    (b'class App\0{}', 'BINARY_FILE'), (b'class App\n\xff\n', 'DECODE_FAILED_UTF8')], ids=['oversized', 'binary', 'decode'])
def test_size_binary_decode_fail_closed(tmp_path, content, reason):
    path, finding, scan = fixture(tmp_path)
    path.write_bytes(content)
    result = LocalEvidenceService(scan).detail(finding)
    assert result['evidence_status'] == 'UNAVAILABLE' and result['reason'] == reason
    assert result['original_evidence'] is None and result['current_context'] is None


def test_line_and_context_budgets(tmp_path):
    _, finding, scan = fixture(tmp_path, text='run(cmd);\n'*100)
    finding['line_end'] = 90
    assert LocalEvidenceService(scan).detail(finding)['reason'] == 'LINE_BUDGET_EXCEEDED'
    with pytest.raises(ValueError): LocalEvidenceService(scan).detail(finding, 21)
    with pytest.raises(ValueError): LocalEvidenceService(scan).detail(finding, -1)


def test_secret_never_read_and_adjacent_literals_redacted(tmp_path, monkeypatch):
    secret = 'syntheticCredentialLocalEvidence999'
    text = f'class App {{\n String password = "{secret}";\n Runtime.getRuntime().exec(cmd);\n token = "tiny";\n}}\n'
    _, finding, scan = fixture(tmp_path, text=text)
    result = LocalEvidenceService(scan).detail(finding)
    assert secret not in json.dumps(result) and 'tiny' not in json.dumps(result)
    assert 'exec(cmd)' in result['original_evidence']['matched_code']
    secret_finding = dict(finding, category='secret')
    scan['findings'].append(secret_finding)
    def forbidden(*args):
        raise AssertionError('Secret detail must not read any source')
    monkeypatch.setattr(WorkspaceReader, 'read', forbidden)
    result = LocalEvidenceService(scan).detail(secret_finding)
    assert result['reason'] == 'SECRET_REDACTED' and '[REDACTED_SECRET]' in json.dumps(result)


@pytest.mark.parametrize('text', ['String privateKey = """\nprivateLiteralMiddle\nprivateLiteralEnd\n""";\nrun(cmd);\n',
    '-----BEGIN PRIVATE KEY-----\nprivateKeyMiddle\nprivateKeyEnd\n-----END PRIVATE KEY-----\nrun(cmd);\n'])
def test_multiline_secret_window_redaction(tmp_path, text):
    _, finding, scan = fixture(tmp_path, text=text)
    result = LocalEvidenceService(scan).detail(finding, 0)
    assert result['evidence_status'] == 'EXACT'
    assert 'privateLiteral' not in json.dumps(result) and 'privateKey' not in json.dumps(result)


def test_opened_file_race_fails_before_read(tmp_path, monkeypatch):
    path, finding, scan = fixture(tmp_path)
    outside = tmp_path/'outside'; outside.write_text('OUTSIDE_MUST_NOT_BE_READ')
    from security_runtime import local_evidence
    original_open = local_evidence.os.open
    def swapped(*args, **kwargs):
        return original_open(outside, *args[1:], **kwargs)
    monkeypatch.setattr(local_evidence.os, 'open', swapped)
    result = LocalEvidenceService(scan).detail(finding)
    assert result['reason'] == 'FILE_CHANGED_DURING_READ'
    assert 'OUTSIDE_MUST_NOT_BE_READ' not in json.dumps(result)


def test_scanner_locator_and_actual_metadata_omit_source(tmp_path):
    private = 'syntheticSourceSecretShouldNeverPersist'
    raw = dict(results=[dict(check_id='fixture.command', path='App.java',
        start=dict(line=2, col=4), end=dict(line=3, col=9), extra=dict(
        lines='requires login', fingerprint='requires login', message='Synthetic', severity='ERROR',
        metavars={'$X': dict(start=dict(line=2, col=5), abstract_content=private)},
        dataflow_trace=dict(taint_source=['CliLoc', dict(location=dict(path=str(tmp_path/'App.java'),
            start=dict(line=1, col=2)), content=private)])))])
    finding = SemgrepAdapter().normalize(raw, FindingNormalizer(tmp_path))[0]
    assert finding.technical_details['evidence_locator']['start_column'] == 4
    assert finding.technical_details['evidence_locator']['scanner_fingerprint'] is None
    md = finding.technical_details['scanner_evidence_metadata']
    assert md['metavars']['$X']['start']['col'] == 5
    assert md['dataflow_trace']['taint_source'][0] == 'CliLoc'
    assert private not in json.dumps(asdict(finding)) and str(tmp_path) not in json.dumps(md)


def test_hydration_does_not_change_stored_scan_reviews_or_identity(tmp_path):
    private = 'syntheticPrivateValueMustNotEnterDatabase'
    text = f'class App {{\n String token="{private}";\n Runtime.getRuntime().exec(cmd);\n}}\n'
    path, raw, scan = fixture(tmp_path, text=text)
    from security_runtime.models import Finding
    finding = Finding(**raw)
    store = SQLiteStore(tmp_path/'state.db')
    store.save(ScanResult('s1', 'release', TargetProfile(str(tmp_path)), 'COMPLETED',
        [finding], [], 'Synthetic', 'REVIEW', 1, coverage='FULL'))
    service = FindingQualityService(store)
    row = service.view('s1')['findings'][0]
    service.review('s1', [dict(finding_id=row['finding_id'], observation_hash=row['observation_hash'],
        triage_status='TRUE_POSITIVE', triage_reason='Synthetic human decision', triage_source='HUMAN')])
    before = store.get_scan('s1'); view = service.view('s1')
    attach_local_evidence(view, before)
    assert view['findings'][0]['local_evidence']['evidence_status'] == 'EXACT'
    path.write_text('changed\n')
    changed = attach_local_evidence(service.view('s1'), before)
    assert changed['findings'][0]['triage_status'] == 'TRUE_POSITIVE'
    assert changed['findings'][0]['observation_hash'] == row['observation_hash']
    assert changed['scan_coverage'] == 'FULL' and store.get_scan('s1') == before
    assert 'Runtime.getRuntime' not in json.dumps(before)
    assert private not in store.path.read_bytes().decode('utf-8', errors='ignore')


def test_private_export_local_evidence_leaves_database_intact(tmp_path, capsys):
    from scripts.finding_quality import main
    from security_runtime.models import Finding
    private = 'syntheticPrivateExportLiteralOnly'
    _, raw, _ = fixture(tmp_path, text=f'class App {{\n String password="{private}";\n Runtime.getRuntime().exec(cmd);\n}}\n')
    store = SQLiteStore(tmp_path/'state.db')
    store.save(ScanResult('s1', 'release', TargetProfile(str(tmp_path)), 'COMPLETED',
        [Finding(**raw)], [], 'Synthetic', 'REVIEW', 1, coverage='FULL'))
    before = store.path.read_bytes()
    original = FindingQualityService(store).view('s1')['findings'][0]
    main(['export', '--workspace', str(tmp_path), '--database', str(store.path),
        '--scan', 's1', '--local-evidence'])
    baseline = (tmp_path/'.security-runtime/finding-quality/baseline.json').read_text()
    data = json.loads(baseline)
    assert data['local_evidence_summary']['status'] == dict(EXACT=1, STALE=0, MISSING=0, UNAVAILABLE=0)
    assert data['findings'][0]['observation_hash'] == original['observation_hash']
    assert private not in baseline and store.path.read_bytes() == before
    assert 'Runtime.getRuntime' not in capsys.readouterr().out


@pytest.mark.parametrize('change', ['unchanged', 'during_scan', 'unreadable'])
def test_adapter_scan_captures_hash_without_changing_engine_results(tmp_path, monkeypatch, change):
    from security_runtime.models import ScanContext, ScanMode
    from security_runtime.processes import ProcessResult
    from security_runtime.toolchain import ResolvedTool, ToolStatus
    path = tmp_path/'App.java'; path.write_text('class App { void run() { danger(cmd); } }\n')
    rules = tmp_path/'rules'; rules.mkdir()
    (rules/'rules.yml').write_text('rules:\n- id: fixture.command\n  languages: [java]\n  message: Synthetic\n  severity: ERROR\n  pattern: danger($X)\n')
    scanner = SemgrepAdapter()
    monkeypatch.setattr(scanner.tool_manager, 'ensure', lambda *a, **k:
        ResolvedTool('semgrep', '1.178.0', 'semgrep', None, ToolStatus.READY))
    def execute(argv, cwd, timeout):
        if change == 'during_scan':
            path.write_text('class App { void run() { danger(changed); } }\n')
        return ProcessResult(0, json.dumps(dict(results=[dict(check_id='fixture.command',
            path='App.java', start=dict(line=1, col=25), end=dict(line=1, col=36),
            extra=dict(lines='requires login', fingerprint='requires login', message='Synthetic', severity='ERROR'))],
            paths=dict(scanned=['App.java']), time=dict(rules=['fixture.command']), errors=[])), '', 1)
    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    if change == 'unreadable':
        monkeypatch.setattr('security_runtime.scanners.snapshot_fingerprint', lambda *a:
            dict(file_sha256=None, reason='DECODE_FAILED_UTF8'))
    findings, run = scanner.scan(ScanContext(str(tmp_path), ScanMode.RELEASE, ('App.java',),
        rules_path=str(rules)), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and len(findings) == 1
    assert run.rule_coverage['total_executed'] == 1
    locator = findings[0].technical_details['evidence_locator']
    assert bool(locator['file_sha256']) == (change == 'unchanged')
    if change == 'during_scan': assert locator['snapshot_reason'] == 'SCAN_FILE_CHANGED'
    raw = asdict(findings[0])
    scan = dict(target_profile=dict(path=str(tmp_path)), findings=[raw])
    assert LocalEvidenceService(scan).detail(raw)['evidence_status'] == ('EXACT' if change == 'unchanged' else 'UNAVAILABLE')
