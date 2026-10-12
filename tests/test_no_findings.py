"""Empty scan results must not imply clearance, including historical snapshots."""
import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.human import render_scan, render_security_summary
from security_runtime.models import ScanResult, TargetProfile
from security_runtime.risk import NO_FINDINGS_MESSAGE, RiskEngine
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore


def test_empty_and_low_severity_findings_have_different_conclusions(tmp_path):
    engine = RiskEngine()
    low = FindingNormalizer(tmp_path).make(scanner='semgrep', category='code',
        title='Candidate', description='Needs review', severity='LOW', confidence='LOW',
        file_path='app.ts', line=1, rule_id='synthetic.example')
    assert engine.assess([]) == 'NO_FINDINGS'
    assert engine.assess([low]) == 'REVIEW'
    assert engine.assess([], complete=False) == 'REVIEW'


@pytest.mark.parametrize('status,execution,coverage,count,expected', [
    ('COMPLETED', 'EXECUTED', 'FULL', 0, 'NO_FINDINGS'),
    ('COMPLETED', 'EXECUTED', 'SCOPED', 0, 'NO_FINDINGS'),
    ('COMPLETED', 'EXECUTED', 'FULL', 1, 'REVIEW'),
    ('PARTIAL', 'EXECUTED', 'PARTIAL', 0, 'REVIEW'),
    ('PARTIAL', 'UNAVAILABLE', 'MINIMAL', 0, 'REVIEW'),
    ('NO_CHANGES', 'NO_CHANGES', 'NONE', 0, 'NOT_ASSESSED'),
    ('NOT_APPLICABLE', 'NOT_APPLICABLE', 'NONE', 0, 'NOT_ASSESSED'),
])
def test_historical_safe_is_translated_without_changing_stored_scan(
        tmp_path, status, execution, coverage, count, expected):
    (tmp_path / 'app.ts').write_text('const answer = 42;\n')
    candidate = FindingNormalizer(tmp_path).make(scanner='semgrep', category='code',
        title='Candidate', description='Needs review', severity='LOW', confidence='LOW',
        file_path='app.ts', line=1, rule_id='synthetic.example')
    scan = ScanResult('historical', 'release', TargetProfile(str(tmp_path), files=['app.ts']),
        status, [candidate] if count else [], [], '当前未发现阻止提交的问题', 'SAFE', 12,
        coverage=coverage, execution_state=execution)
    store = SQLiteStore(tmp_path / 'state' / 'scans.db')
    store.save(scan)
    before = store.path.read_bytes()
    result = SecuritySummaryService(ReadOnlySQLiteStore(store.path)).get(tmp_path, details=True)
    assert result['release_status'] == expected
    assert store.path.read_bytes() == before
    assert store.get_scan(scan.scan_id)['release_status'] == 'SAFE'
    assert 'SAFE' not in render_scan(scan)
    human = render_security_summary(result)
    assert 'SAFE' not in human
    if expected == 'NO_FINDINGS':
        assert result['notice'] == NO_FINDINGS_MESSAGE
        assert NO_FINDINGS_MESSAGE in human
    if count:
        assert '范围内未发现候选安全问题' not in human
        assert '发现 1 个候选安全问题' in render_scan(scan)


def test_completed_empty_scan_copy_names_rule_scope_and_limits(tmp_path):
    scan = ScanResult('empty', 'release', TargetProfile(str(tmp_path)), 'COMPLETED', [], [],
        NO_FINDINGS_MESSAGE, 'NO_FINDINGS', 9)
    text = render_scan(scan)
    assert '本次已执行规则范围内未发现候选安全问题' in text
    assert '不能证明项目安全' in text
    assert 'SAFE' not in text and '未发现阻止提交' not in text
