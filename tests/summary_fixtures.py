"""Shared synthetic risk fixtures, independent of collected summary tests."""
import hashlib

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanResult, TargetProfile
from security_runtime.storage import SQLiteStore
from security_runtime.triage import TriageService

SECRET = 'syntheticSummaryCredentialNotForProduction999'


def snapshot(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob('*') if p.is_file()}


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE', raising=False)
    (tmp_path/'App.java').write_text('class App {\n boolean verify() { return true; }\n void check() {}\n void digest() {}\n}\n')
    (tmp_path/'config.properties').write_text(f'api_key="{SECRET}"\n')
    (tmp_path/'pom.xml').write_text('<project/>\n')
    (tmp_path/'Dockerfile').write_text('FROM demo\n')
    normalizer = FindingNormalizer(tmp_path)
    def code(rule, line):
        return normalizer.make(scanner='semgrep', category='tls-validation', title='Candidate', description='Signal',
            severity='HIGH', confidence='HIGH', file_path='App.java', line=line, rule_id=rule)
    findings = [code('ai-security.java.trust-all-hostname', 2),
        code('ai-security.java.trust-all-certificates', 3), code('ai-security.java.weak-digest', 4),
        normalizer.make(scanner='gitleaks', category='secret', title='Secret', description='Candidate',
            severity='HIGH', confidence='HIGH', file_path='config.properties', line=1, evidence='[REDACTED_SECRET]')]
    for advisory in ('CVE-2026-1111', 'CVE-2026-2222'):
        findings.append(normalizer.dependency(scanner='osv-scanner', package='org.demo:lib', version='1.0',
            ecosystem='Maven', manifest='pom.xml', vulnerability_id=advisory, severity='HIGH'))
    findings.append(normalizer.make(scanner='trivy-misconfig', category='configuration', title='Config',
        description='Signal', severity='LOW', confidence='MEDIUM', file_path='Dockerfile', line=1, rule_id='DS-0002'))
    result = ScanResult('scan-a', 'release', TargetProfile(str(tmp_path),
        files=['App.java', 'config.properties', 'pom.xml', 'Dockerfile']), 'PARTIAL', findings, [],
        'Candidates', 'BLOCKED', 10, coverage='PARTIAL',
        capability_results={'CODE_SAST':'PARTIAL', 'SECRET_SCAN':'EXECUTED', 'DEPENDENCY_VULN':'PARTIAL', 'IAC_MISCONFIG':'EXECUTED'},
        capability_details={'DEPENDENCY_VULN':{'status':'PARTIAL','active_provider':'osv-scanner','provider_role':'FALLBACK',
            'coverage':'PARTIAL','primary_error_code':'MAVEN_RATE_LIMITED','coverage_notes':['Incomplete graph']}})
    store = SQLiteStore(tmp_path/'state/scans.db')
    store.save(result)
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(store.path.parent))
    return tmp_path, result, store


def review(sample, indices=(0, 1), verdict='NEEDS_REVIEW', exploitability='UNKNOWN'):
    root, scan, store = sample
    service = TriageService(store)
    for index in indices:
        packet = service.prepare(scan.scan_id, finding_ids=[scan.findings[index].id])['packets'][0]
        value = dict(finding_id=packet['finding_id'], context_hash=packet['context_hash'], verdict=verdict,
            confidence='HIGH', exploitability=exploitability, reason='Bounded AI review; '+SECRET,
            attack_path='', evidence_refs=[dict(file=packet['file'], start_line=packet['line']['start'],
                end_line=packet['line']['end'], claim='Local candidate')], preconditions_met=[],
            preconditions_unknown=['Production conditions'], recommended_action='Review')
        service.submit(scan.scan_id, [value])
