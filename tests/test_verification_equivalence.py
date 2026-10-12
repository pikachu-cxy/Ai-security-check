"""Occurrence compatibility, family matching, and conservative absence proof."""
from dataclasses import asdict
from types import SimpleNamespace

import pytest

from security_runtime.equivalence import equivalence_key
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScannerRun
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.verification import VerificationService
from security_runtime.verification_policy import local_recheck_requested


def finding(root, *, line=100, rule='tls-rule', file='Tls.java', scanner='fixture', category='code'):
    return FindingNormalizer(root).make(scanner=scanner, category=category, title='Candidate',
        description='Untrusted scanner text', severity='HIGH', confidence='HIGH',
        file_path=file, line=line, rule_id=rule)


class LocalScanner:
    name = scanner_id = 'fixture'
    verification_offline = verification_scope_complete = True

    def __init__(self, found=(), status='SUCCESS', coverage='FULL'):
        self.found, self.status, self.coverage = found, status, coverage
        self.calls = []

    def supports(self, profile, context):
        return True

    def scan(self, context, normalizer):
        assert local_recheck_requested()
        self.calls.append(context.files)
        return list(self.found), ScannerRun(self.name, 'test', self.status, 2, coverage_contract=self.coverage)


@pytest.fixture
def root(tmp_path):
    (tmp_path / 'Tls.java').write_text('class Tls {}', encoding='utf-8')
    return tmp_path


def verify(root, old, scanner):
    return VerificationService(ScannerRegistry([scanner])).verify_many(root, [asdict(old)], {'target_profile':{'files':['Tls.java']}})[0]


def test_line_movement_is_same_family_not_same_occurrence(root):
    old, moved = finding(root), finding(root, line=110)
    assert old.id == old.fingerprint and old.fingerprint != moved.fingerprint
    assert old.equivalence_key == moved.equivalence_key
    out = verify(root, old, LocalScanner([moved]))
    assert out['verification_status'] == 'STILL_PRESENT'
    assert out['matched_by'] == 'equivalence_key'
    assert out['original_evidence']['line_start'] == 100
    assert out['current_evidence'][0]['line_start'] == 110
    assert not local_recheck_requested()


def test_exact_occurrence_and_legacy_missing_additive_key(root):
    old = finding(root)
    row = asdict(old)
    del row['equivalence_key']
    service = VerificationService(ScannerRegistry([LocalScanner([old])]))
    out = service.verify_many(root, [row], {'target_profile':{'files':['Tls.java']}})[0]
    assert out['matched_by'] == 'fingerprint'
    assert equivalence_key(row) == old.equivalence_key


def test_different_rule_must_not_match_legacy_fingerprint_collision(root):
    old, other = finding(root), finding(root, rule='other-rule')
    assert old.fingerprint == other.fingerprint  # preserve historical contract
    assert old.equivalence_key != other.equivalence_key
    assert verify(root, old, LocalScanner([other]))['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    other.file_path = 'Other.java'
    assert verify(root, old, LocalScanner([other]))['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


@pytest.mark.parametrize('status,coverage', [('FAILED','FULL'),('TIMEOUT','FULL'),('UNAVAILABLE','FULL'),
    ('NOT_COVERED','FULL'),('SUCCESS','PARTIAL')])
def test_failed_or_partial_absence_never_resolved(root, status, coverage):
    assert verify(root, finding(root), LocalScanner(status=status, coverage=coverage))['status'] == 'INCONCLUSIVE'


def test_missing_rule_file_and_unattested_provider(root):
    scanner = LocalScanner()
    assert verify(root, finding(root, rule=''), scanner)['status'] == 'INCONCLUSIVE'
    scanner.verification_offline = False
    assert verify(root, finding(root), scanner)['status'] == 'INCONCLUSIVE'
    assert len(scanner.calls) == 1
    (root / 'Tls.java').unlink()
    scanner.verification_offline = True
    assert verify(root, finding(root), scanner)['status'] == 'INCONCLUSIVE'
    assert len(scanner.calls) == 1


def test_secret_family_has_no_credential_or_credential_digest(root):
    one, two = finding(root, category='secret'), finding(root, category='secret', line=110)
    one.evidence, two.evidence = 'CANARY_SECRET_A', 'CANARY_SECRET_B'
    one.technical_details['Secret'] = 'CANARY_SECRET_A'
    assert equivalence_key(one) == equivalence_key(two)
    out = verify(root, one, LocalScanner([two]))
    assert out['status'] == 'STILL_PRESENT'
    assert 'CANARY_SECRET' not in str(out)


def test_dependency_reuses_canonical_identity(root):
    n = FindingNormalizer(root)
    a = n.dependency(scanner='trivy-vuln', package='a:b', version='1', ecosystem='Maven',
        manifest='pom.xml', vulnerability_id='CVE-2026-1234')
    b = n.dependency(scanner='osv-scanner', package='a:b', version='1', ecosystem='maven',
        manifest='pom.xml', vulnerability_id='GHSA-xxxx', aliases=['CVE-2026-1234'])
    assert a.fingerprint == b.fingerprint
    assert a.equivalence_key == b.equivalence_key
    b.technical_details['package_version'] = '2'
    assert equivalence_key(a) != equivalence_key(b)


@pytest.mark.parametrize('current_id,aliases', [
    ('CVE-2026-1234', []), ('GHSA-fixture', ['CVE-2026-1234'])])
def test_dependency_upgrade_still_affected_is_not_resolved(root, current_id, aliases):
    (root / 'pom.xml').write_text('<project/>')
    normalizer = FindingNormalizer(root)
    old = normalizer.dependency(scanner='fixture', package='a:b', version='1.0',
        ecosystem='maven', manifest='pom.xml', vulnerability_id='CVE-2026-1234')
    current = normalizer.dependency(scanner='fixture', package='a:b', version='1.1',
        ecosystem='maven', manifest='pom.xml', vulnerability_id=current_id, aliases=aliases)
    assert old.fingerprint != current.fingerprint
    assert old.equivalence_key != current.equivalence_key
    out = VerificationService(ScannerRegistry([LocalScanner([current])])).verify_many(
        root, [asdict(old)], {'target_profile': {'files': ['pom.xml']}})[0]
    assert out['verification_status'] == 'STILL_PRESENT'
    assert out['matched_by'] == 'dependency_advisory'


@pytest.mark.parametrize('package,advisory,coverage,expected', [
    ('a:b', 'CVE-2026-9999', 'FULL', 'SCANNER_VERIFIED_RESOLVED'),
    ('other:package', 'CVE-2026-1234', 'FULL', 'SCANNER_VERIFIED_RESOLVED'),
    ('a:b', 'CVE-2026-9999', 'PARTIAL', 'INCONCLUSIVE')])
def test_dependency_recheck_keeps_package_advisory_and_coverage_boundaries(
        root, package, advisory, coverage, expected):
    (root / 'pom.xml').write_text('<project/>')
    normalizer = FindingNormalizer(root)
    old = normalizer.dependency(scanner='fixture', package='a:b', version='1.0',
        ecosystem='maven', manifest='pom.xml', vulnerability_id='CVE-2026-1234')
    current = normalizer.dependency(scanner='fixture', package=package, version='2.0',
        ecosystem='maven', manifest='pom.xml', vulnerability_id=advisory)
    out = VerificationService(ScannerRegistry([LocalScanner([current], coverage=coverage)])).verify_many(
        root, [asdict(old)], {'target_profile': {'files': ['pom.xml']}})[0]
    assert out['verification_status'] == expected


def test_dependency_recheck_missing_current_identity_cannot_prove_absence(root):
    (root / 'pom.xml').write_text('<project/>')
    normalizer = FindingNormalizer(root)
    old = normalizer.dependency(scanner='fixture', package='a:b', version='1.0',
        ecosystem='maven', manifest='pom.xml', vulnerability_id='CVE-2026-1234')
    incomplete = normalizer.dependency(scanner='fixture', package='a:b', version='1.1',
        ecosystem='maven', manifest='pom.xml', vulnerability_id='')
    out = VerificationService(ScannerRegistry([LocalScanner([incomplete])])).verify_many(
        root, [asdict(old)], {'target_profile': {'files': ['pom.xml']}})[0]
    assert out['verification_status'] == 'INCONCLUSIVE'
    assert 'DEPENDENCY_ADVISORY_IDENTITY_MISSING' in out['reason']


class PlannedScanner(LocalScanner):
    def __init__(self, *, confirmation=True, scanned=True, error=False, selected=True):
        super().__init__()
        self.plan = SimpleNamespace(rules=[SimpleNamespace(rule_id='tls-rule', rule_version='1')] if selected else [],
            pack=SimpleNamespace(descriptor=SimpleNamespace(rule_pack_id='fixture', version='1'), checksum='fixture'),
            confirmed_rules={'tls-rule'} if confirmation else set(), scanned_files={'Tls.java'} if scanned else set(),
            errored_files={'Tls.java'} if error else set(), unscoped_error=False)

    def plan_rules(self, profile, context):
        return self.plan


@pytest.mark.parametrize('kwargs', [{'confirmation':False},{'scanned':False},{'error':True},{'selected':False}])
def test_rule_and_file_execution_evidence_required(root, kwargs):
    assert verify(root, finding(root), PlannedScanner(**kwargs))['status'] == 'INCONCLUSIVE'


def test_reported_engine_skip_cannot_prove_resolution(root):
    scanner = PlannedScanner()
    scanner.plan.skipped_files = {'Tls.java': 'too_big'}
    assert verify(root, finding(root), scanner)['status'] == 'INCONCLUSIVE'


def test_catalog_version_mismatch_and_original_rule_missing(root):
    old = finding(root)
    old.technical_details.update(rule_pack='fixture', rule_version='2')
    assert verify(root, old, PlannedScanner())['status'] == 'INCONCLUSIVE'
    old.technical_details['rule_version'] = '1'
    assert verify(root, old, PlannedScanner())['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


def test_member_scope_reuse_and_safe_failure(root):
    scanner = LocalScanner()
    service = VerificationService(ScannerRegistry([scanner]))
    members = [asdict(finding(root)), asdict(finding(root, line=101))]
    scan = {'target_profile':{'files':['Tls.java']}}
    out = service.verify_many(root, members, scan)
    assert all(r['status'] == 'RESOLVED' for r in out)
    assert scanner.calls == [('Tls.java',)]
    members[0]['file_path'] = '../escape.java'
    assert service.verify_many(root, members, scan)[0]['status'] == 'INCONCLUSIVE'
    assert not out[0]['runtime_observed_execution']['patch_applied']
    assert not out[0]['runtime_observed_execution']['tests_run']


def test_low_level_verify_retains_history_and_legacy_status(root):
    store = SQLiteStore(root / 'state.db')
    old = asdict(finding(root))
    scan = {'target_profile': {'path': str(root), 'files':['Tls.java']}}
    runtime = SecurityRuntime(ScannerRegistry([LocalScanner()]), store)
    store.get_finding = lambda _: (old, scan)
    out = runtime.verify(old['id'], root)
    assert out['status'] == 'RESOLVED'
    assert out['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert old['line_start'] == 100


def test_missing_original_scope_and_budget_do_not_invoke(root):
    scanner = LocalScanner()
    service = VerificationService(ScannerRegistry([scanner]))
    assert service.verify_many(root, [asdict(finding(root))], {})[0]['reason'] == 'ORIGINAL_AFFECTED_SCOPE_NOT_ATTESTED'
    members = [asdict(finding(root, file=f'File{i}.java')) for i in range(21)]
    results = service.verify_many(root, members, {'target_profile':{'files':[f['file_path'] for f in members]}})
    assert all(r['reason'] == 'VERIFICATION_BUDGET_EXCEEDED' for r in results)
    assert scanner.calls == []


def test_preparation_failure_is_not_reported_as_engine_execution(root, monkeypatch):
    from security_runtime.scanners import GitleaksAdapter
    adapter = GitleaksAdapter()
    monkeypatch.setattr(adapter, 'scan', lambda *a: ([], ScannerRun('gitleaks','test','FAILED',1)))
    out = verify(root, finding(root, scanner='gitleaks'), adapter)
    assert out['runtime_observed_execution']['scanner_recheck_attempted']
    assert not out['runtime_observed_execution']['scanner_recheck']
    assert not out['runtime_observed_execution']['engine_process_observed']


def test_failed_provider_dominates_presence_and_failed_output_is_untrusted(root):
    old = finding(root)
    old.scanner_sources.append('missing-provider')
    out = verify(root, old, LocalScanner([finding(root)]))
    assert out['status'] == 'INCONCLUSIVE' and out['observed_present']
    out = verify(root, finding(root), LocalScanner([finding(root)], status='FAILED'))
    assert out['status'] == 'INCONCLUSIVE' and not out['current_evidence']
