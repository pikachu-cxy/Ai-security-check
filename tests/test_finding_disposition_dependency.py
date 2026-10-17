"""Concrete package/advisory handling must not depend on scanner line=1."""
import json

import pytest

from security_runtime.finding_feedback import FindingFeedbackService
from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.storage import SQLiteStore
from test_finding_feedback import stable_package  # noqa: F401


def scan(store, root, scan_id, *, package='target-package', version='1.0',
         advisory='CVE-2099-0001', manifest='requirements.txt', ecosystem='pypi', **metadata):
    finding = FindingNormalizer(root).dependency(scanner='osv-scanner', package=package,
        version=version, ecosystem=ecosystem, manifest=manifest, vulnerability_id=advisory)
    finding.technical_details.update(metadata)
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(root, manifest)
    store.save(ScanResult(scan_id, 'release', TargetProfile(str(root), files=[manifest]),
        'COMPLETED', [finding], [ScannerRun('osv-scanner', '1.0', 'SUCCESS', 1)], '', 'REVIEW', 1))
    return finding


def submit_risk(service, scan_id, finding, *, line=2):
    prepared = service.prepare(scan_id, finding.id)
    assert prepared['status'] == 'READY'
    return service.submit(scan_id, finding.id, context_hash=prepared['packet']['context_hash'],
        verdict='STILL_RISK', reason='The newly observed package/version remains in the affected advisory range.',
        evidence_refs=[dict(file=finding.file_path, start_line=line, end_line=line,
                            claim='The affected package/version is declared here; the issued advisory material binds this package.')],
        confidence='HIGH', unknowns=[], context_complete=True)


def test_same_package_upgrade_requires_reassessment_then_fresh_risk_reopens(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    manifest = root/'requirements.txt'
    manifest.write_text('sibling-package==9.0\ntarget-package==1.0\n')
    store = SQLiteStore(tmp_path/'scans.db')
    finding = scan(store, root, 's1')
    service = FindingFeedbackService(store, root)
    excluded = service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    assert finding.line_start == 1
    manifest.write_text('sibling-package==9.0\ntarget-package==1.1\n')
    assert service.status('s1', finding.id)['disposition']['reassessment_required']
    current = scan(store, root, 's2', version='1.1')
    pending = service.status('s2', current.id)
    assert pending['disposition']['issue_key'] == excluded['disposition']['issue_key']
    assert pending['reminder_suppressed'] and pending['disposition']['reassessment_required']
    reviewed = submit_risk(service, 's2', current)
    assert not reviewed['reminder_suppressed'] and reviewed['state'] == 'STILL_RISK'
    assert reviewed['disposition']['decision']['reopened']


def test_new_advisory_or_sibling_package_does_not_borrow_an_exclusion(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements.txt').write_text('sibling-package==1.0\ntarget-package==1.0\n')
    store = SQLiteStore(tmp_path/'scans.db')
    original = scan(store, root, 's1')
    service = FindingFeedbackService(store, root)
    state = service.set_disposition('s1', original.id, 'EXCLUDE', user_requested=True)
    new_advisory = scan(store, root, 's2', advisory='CVE-2099-0002')
    assert not service.status('s2', new_advisory.id)['reminder_suppressed']
    sibling = scan(store, root, 's3', package='sibling-package')
    assert not service.status('s3', sibling.id)['reminder_suppressed']
    assert service.status('s1', original.id)['disposition']['issue_key'] == state['disposition']['issue_key']


def test_unrelated_requirements_or_comment_movement_do_not_restart_user_reminder(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements.txt').write_text('sibling-package==9.0\ntarget-package==1.0\n')
    store = SQLiteStore(tmp_path/'scans.db')
    finding = scan(store, root, 's1')
    service = FindingFeedbackService(store, root)
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    (root/'requirements.txt').write_text('# moved\nsibling-package==10.0\n\ntarget-package==1.0\n')
    current = scan(store, root, 's2')
    state = service.status('s2', current.id)
    assert state['reminder_suppressed'] and not state['disposition']['reassessment_required']
    assert submit_risk(service, 's2', current, line=4)['reminder_suppressed']


def test_package_json_other_fields_are_not_material_but_target_version_is(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    manifest = root/'package.json'
    manifest.write_text(json.dumps(dict(name='fixture', dependencies={'target-package': '1.0', 'sibling': '1'}), indent=2))
    store = SQLiteStore(tmp_path/'scans.db')
    finding = scan(store, root, 's1', manifest='package.json', ecosystem='npm')
    service = FindingFeedbackService(store, root)
    service.set_disposition('s1', finding.id, 'EXCLUDE', user_requested=True)
    manifest.write_text(json.dumps(dict(name='renamed', scripts={'test': 'nothing'},
        dependencies={'target-package': '1.0', 'sibling': '2'}), indent=2))
    unchanged = scan(store, root, 's2', manifest='package.json', ecosystem='npm')
    assert not service.status('s2', unchanged.id)['disposition']['reassessment_required']
    manifest.write_text(json.dumps(dict(name='renamed', dependencies={'target-package': '1.1'}), indent=2))
    changed = scan(store, root, 's3', manifest='package.json', ecosystem='npm', version='1.1')
    assert service.status('s3', changed.id)['disposition']['reassessment_required']
    line = next(index for index, text in enumerate(manifest.read_text().splitlines(), 1) if 'target-package' in text)
    assert not submit_risk(service, 's3', changed, line=line)['reminder_suppressed']


def test_same_advisory_new_affected_material_can_reopen_but_provider_only_cannot(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements.txt').write_text('sibling-package==9.0\ntarget-package==1.0\n')
    store = SQLiteStore(tmp_path/'scans.db')
    original = scan(store, root, 's1', source='old-provider')
    service = FindingFeedbackService(store, root)
    service.set_disposition('s1', original.id, 'EXCLUDE', user_requested=True)
    provider = scan(store, root, 's2', source='new-provider')
    assert not service.status('s2', provider.id)['disposition']['reassessment_required']
    assert submit_risk(service, 's2', provider)['reminder_suppressed']
    updated = scan(store, root, 's3', affected_ranges=[dict(type='ECOSYSTEM',
        events=[dict(introduced='0'), dict(fixed='2.0')])], fixed_versions=['2.0'])
    assert service.status('s3', updated.id)['disposition']['reassessment_required']
    assert not submit_risk(service, 's3', updated)['reminder_suppressed']


@pytest.mark.parametrize('ecosystem,purl,expected,manifest,content', [
    ('npm', 'pkg:npm/%40scope/target@1.0', '@scope/target', 'package.json',
     '{"dependencies":{"@scope/target":"1.0"}}'),
    ('npm', 'pkg:npm/@scope/target', '@scope/target', 'package.json',
     '{"dependencies":{"@scope/target":"1.0"}}'),
    ('maven', 'pkg:maven/org.example/target@1.0', 'org.example:target', 'pom.xml',
     '<project><dependencies><dependency><groupId>org.example</groupId><artifactId>target</artifactId>'
     '<version>1.0</version></dependency></dependencies></project>'),
])
def test_purl_only_identity_preserves_scoped_package_and_namespace(tmp_path, ecosystem, purl,
                                                               expected, manifest, content):
    from security_runtime.dependency_disposition import dependency_scope
    from dataclasses import asdict
    (tmp_path/manifest).write_text(content)
    finding = FindingNormalizer(tmp_path).dependency(scanner='osv-scanner', package=expected,
        version='1.0', ecosystem=ecosystem, manifest=manifest, vulnerability_id='CVE-2099-0001')
    finding.technical_details['evidence_locator'] = snapshot_fingerprint(tmp_path, manifest)
    native = dependency_scope(tmp_path, asdict(finding))
    finding.technical_details.pop('package')
    finding.technical_details['purl'] = purl
    assert dependency_scope(tmp_path, asdict(finding))['issue_key'] == native['issue_key']
