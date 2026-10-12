"""Upstream advisory options survive normalization/merge; no real upgrades."""
from dataclasses import asdict

import pytest

from security_runtime.dependency_context import remediation_options
from security_runtime.findings import FindingNormalizer, deduplicate
from security_runtime.scanners import TrivyAdapter


def trivy_finding(root, fixed):
    return TrivyAdapter().normalize({'Results': [{'Target': 'pom.xml', 'Type': 'pom',
        'Vulnerabilities': [{'PkgName': 'a:b', 'InstalledVersion': '1.0',
            'VulnerabilityID': 'CVE-2026-1234', 'FixedVersion': fixed}]}]},
        FindingNormalizer(root))[0]


def test_trivy_preserves_individual_fixed_options(tmp_path):
    row = trivy_finding(tmp_path, '1.2.3, 2.0.0')
    assert row.technical_details['fixed_versions'] == ['1.2.3', '2.0.0']
    advice = remediation_options([asdict(row)])
    assert advice['advisories'][0]['fixed_options'] == ['1.2.3', '2.0.0']
    assert advice['advisories'][0]['upstream_evidence'][0]['fixed_version_text'] == '1.2.3, 2.0.0'
    assert not advice['automatic_edit'] and not advice['joint_upgrade_verified']


@pytest.mark.parametrize('constraint', ['>=4.17.11', '${dependency.version}', 'latest'])
def test_trivy_constraint_is_not_invented_as_exact_upgrade(tmp_path, constraint):
    row = trivy_finding(tmp_path, constraint)
    advice = remediation_options([asdict(row)])['advisories'][0]
    assert advice['fixed_options'] == []
    assert advice['status'] == 'ADVISORY_CONSTRAINTS_REQUIRE_COMPATIBILITY_REVIEW'
    assert advice['upstream_evidence'][0]['fixed_version_text'] == constraint


@pytest.mark.parametrize('reverse', [False, True])
def test_provider_dedup_keeps_separate_fix_evidence(tmp_path, reverse):
    osv = FindingNormalizer(tmp_path).dependency(scanner='osv-scanner', package='a:b',
        version='1.0', ecosystem='maven', manifest='pom.xml',
        vulnerability_id='GHSA-fixture', aliases=['CVE-2026-1234'], source='OSV')
    osv.technical_details.update(fixed_versions=['1.3.0'], affected_ranges=[{
        'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '1.3.0'}]}])
    rows = [osv, trivy_finding(tmp_path, '1.2.3')]
    merged = deduplicate(list(reversed(rows)) if reverse else rows)
    assert len(merged) == 1
    advice = remediation_options([asdict(merged[0])])
    assert advice['advisories'][0]['fixed_options'] == ['1.2.3', '1.3.0']
    evidence = advice['advisories'][0]['upstream_evidence']
    by_source = {row['source']: row for row in evidence}
    assert by_source['Trivy']['fixed_versions'] == ['1.2.3']
    assert by_source['OSV']['fixed_versions'] == ['1.3.0']
    assert by_source['OSV']['affected_ranges'][0]['events'][-1] == {'fixed': '1.3.0'}
    assert not advice['joint_upgrade_verified']
