"""Partial Vue script evidence can show presence, never prove SFC absence."""
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.hook_runtime import covered, family_delta, family_multiset
from security_runtime.models import ScannerRun
from security_runtime.scanners import GitleaksAdapter, ScannerRegistry
from security_runtime.verification import VerificationService
from security_runtime.verification_policy import local_recheck_requested, scanner_process_observed


class VuePlannedScanner:
    """Trusted local provider exposing otherwise complete rule/file receipts."""
    name = scanner_id = 'fixture'
    verification_offline = verification_scope_complete = True

    def __init__(self, plan, found=()):
        self.plan, self.found, self.calls = plan, found, []

    def plan_rules(self, profile, context):
        return self.plan

    def supports(self, profile, context):
        return True

    def scan(self, context, normalizer):
        assert local_recheck_requested()
        self.calls.append(context.files)
        return list(self.found), ScannerRun(self.name, 'fixture', 'SUCCESS', 0,
                                            coverage_contract='FULL', provider='fixture')


def setup_case(root, bundled, *, filename='App.vue'):
    source = 'const input = location.hash;\nelement.innerHTML = input;\n'
    (root / filename).write_text('<script setup>' + source + '</script>\n'
        if filename.endswith('.vue') else source, encoding='utf-8')
    detector = 'ai-security.javascript.browser-dom-xss' if bundled else 'local.vue.rule'
    record = SimpleNamespace(rule_id=detector, rule_version='1.0.0',
                             target_extensions=('.js', '.vue'))
    # Include .vue in the simulated family applicability so a pre-existing
    # catalog omission cannot accidentally make the new absence guard pass.
    program = SimpleNamespace(family_rules=lambda _: (detector,)) if bundled else None
    pack = SimpleNamespace(descriptor=SimpleNamespace(rule_pack_id='builtin' if bundled else 'local',
                           version='1.0.0', bundled=bundled), checksum='a' * 64,
                           program=program, catalog=(record,))
    plan = SimpleNamespace(rules=(record,), pack=pack, confirmed_rules={detector},
        scanned_files={filename}, errored_files=set(), skipped_files={}, unscoped_error=False)
    old = FindingNormalizer(root).make(scanner='fixture', category='browser-dom-xss',
        title='Candidate', description='Static test fixture', severity='HIGH', confidence='HIGH',
        file_path=filename, line=2, rule_id=detector)
    old.technical_details.update(engine='fixture', rule_pack=pack.descriptor.rule_pack_id,
        rule_pack_version=pack.descriptor.version, rule_pack_checksum=pack.checksum,
        rule_version=record.rule_version)
    return old, plan


def verify(root, old, scanner):
    return VerificationService(ScannerRegistry([scanner])).verify_many(root, [asdict(old)],
        {'target_profile': {'files': [old.file_path]}})[0]


@pytest.mark.parametrize('bundled', [False, True], ids=['local-rules-no-program', 'bundled-family'])
def test_vue_zero_findings_cannot_resolve_even_with_complete_rule_file_receipts(tmp_path, bundled):
    old, plan = setup_case(tmp_path, bundled)
    scanner = VuePlannedScanner(plan)
    result = verify(tmp_path, old, scanner)
    assert scanner.calls == [('App.vue',)]
    assert result['status'] == result['verification_status'] == 'INCONCLUSIVE'
    assert 'ORIGINAL_RULE_FILE_COVERAGE_NOT_PROVEN' in result['reason']
    assert not result['current_evidence']


@pytest.mark.parametrize('bundled', [False, True], ids=['local-rules-no-program', 'bundled-family'])
def test_vue_matching_finding_stays_present_despite_partial_absence_boundary(tmp_path, bundled):
    old, plan = setup_case(tmp_path, bundled)
    result = verify(tmp_path, old, VuePlannedScanner(plan, (old,)))
    assert result['status'] == result['verification_status'] == 'STILL_PRESENT'
    assert result['matched_by'] == 'fingerprint'
    assert result['current_evidence'][0]['file_path'] == 'App.vue'


@pytest.mark.parametrize('bundled', [False, True], ids=['local-rules-no-program', 'bundled-family'])
def test_hook_vue_absence_is_unconfirmed_and_retains_original_family(tmp_path, bundled):
    old, plan = setup_case(tmp_path, bundled)
    run = ScannerRun('fixture', 'fixture', 'SUCCESS', 0, coverage_contract='FULL', provider='fixture')
    previous = family_multiset([old], [run], {'fixture': plan})
    family, = previous.values()
    assert not family['uncertain']  # The only missing proof is full Vue coverage.
    assert not covered(family, [run], {'fixture': plan})
    current, delta = family_delta(previous, {}, lambda value: covered(value, [run], {'fixture': plan}))
    assert delta['resolved'] == 0 and delta['persisting'] == 1
    assert delta['families'][0]['status'] == 'UNCONFIRMED_ABSENCE'
    assert current[family['equivalence_key']]['uncertain']


@pytest.mark.parametrize('bundled', [False, True], ids=['local-rules-no-program', 'bundled-family'])
def test_hook_vue_observed_family_remains_persisting(tmp_path, bundled):
    old, plan = setup_case(tmp_path, bundled)
    run = ScannerRun('fixture', 'fixture', 'SUCCESS', 0, coverage_contract='FULL', provider='fixture')
    previous = family_multiset([old], [run], {'fixture': plan})
    current, delta = family_delta(previous, previous,
        lambda value: covered(value, [run], {'fixture': plan}))
    assert delta['resolved'] == 0 and delta['persisting'] == 1
    assert delta['families'][0]['status'] == 'PERSISTING'
    assert delta['families'][0]['count_certainty'] == 'OBSERVED_LOWER_BOUND'
    assert set(current) == set(previous)


@pytest.mark.parametrize('bundled', [False, True], ids=['local-rules-no-program', 'bundled-family'])
def test_same_complete_receipts_still_prove_absence_for_standalone_javascript(tmp_path, bundled):
    old, plan = setup_case(tmp_path, bundled, filename='App.js')
    result = verify(tmp_path, old, VuePlannedScanner(plan))
    assert result['status'] == 'RESOLVED'
    assert result['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


def test_vue_sast_boundary_does_not_override_bound_gitleaks_absence_receipt(tmp_path):
    (tmp_path / 'App.vue').write_text('<script setup>const fixed = 1;</script>', encoding='utf-8')
    old = FindingNormalizer(tmp_path).make(scanner='gitleaks', category='secret',
        title='Secret fixture', description='Test', severity='HIGH', confidence='HIGH',
        file_path='App.vue', line=1, rule_id='fixture-secret-detector')
    old.technical_details.update(engine='gitleaks', rule_version='1.0.0', rule_pack_checksum='a' * 64)
    adapter = GitleaksAdapter()
    run = ScannerRun('gitleaks', 'fixture', 'SUCCESS', 0, coverage_contract='FULL', provider='gitleaks')

    def scan(context, normalizer):
        scanner_process_observed()
        return [], run

    with patch.object(adapter, 'scan', side_effect=scan), \
            patch('security_runtime.secret_coverage.covers', return_value=True) as receipt:
        result = verify(tmp_path, old, adapter)
        family, = family_multiset([old], [run], {}).values()
        assert covered(family, [run], {})
    assert receipt.call_count == 2
    assert result['status'] == 'RESOLVED'
    assert result['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
