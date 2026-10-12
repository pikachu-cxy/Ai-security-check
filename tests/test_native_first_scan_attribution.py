"""Native attribution uses real local reads and digest-bound Git pre-edit bytes."""
from dataclasses import replace
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner
from security_runtime.findings import FindingNormalizer
from security_runtime.first_scan_attribution import (
    attribute, capture_detector, detector_observed, diagnostics, file_digest,
    native_detector_stamp,
)
from security_runtime.hook_runtime import family_multiset
from security_runtime.models import ScanContext, ScanMode


FILE = 'src/expressionEvaluator.ts'
SAFE = b'export const calculate = (expression: string) => parseArithmetic(expression);\n'
UNSAFE = b'export function calculate(expression: string) {\n  return new Function(`return (${expression});`)();\n}\n'
KEY = b'unit-test-only-attribution-key-32-bytes'


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    git(root, 'init')
    git(root, 'config', 'user.name', 'Fixture')
    git(root, 'config', 'user.email', 'fixture@example.invalid')
    target = root / FILE
    target.parent.mkdir(parents=True)
    adapter = NativeFunctionScanner()
    registry = SimpleNamespace(adapters=[adapter])
    core = SimpleNamespace(managed_registry=lambda: registry,
                           store=SimpleNamespace(key=lambda _: KEY))
    return root, target, adapter, registry, core


def committed(setup, before=SAFE):
    root, target, _, _, _ = setup
    target.write_bytes(before)
    git(root, 'add', FILE)
    git(root, 'commit', '-m', 'baseline')
    return {'file_digests': {FILE: file_digest(KEY, before)}}


def observed(setup, after=UNSAFE):
    root, target, adapter, registry, _ = setup
    target.write_bytes(after)
    context = ScanContext(str(root), ScanMode.QUICK, (FILE,))
    plan = adapter.plan_rules(None, context)
    findings, run = adapter.scan(replace(context, rule_plan=plan), FindingNormalizer(root))
    observation = {'families': family_multiset(findings, [run], {adapter.name: plan}),
                   'runs': [run], 'plans': {adapter.name: plan}}
    observation['attribution_detector'] = capture_detector(registry, observation, root)
    return observation, {FILE: file_digest(KEY, after)}


def perform(setup, previous, observation, current):
    root, _, _, _, core = setup
    result = {**diagnostics(), 'scanner_invocation_count': 1}
    families = attribute(core, root, previous, {FILE}, current, observation, result)
    return families, result


def test_new_native_risk_requires_actual_equivalent_pre_edit_scan(setup):
    previous = committed(setup)
    observation, current = observed(setup)
    assert detector_observed(observation['attribution_detector'], observation, {})
    families, result = perform(setup, previous, observation, current)
    assert families == {}
    assert result['first_scan_attribution_status'] == 'FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert result['pre_edit_targeted_scan_run']
    assert result['pre_edit_targeted_scan_count'] == 1
    assert result['pre_existing_risk_count'] == 0
    assert result['newly_attributed_risk_count'] == 1
    assert result['attribution_scanner_equivalent']
    assert result['scanner_invocation_count'] == 2
    assert setup[1].read_bytes() == UNSAFE


def test_existing_native_risk_and_exact_line_motion_are_not_new(setup):
    previous = committed(setup, UNSAFE)
    observation, current = observed(setup, b'// unrelated edit\n\n' + UNSAFE)
    families, result = perform(setup, previous, observation, current)
    assert len(families) == 1
    assert result['first_scan_attribution_status'] == 'FIRST_SCAN_EXISTING_RISK'
    assert result['pre_existing_risk_count'] == 1
    assert result['newly_attributed_risk_count'] == 0


def test_changed_existing_sink_is_inconclusive_instead_of_new(setup):
    previous = committed(setup, UNSAFE)
    observation, current = observed(setup, UNSAFE.replace(b'  return', b'   return'))
    families, result = perform(setup, previous, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'OCCURRENCE_IDENTITY_UNPROVEN'
    assert result['first_scan_attribution_status'] == 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'


def test_hmac_mismatched_original_bytes_do_not_guess_git_baseline(setup):
    previous = committed(setup)
    previous['file_digests'][FILE] = file_digest(KEY, SAFE + b'// not committed\n')
    observation, current = observed(setup)
    families, result = perform(setup, previous, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'NO_TRUSTED_PRE_EDIT_BYTES'
    assert not result['pre_edit_targeted_scan_run']


def test_no_authenticated_pre_edit_digest_is_inconclusive(setup):
    committed(setup)
    observation, current = observed(setup)
    families, result = perform(setup, {'file_digests': {}}, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'TARGET_IDENTITY_NOT_PROVEN'


def test_stale_current_bytes_are_rejected_before_pre_edit_scan(setup):
    previous = committed(setup)
    observation, current = observed(setup)
    setup[1].write_bytes(UNSAFE + b'// concurrent change\n')
    families, result = perform(setup, previous, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'SOURCE_CHANGED_DURING_ATTRIBUTION'
    assert not result['pre_edit_targeted_scan_run']


@pytest.mark.parametrize('mismatch', ['checksum', 'provider', 'version', 'coverage', 'missing_implementation'])
def test_rule_and_provider_mismatches_fail_closed(setup, monkeypatch, mismatch):
    previous = committed(setup)
    observation, current = observed(setup)
    root, _, _, registry, _ = setup
    plan = observation['plans']['native-js-function']
    run = observation['runs'][0]
    if mismatch == 'checksum':
        observation['plans']['native-js-function'] = replace(plan, pack=replace(plan.pack, checksum='0' * 64))
    elif mismatch == 'provider':
        run.provider = 'different-provider'
    elif mismatch == 'version':
        run.version = '2.0.0'
    elif mismatch == 'coverage':
        plan.scanned_files.clear()
    else:
        import security_runtime.dynamic_function as module
        monkeypatch.setattr(module, '__file__', str(root / 'missing-provider.py'))
    assert capture_detector(registry, observation, root) is None
    # Keep the original stamped observation: attribute must independently recheck.
    families, result = perform(setup, previous, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'DETECTOR_NOT_EQUIVALENT'
    assert result['attribution_scanner_equivalent'] is False


def test_mixed_provider_family_cannot_use_native_attribution(setup):
    previous = committed(setup)
    observation, current = observed(setup)
    next(iter(observation['families'].values()))['scanner_sources'].append('semgrep')
    families, result = perform(setup, previous, observation, current)
    assert families is None
    assert result['first_scan_attribution_reason'] == 'DETECTOR_NOT_EQUIVALENT'


@pytest.mark.parametrize('encoding', ['CRLF', 'BOM'])
def test_original_bytes_are_authenticated_without_normalizing_scanned_input(setup, encoding):
    before, after = SAFE, UNSAFE
    if encoding == 'CRLF':
        before, after = before.replace(b'\n', b'\r\n'), after.replace(b'\n', b'\r\n')
    else:
        before, after = b'\xef\xbb\xbf' + before, b'\xef\xbb\xbf' + after
    previous = committed(setup, before)
    observation, current = observed(setup, after)
    families, result = perform(setup, previous, observation, current)
    assert families == {}
    assert result['first_scan_attribution_status'] == 'FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert setup[1].read_bytes() == after
