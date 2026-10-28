"""Release evidence must reject hidden fallback and false completion."""
import pytest

from scripts.dependency_unavailable_acceptance import assert_dependency_gap


def payload():
    return {'status': 'PARTIAL', 'capability_results': {'DEPENDENCY_VULN': 'UNAVAILABLE'},
            'capability_details': {'DEPENDENCY_VULN': {
                'active_provider': None, 'coverage': 'NONE', 'primary_provider': 'trivy'}},
            'scanner_runs': [{'scanner': 'trivy-vuln', 'status': 'UNAVAILABLE',
                              'error_code': 'ENGINE_UNAVAILABLE'}]}


def test_explicit_primary_gap_is_accepted():
    assert_dependency_gap(payload())


@pytest.mark.parametrize('invalid', ['complete', 'fallback', 'hidden_error', 'claimed_coverage'])
def test_invalid_release_evidence_is_rejected(invalid):
    value = payload()
    if invalid == 'complete':
        value['status'] = 'COMPLETED'
    elif invalid == 'fallback':
        value['scanner_runs'].append({'scanner': 'osv-scanner', 'status': 'SUCCESS'})
    elif invalid == 'hidden_error':
        value['scanner_runs'][0]['error_code'] = ''
    else:
        value['capability_details']['DEPENDENCY_VULN']['coverage'] = 'FULL'
    with pytest.raises(AssertionError):
        assert_dependency_gap(value)
