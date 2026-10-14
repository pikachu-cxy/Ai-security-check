"""Synthetic offline DB acceptance must retain unknown freshness and extraction proof."""
import copy

import pytest

from scripts.osv_fallback_acceptance import assert_offline_fallback


def response():
    return {'capability_results': {'DEPENDENCY_VULN': 'PARTIAL'},
            'capability_details': {'DEPENDENCY_VULN': {'active_provider': 'osv-scanner',
                'provider_role': 'FALLBACK', 'coverage': 'PARTIAL'}},
            'scanner_runs': [{'scanner': 'trivy-vuln', 'status': 'UNAVAILABLE'},
                {'scanner': 'osv-scanner', 'status': 'SUCCESS', 'coverage_contract': 'PARTIAL',
                 'coverage_notes': ['Offline vulnerability database freshness is unconfirmed'],
                 'dependency_inventory': {'vulnerability_db_freshness': 'UNKNOWN',
                     'complete_dependency_graph_attested': False,
                     'planned_manifests': 1, 'confirmed_manifests': 1,
                     'confirmed_package_occurrences': 1}}]}


def test_offline_available_fallback_keeps_unknown_freshness():
    assert_offline_fallback(response())


@pytest.mark.parametrize('change', ['full', 'failed', 'missing_manifest', 'missing_package', 'fresh', 'wrong_provider'])
def test_fallback_gate_rejects_absent_execution_inventory_and_false_freshness(change):
    data = copy.deepcopy(response())
    fallback = data['scanner_runs'][1]
    if change == 'full': data['capability_results']['DEPENDENCY_VULN'] = 'EXECUTED'
    elif change == 'failed': fallback['status'] = 'FAILED'
    elif change == 'missing_manifest': fallback['dependency_inventory']['confirmed_manifests'] = 0
    elif change == 'missing_package': fallback['dependency_inventory']['confirmed_package_occurrences'] = 0
    elif change == 'fresh': fallback['dependency_inventory']['vulnerability_db_freshness'] = 'FRESH'
    else: data['capability_details']['DEPENDENCY_VULN']['active_provider'] = 'other'
    with pytest.raises(AssertionError):
        assert_offline_fallback(data)
