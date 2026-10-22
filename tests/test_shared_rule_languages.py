"""Shared JS/TS execution rules retain distinct file and language coverage."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from security_runtime.rule_catalog import RuleRecord, validate_rule
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import RulePackManager, FIRST_PARTY_RULE_PACK


def shared_pack():
    rule = RuleRecord('test.shared', 'javascript', ('javascript','typescript'),
        'code', ('CWE-78',), 'ERROR', 'HIGH', 'BETA', 'Node.js', 'custom',
        '1.0.0', (), {}, 'taint', 'shared.yml', ('.js','.jsx','.ts','.tsx'))
    return SimpleNamespace(catalog=(rule,), program=None,
        descriptor=SimpleNamespace(bundled=False, rule_pack_id='custom', version='1.0.0'), checksum='test')


@pytest.mark.parametrize('target,language', [('app.js','javascript'),('view.jsx','javascript'),('app.ts','typescript'),('view.tsx','typescript')])
def test_shared_rule_selected_and_proven_for_each_language(target, language):
    plan = plan_rules(shared_pack(), [target])
    assert len(plan.rules) == 1 and plan.files == (target,)
    plan.observe({'time':{'rules':['test.shared']},'paths':{'scanned':[target]}}, plan.files)
    row = plan.coverage('SUCCESS')
    assert row['total_selected'] == row['total_executed'] == 1
    assert row['per_language'][language]['status'] == 'EXECUTED'


def test_two_languages_share_rule_identity_but_need_both_file_proofs():
    plan = plan_rules(shared_pack(), ['app.js','app.ts'])
    plan.observe({'time':{'rules':['test.shared']},'paths':{'scanned':['app.js']}}, plan.files)
    coverage = plan.coverage('SUCCESS')
    assert coverage['total_selected'] == coverage['total_executed'] == 1
    assert coverage['per_language']['javascript']['status'] == 'EXECUTED'
    assert coverage['per_language']['typescript']['status'] == 'FAILED'
    assert coverage['status'] == 'PARTIAL'


def test_unsupported_vue_is_not_hidden_beside_supported_javascript():
    plan = plan_rules(shared_pack(), ['app.js','component.vue'])
    assert plan.files == ('app.js','component.vue')
    plan.observe({'time':{'rules':['test.shared']},'paths':{'scanned':['app.js']}}, plan.files)
    coverage = plan.coverage('SUCCESS')
    assert coverage['per_language']['javascript']['target_files'] == 1
    assert coverage['per_language']['vue']['status'] == 'NOT_COVERED'
    assert coverage['status'] == 'PARTIAL'


def test_rule_release_preserves_versions_of_unchanged_rules():
    import yaml
    pack = RulePackManager().resolve()
    rule = yaml.safe_load((pack.path/'java/trust-all-hostname.yml').read_text(encoding='utf-8'))['rules'][0]
    assert rule['metadata']['rule_version'] == '1.1.0'
    assert pack.descriptor.version == '1.6.0'
    validate_rule(rule, pack.descriptor)
    for version in ('', 'latest', '1.2', '1.2.3-extra', 123, '1234567.1.0'):
        rule['metadata']['rule_version'] = version
        with pytest.raises(ValueError, match='Rule version invalid'):
            validate_rule(rule, pack.descriptor)
