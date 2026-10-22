"""New language rules must enter planning without inventing execution evidence."""
import pytest

from security_runtime.rulepacks import RulePackManager
from security_runtime.rule_coverage import plan_rules


@pytest.mark.parametrize('filename,language,count', [
    ('handler.go', 'go', 4), ('index.php', 'php', 6),
    ('browser.js', 'javascript', 9), ('browser.ts', 'typescript', 9),
])
def test_new_defaults_require_actual_engine_evidence(filename, language, count):
    plan = plan_rules(RulePackManager().resolve(), [filename])
    assert len(plan.rules) == count
    assert plan.files == (filename,)
    assert plan.coverage()['total_executed'] == 0
    plan.observe({'time': {'rules': [r.rule_id for r in plan.rules]},
                  'paths': {'scanned': [filename]}}, plan.files)
    row = plan.coverage('SUCCESS')['per_language'][language]
    assert row['status'] == 'EXECUTED'
    assert row['executed_rules'] == count


def test_mixed_languages_preserve_vue_gap_and_unique_rule_ids():
    plan = plan_rules(RulePackManager().resolve(),
                      ['handler.go', 'index.php', 'app.js', 'app.ts', 'App.vue'])
    assert len(plan.rules) == 19  # JS and TS share nine identities.
    assert 'App.vue' in plan.files
    plan.observe({'time': {'rules': [r.rule_id for r in plan.rules]},
                  'paths': {'scanned': list(plan.files)}}, plan.files)
    assert plan.coverage('SUCCESS')['status'] == 'PARTIAL'


def test_local_rules_still_replace_bundled_selection(tmp_path):
    (tmp_path / 'local.yml').write_text('''rules:
- id: local.php.danger
  languages: [php]
  severity: WARNING
  message: Local policy
  pattern: dangerous(...)
''', encoding='utf-8')
    pack = RulePackManager().resolve(user_path=tmp_path)
    plan = plan_rules(pack, ['index.php', 'handler.go'])
    assert [r.rule_id for r in plan.rules] == ['local.php.danger']
    assert plan.files == ('index.php',)
