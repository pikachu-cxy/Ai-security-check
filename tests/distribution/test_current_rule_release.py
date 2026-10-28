"""Real default-rule release gate after retirement of ai-security-core.

Synthetic Python, JavaScript, TypeScript and Vue sources are never executed.
Pinned catalog bytes are checked by test_opengrep_migration in the same gate.
"""
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.scanners import OpenGrepAdapter
from security_runtime.verification_policy import local_recheck


def test_current_rules_detect_and_clear_each_supported_script_projection(tmp_path):
    cases = {
        'sample.py': ('def run(value):\n    return eval(value)\n', 'def run(value):\n    return value\n',
                      'python.lang.security.audit.eval-detected.eval-detected'),
        'sample.js': ('function run(value) { return eval(value); }\n', 'function run(value) { return value; }\n',
                      'javascript.browser.security.eval-detected.eval-detected'),
        'sample.ts': ('function run(value: string) { return eval(value); }\n', 'function run(value: string) { return value; }\n',
                      'javascript.browser.security.eval-detected.eval-detected'),
        'sample.vue': ('<script>function run(value) { return eval(value); }</script>\n',
                       '<script>function run(value) { return value; }</script>\n',
                       'javascript.browser.security.eval-detected.eval-detected'),
    }
    adapter = OpenGrepAdapter()
    for vulnerable in (True, False):
        for name, (positive, negative, _) in cases.items():
            (tmp_path / name).write_text(positive if vulnerable else negative, encoding='utf-8')
        with local_recheck():
            findings, run = adapter.scan(ScanContext(str(tmp_path), ScanMode.FEATURE, tuple(cases)), FindingNormalizer(tmp_path))
        assert run.status == 'SUCCESS', run
        assert run.rule_coverage['total_executed'] > 0, run.rule_coverage
        found = {(finding.file_path.replace('\\', '/'), finding.technical_details['rule_id']) for finding in findings}
        expected = {(name, values[2]) for name, values in cases.items()}
        if vulnerable:
            assert expected <= found, (expected - found, found)
        else:
            assert not expected & found, found
