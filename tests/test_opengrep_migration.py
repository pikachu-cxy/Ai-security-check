"""Installation/API/pack compatibility checks; no old/new efficacy comparison."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from security_runtime.engines import ON_DEMAND_ENGINES
from security_runtime.rulepacks import RulePackManager, DEFAULT_RULE_PACK, execution_rule
from security_runtime.scanners import OpenGrepAdapter, ScannerRegistry, ScanContext
from security_runtime.sast import OpenGrepEngineProvider, SASTRequest
from security_runtime.toolchain import ToolManager, VERSIONS


@pytest.fixture(scope='module')
def pack():
    return RulePackManager().resolve()


def test_default_engine_and_rules_are_replaced(pack):
    names = [a.name for a in ScannerRegistry().adapters]
    assert 'opengrep' in names and 'semgrep' not in names
    assert 'semgrep' in ON_DEMAND_ENGINES
    assert VERSIONS['opengrep'] == '1.32.0'
    assert pack.descriptor.rule_pack_id == 'opengrep-rules'
    assert len(pack.catalog) == 2007
    assert len({r.rule_id for r in pack.catalog}) == 2007
    assert pack.program is None
    assert not list(pack.path.glob('core/*'))


def test_vendored_rules_match_import_receipt(pack):
    receipt = json.loads((pack.path.parent/'opengrep_rules.json').read_text(encoding='utf-8'))
    for name, expected in receipt['sha256'].items():
        assert hashlib.sha256((pack.path/name).read_bytes()).hexdigest() == expected
    assert receipt['commit'] == pack.descriptor.version
    assert not pack.descriptor.commercial_use_allowed


def test_upstream_collisions_are_namespaced_not_dropped(pack):
    matches = [r for r in pack.catalog if r.provenance['original_rule_id'] == 'eval-detected']
    assert len(matches) > 1
    assert len({r.rule_id for r in matches}) == len(matches)


def test_user_rules_directory_keeps_original_ids(tmp_path):
    (tmp_path/'custom.yml').write_text('rules:\n- id: customer-rule\n  languages: [python]\n  message: Custom\n  severity: WARNING\n  pattern: eval(...)\n')
    custom = RulePackManager().resolve(user_path=tmp_path)
    assert custom.catalog[0].rule_id == 'customer-rule'
    assert not custom.descriptor.bundled
    assert execution_rule({'id':'customer-rule'}, 'custom.yml', custom.descriptor)['id'] == 'customer-rule'


def test_invalid_user_rules_are_not_silently_ignored(tmp_path):
    (tmp_path/'bad.yml').write_text('rules: [{id: broken}]')
    with pytest.raises(ValueError):
        RulePackManager().resolve(user_path=tmp_path)


def test_native_command_does_not_pass_removed_python_metrics_option(pack, tmp_path):
    command = OpenGrepEngineProvider().command(str(tmp_path/'opengrep.exe'), SASTRequest(tmp_path,pack,('a.py',)))
    assert '--metrics' not in command
    assert '--no-rewrite-rule-ids' in command
    assert '--disable-version-check' in command
    assert '--experimental' in command


def test_real_native_frontend_preserves_taint_paths_and_rule_errors(tmp_path):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native compatibility check')
    import subprocess
    from security_runtime.engine_environment import engine_environment
    from security_runtime.toolchain import tool_environment
    root = tmp_path/'project'; root.mkdir()
    rules = tmp_path/'rules'; rules.mkdir()
    (rules/'taint.yaml').write_text('''rules:
- id: fixture-taint
  languages: [python]
  mode: taint
  severity: ERROR
  message: User input reaches eval
  pattern-sources:
  - pattern: source(...)
  pattern-sinks:
  - pattern: eval(...)
  paths:
    exclude: [ignored.py]
''')
    text = 'def run():\n    value = source()\n    return eval(value)\n'
    (root/'sample.py').write_text(text)
    (root/'ignored.py').write_text(text)
    pack = RulePackManager().resolve(user_path=rules)
    request = SASTRequest(root, pack, ('sample.py', 'ignored.py'))
    native = OpenGrepEngineProvider().command(binary, request)
    legacy = [arg for arg in native if arg != '--experimental']
    with engine_environment('opengrep', tool_environment(Path(binary)), workspace=root) as env:
        def run(command):
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=30)
            return json.loads(result.stdout)
        old, new = run(legacy), run(native)
        assert old['results'] == new['results']
        assert len(new['results']) == 1 and new['results'][0]['path'] == 'sample.py'
        assert new['results'][0]['extra']['dataflow_trace']
        assert old['errors'] == new['errors'] == []
        assert set(old['time']['rules']) == set(new['time']['rules'])
        assert old['paths'] == new['paths']
        (rules/'taint.yaml').write_text('rules:\n- id: invalid-pattern\n  languages: [python]\n'
            '  severity: ERROR\n  message: invalid\n  pattern: "(bad"\n')
        old, new = run(legacy), run(native)
        assert old['errors'] and new['errors']
        assert {(e.get('type'), e.get('path')) for e in old['errors']} == {
            (e.get('type'), e.get('path')) for e in new['errors']}


@pytest.mark.parametrize('system,arch', [('windows','x64'),('linux','x64'),('linux','arm64'),('macos','x64'),('macos','arm64')])
def test_official_binary_manifests_are_pinned(tmp_path, monkeypatch, system, arch):
    monkeypatch.setattr('security_runtime.toolchain.platform_key', lambda:(system,arch))
    manifest = ToolManager(tmp_path).manifest('opengrep')
    assert '/opengrep/opengrep/releases/download/v1.32.0/' in manifest.download_url
    assert manifest.archive_type == 'binary' and len(manifest.sha256) == 64


def test_verified_download_survives_failed_probe_and_is_reused(tmp_path, monkeypatch):
    from dataclasses import replace
    from security_runtime.component_health import diagnosis
    from security_runtime.diagnostics import DiagnosticError
    data = b'verified test binary'
    calls = []
    class Provider:
        def download(self, manifest, destination):
            calls.append(1)
            destination.write_bytes(data)
    manager = ToolManager(tmp_path, provider=Provider())
    manifest = replace(manager.manifest('opengrep'), sha256=hashlib.sha256(data).hexdigest())
    def failed(tool, path, *, initial_install=False):
        assert initial_install
        manager._probe_diagnostics[(tool, str(path))] = diagnosis('COMPONENT_START_TIMEOUT')
        return ''
    monkeypatch.setattr(manager, '_probe_version', failed)
    with pytest.raises(DiagnosticError) as error:
        manager._install_binary(manifest)
    assert error.value.diagnostic.error_code == 'COMPONENT_START_TIMEOUT'
    monkeypatch.setattr(manager, '_probe_version', lambda *args, **kwargs: manifest.version)
    manager._install_binary(manifest)
    assert len(calls) == 1
    assert (tmp_path / 'tools' / 'opengrep' / manifest.version / 'opengrep').read_bytes() == data


def test_macos_opengrep_initial_probe_allows_cold_start(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import security_runtime.toolchain as toolchain
    timeouts = []
    monkeypatch.setattr(toolchain.sys, 'platform', 'darwin')
    monkeypatch.setattr(toolchain, 'run_process', lambda *a, **kw: (timeouts.append(kw['timeout']) or
        SimpleNamespace(returncode=0, stdout='1.32.0', stderr='')))
    manager = ToolManager(tmp_path)
    assert manager._probe_version('opengrep', tmp_path / 'opengrep', initial_install=True) == '1.32.0'
    assert manager._probe_version('opengrep', tmp_path / 'opengrep') == '1.32.0'
    assert timeouts == [120, 8]


def test_additional_languages_are_selected(pack):
    from security_runtime.rule_coverage import plan_rules
    plan = plan_rules(pack, ('a.cs','a.rb','a.rs','Dockerfile','a.py'))
    for language in ('csharp','ruby','rust','dockerfile','python'):
        assert any(language in r.engine_languages for r in plan.rules)
    assert set(plan.files) == {'a.cs','a.rb','a.rs','Dockerfile','a.py'}


def test_real_opengrep_custom_and_default_rules(tmp_path, monkeypatch):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native engine smoke check')
    from security_runtime.findings import FindingNormalizer
    monkeypatch.setenv('SECURITY_RUNTIME_OPENGREP_PATH', binary)
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')
    root = tmp_path/'project'
    root.mkdir()
    (root/'sample.py').write_text('def run(user_input):\n    return eval(user_input)\n')
    custom = tmp_path/'custom'
    custom.mkdir()
    (custom/'rule.yml').write_text('rules:\n- id: custom-eval\n  languages: [python]\n  message: Do not eval input\n  severity: ERROR\n  pattern: eval(...)\n')
    adapter = OpenGrepAdapter(ToolManager(tmp_path/'tools'))
    for rules_path in (str(custom), None):
        findings, result = adapter.scan(ScanContext(str(root),'quick',('sample.py',),rules_path=rules_path), FindingNormalizer(root))
        assert result.status == 'SUCCESS', (result.error_code,result.error,result.scanner_diagnostics)
        assert result.rule_coverage['total_executed'] > 0, result.rule_coverage
        assert findings
        assert all(f.scanner_sources == ['opengrep'] for f in findings)
        if rules_path:
            assert findings[0].technical_details['rule_id'] == 'custom-eval'


def test_real_managed_install_and_frozen_input_scan(tmp_path, monkeypatch):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native engine smoke check')
    import shutil
    import subprocess
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.storage import SQLiteStore
    from security_runtime.scan_input import scoped_request
    class LocalRelease:
        def download(self, manifest, destination):
            shutil.copyfile(binary, destination)
    manager=ToolManager(tmp_path/'tools', provider=LocalRelease())
    manager._install_binary(manager.manifest('opengrep'))
    assert manager.ensure('opengrep', offline=True).status == 'READY'
    root=tmp_path/'project'
    root.mkdir()
    subprocess.run(['git','init',str(root)], check=True, capture_output=True)
    (root/'sample.py').write_text('def run(user_input):\n    return eval(user_input)\n')
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    runtime=SecurityRuntime(registry=ScannerRegistry([OpenGrepAdapter(manager)], tool_manager=manager),
                            store=SQLiteStore(tmp_path/'scans.db'))
    result=runtime.scan(root, request=scoped_request(root,['sample.py']))
    assert result.execution_state == 'EXECUTED', result.scanner_diagnostics
    assert result.scanner_runs[0].status == 'SUCCESS', result.scanner_runs
    assert result.findings
    from dataclasses import asdict
    from security_runtime.verification import VerificationService
    original = next(f for f in result.findings if 'eval' in f.technical_details['rule_id'])
    (root/'sample.py').write_text('def run(user_input):\n    return int(user_input)\n')
    checked = VerificationService(runtime.registry).verify_many(root, [asdict(original)], asdict(result))
    assert checked[0]['status'] == 'RESOLVED', checked
    assert checked[0]['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'


def test_dockerfile_only_project_enables_sast(tmp_path):
    from security_runtime.target import TargetDetector
    (tmp_path/'Dockerfile').write_text('FROM alpine:3.20\n')
    profile = TargetDetector().detect(tmp_path)
    assert 'Dockerfile' in profile.languages
    assert OpenGrepAdapter().supports(profile, ScanContext(str(tmp_path), 'quick', ('Dockerfile',)))


def test_generic_rules_enable_plain_config_project(tmp_path):
    from security_runtime.target import TargetDetector
    (tmp_path/'nginx.conf').write_text('server {}\n')
    profile = TargetDetector().detect(tmp_path)
    assert OpenGrepAdapter().supports(profile, ScanContext(str(tmp_path), 'quick', ('nginx.conf',)))


def test_generic_catalog_does_not_invent_regex_coverage(tmp_path):
    from security_runtime.rule_coverage import plan_rules
    (tmp_path/'rule.yml').write_text('rules:\n- id: plain\n  languages: [generic]\n  message: Test\n  severity: WARNING\n  pattern: danger\n')
    pack = RulePackManager().resolve(user_path=tmp_path)
    plan = plan_rules(pack, ('Mapper.xml', 'unknown.conf'))
    assert plan.files == ('Mapper.xml',)
    plan.observe({'time': {'rules': ['plain']}, 'paths': {'scanned': ['Mapper.xml']}}, plan.files)
    assert plan.detected_languages == ('generic',)
    assert plan.coverage('SUCCESS')['status'] == 'EXECUTED'


@pytest.mark.parametrize('name,language,mode,declarations', [
    ('a.mjs', 'javascript', 'NATIVE', {'javascript'}),
    ('a.cjs', 'javascript', 'NATIVE', {'javascript'}),
    ('a.mts', 'typescript', 'TS_PROJECTION', {'javascript', 'typescript'}),
    ('a.cts', 'typescript', 'TS_PROJECTION', {'javascript', 'typescript'}),
    ('a.ts', 'typescript', 'NATIVE', {'javascript', 'typescript'}),
    ('a.tsx', 'typescript', 'NATIVE', {'javascript', 'typescript'}),
    ('a.pyi', 'python', 'NATIVE', {'python'}),
    ('a.ktm', 'kotlin', 'NATIVE', {'kotlin'}),
    ('a.phtml', 'php', 'NATIVE', {'php'}),
    ('a.tfvars', 'hcl', 'NATIVE', {'hcl'}),
    ('a.edn', 'clojure', 'NATIVE', {'clojure'}),
    ('a.C', 'cpp', 'NATIVE', set()),
    ('a.c', 'c', 'NATIVE', {'c'}),
    *[(f'a.{ext}', 'template', 'TEXT', set()) for ext in ('ejs', 'pug', 'mustache', 'hbs', 'jsp', 'erb', 'page')],
    ('a.min.js', 'javascript', 'TEXT', set()),
    *[(f'a.d.{ext}', 'typescript', 'TEXT', set()) for ext in ('ts', 'mts', 'cts')],
    ('a.unknown', None, None, set()),
])
def test_file_capability_planning(pack, name, language, mode, declarations):
    from security_runtime.rule_coverage import plan_rules
    from security_runtime.sast_file_types import file_type
    plan = plan_rules(pack, (name,))
    capability, suffix = file_type(name)
    if language is None:
        assert capability is None and not plan.files and not plan.rules
        return
    assert (capability.language, capability.mode) == (language, mode)
    assert name in plan.language_files[language]
    typed = {rule.engine_languages[0] for rule in plan.rules
             if len(rule.engine_languages) == 1 and rule.engine_languages[0] not in {'generic', 'regex'}}
    # The bundled snapshot has no C++ rule; do not route .C to C.
    if name == 'a.C':
        assert not any('c' in rule.engine_languages for rule in plan.rules)
    assert typed == declarations
    if language == 'template':
        assert plan.files == (name,) and plan.rules
        assert all(rule.has_paths and suffix in rule.target_extensions for rule in plan.rules)


def test_real_opengrep_module_batches(tmp_path, monkeypatch, pack):
    binary = os.environ.get('SECURITY_RUNTIME_TEST_OPENGREP')
    if not binary:
        pytest.skip('Set SECURITY_RUNTIME_TEST_OPENGREP for native execution acceptance')
    import subprocess
    from security_runtime.findings import FindingNormalizer
    from security_runtime import scanners
    from security_runtime.scan_input import capture_scan_input, scoped_request

    assert subprocess.check_output([binary, '--version'], text=True).strip() == '1.32.0'
    monkeypatch.setenv('SECURITY_RUNTIME_OPENGREP_PATH', binary)
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE', '1')
    root = tmp_path / 'project'
    root.mkdir()
    names = tuple(f'{kind}.{ext}' for ext in ('mjs', 'cjs', 'mts', 'cts')
                  for kind in ('positive', 'negative'))
    for name in names:
        algorithm = b'md5' if name.startswith('positive') else b'sha256'
        (root / name).write_bytes(b'const hash = crypto.createHash("' + algorithm + b'");\r\nsavePassword(hash);\r\n')
    (root / 'not-observed.mjs').write_bytes((root / 'positive.mjs').read_bytes())
    source = 'javascript/lang/security/audit/md5-used-as-password.yaml'
    eval_rule = next(rule for rule in pack.catalog if rule.path == source)
    assert eval_rule.engine_languages == ('javascript',) and not eval_rule.has_paths
    rules = tmp_path / 'rules'
    rules.mkdir()
    # Use the actual upstream rule plus a narrowly scoped local path rule.
    import yaml
    from security_runtime.rulepacks import load_rule_yaml
    base, = load_rule_yaml((pack.path / source).read_bytes())['rules']
    filtered = dict(base, id='path-bound-password', paths={'include': ['positive.mjs', '*.ts']})
    original_text = {'id': 'original-path-text', 'languages': ['regex'],
                     'paths': {'include': ['positive.mts']}, 'pattern-regex': 'createHash',
                     'message': 'Fixture text match', 'severity': 'WARNING'}
    (rules / 'test.yml').write_text(yaml.safe_dump({'rules': [base, filtered, original_text]}), encoding='utf-8')
    adapter = OpenGrepAdapter(ToolManager(tmp_path / 'tools'))
    resolved = RulePackManager().resolve(user_path=rules)
    calls = []
    real_execute = scanners._execute

    def execute(args, cwd, timeout):
        calls.append(tuple(args[args.index('--no-git-ignore')+1:]))
        assert '--scan-unknown-extensions' not in args
        return real_execute(args, cwd, timeout)

    monkeypatch.setattr(scanners, '_execute', execute)
    with capture_scan_input(scoped_request(root, list(names))) as view:
        context = ScanContext(str(view.execution_root), 'quick', names, input_view=view,
                              logical_root=str(root), bound_rule_pack=resolved)
        plan = adapter.plan_rules(None, context)
        findings, run = adapter.scan(replace(context, rule_plan=plan),
                                     FindingNormalizer(view.execution_root, identity_root=root))
    assert run.status == 'SUCCESS', (run.error_code, run.scanner_diagnostics)
    assert set((f.file_path, f.technical_details['rule_id']) for f in findings) == {
        *((name, base['id']) for name in names if name.startswith('positive')),
        ('positive.mjs', 'path-bound-password'),
        ('positive.mts', 'original-path-text'),
    }
    assert len(calls) == 3
    assert set(calls[0]) == {name for name in names if name.endswith(('.mjs', '.cjs'))}
    assert set(calls[1]) == {name for name in names if name.endswith(('.mts', '.cts'))}
    assert len(calls[2]) == 4 and all(Path(name).suffix == '.ts' for name in calls[2])
    assert all(not Path(name).exists() for name in calls[2])
    for finding in findings:
        locator = finding.technical_details['evidence_locator']
        assert locator['file_sha256'] == hashlib.sha256((root / finding.file_path).read_bytes()).hexdigest()
        if finding.technical_details['rule_id'] == 'original-path-text':
            assert finding.line_start == 1 and locator['start_column'] == 21
        else:
            assert finding.line_start == 2 and locator['start_column'] == 1
    catalog = {rule.rule_id: rule for rule in resolved.catalog}
    original, path_bound = catalog[base['id']], catalog['path-bound-password']
    assert original.rule_id == base['id']
    assert plan.proves(original, 'negative.mts')
    assert not plan.proves(path_bound, 'positive.cjs')
    assert not plan.proves(path_bound, 'positive.mts')
    assert run.rule_coverage['status'] == 'PARTIAL'
    assert {row['path'] for row in run.rule_coverage['file_gaps']
            if row['reason'] == 'TS_PROJECTION_RULE_PATH_FILTER_UNSUPPORTED'} == {
        name for name in names if name.endswith(('.mts', '.cts'))}
