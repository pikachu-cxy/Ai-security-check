"""Local taint provenance must not invent dynamic execution or missing traces."""
from contextlib import contextmanager
from dataclasses import asdict
import json
import pytest
import yaml

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext
from security_runtime.processes import ProcessResult
from security_runtime.rule_coverage import plan_rules
from security_runtime.rulepacks import RulePackManager
from security_runtime.scanners import SemgrepAdapter


def scan_stub(tmp_path, monkeypatch, *, trace=None, taint=True, include_trace=False):
    root = tmp_path / 'project'
    root.mkdir()
    (root / 'route.js').write_text('const value = location.hash;\neval(value);\n', encoding='utf-8')
    rules = tmp_path / 'rules'
    rules.mkdir()
    definition = {'id': 'test.local-flow', 'languages': ['javascript'],
                  'message': 'Synthetic local flow', 'severity': 'WARNING'}
    if taint:
        definition.update(mode='taint', **{'pattern-sources': [{'pattern': 'location.hash'}],
                                         'pattern-sinks': [{'pattern': 'eval(...)'}]})
    else:
        definition['pattern'] = 'eval(...)'
    (rules / 'rules.yml').write_text(yaml.safe_dump({'rules': [definition]}), encoding='utf-8')
    pack = RulePackManager().resolve(user_path=rules)
    plan = plan_rules(pack, ('route.js',))
    context = ScanContext(str(root), 'release', ('route.js',), rules_path=str(rules), rule_plan=plan)
    commands = []

    @contextmanager
    def artifacts(*args, **kwargs):
        folder = tmp_path / 'artifacts'
        folder.mkdir(exist_ok=True)
        yield folder

    def execute(command, cwd, timeout):
        commands.append(command)
        extra = {'message': 'Synthetic local flow', 'severity': 'WARNING',
                 'metadata': {'mode': 'taint'}}  # Engine metadata cannot override the rule mode.
        if include_trace:
            extra['dataflow_trace'] = trace
        payload = {'results': [{'check_id': 'test.local-flow', 'path': 'route.js',
                               'start': {'line': 2, 'col': 1}, 'end': {'line': 2, 'col': 12},
                               'extra': extra}], 'errors': [],
                   'paths': {'scanned': ['route.js']}, 'time': {'rules': ['test.local-flow']}}
        return ProcessResult(0, json.dumps(payload), '', 1)

    monkeypatch.setattr('security_runtime.scanners._execute', execute)
    monkeypatch.setattr('security_runtime.scanners._artifacts', artifacts)
    finding, = SemgrepAdapter()._scan('never-executed-semgrep', context, FindingNormalizer(root))
    return finding, commands


def test_engine_requests_trace_without_expanding_scope(tmp_path, monkeypatch):
    finding, commands = scan_stub(tmp_path, monkeypatch)
    command, = commands
    assert command.count('--dataflow-traces') == 1
    assert command[command.index('--no-git-ignore') + 1:] == ['route.js']
    assert '--interfile' not in command and '--pro' not in command
    support = finding.technical_details['dataflow_support']
    assert support['basis'] == 'SEMGREP_TAINT_RULE'
    assert support['scope'] == 'ENGINE_LOCAL_ANALYSIS'
    assert support['runtime_execution'] is False
    assert support['cross_file_expansion'] is False


def test_actual_trace_keeps_locations_but_omits_source_and_outside_paths(tmp_path, monkeypatch):
    secret = 'syntheticPrivateTargetSourceMustNotPersist'
    trace = {
        'taint_source': ['CliLoc', {'location': {'path': str(tmp_path / 'project' / 'route.js'),
                                              'start': {'line': 1, 'col': 15}}, 'content': secret}],
        'intermediate_vars': [{'location': {'path': 'route.js', 'start': {'line': 1, 'col': 7}},
                               'content': secret}],
        'taint_sink': ['CliLoc', {'location': {'path': 'route.js', 'start': {'line': 2, 'col': 1}},
                                'content': secret}],
        'untrusted_extra': {'path': str(tmp_path / 'outside.js'), 'content': secret},
    }
    finding, _ = scan_stub(tmp_path, monkeypatch, trace=trace, include_trace=True)
    details = finding.technical_details
    assert details['dataflow_support']['trace_status'] == 'PROVIDED'
    retained = details['scanner_evidence_metadata']['dataflow_trace']
    assert retained['taint_source'][0] == 'CliLoc'
    assert retained['taint_source'][1]['location'] == {'path': 'route.js', 'start': {'line': 1, 'col': 15}}
    assert retained['intermediate_vars'][0]['location']['start']['col'] == 7
    assert retained['taint_sink'][1]['location']['start']['line'] == 2
    assert retained['untrusted_extra']['path'] == '[OUTSIDE_WORKSPACE]'
    serialized = json.dumps(asdict(finding))
    assert secret not in serialized
    assert str(tmp_path) not in json.dumps(details['scanner_evidence_metadata'])


@pytest.mark.parametrize('include_trace,trace', [(False, None), (True, None), (True, {}), (True, [])])
def test_absent_or_empty_trace_does_not_invent_source_or_edges(tmp_path, monkeypatch, include_trace, trace):
    finding, _ = scan_stub(tmp_path, monkeypatch, trace=trace, include_trace=include_trace)
    details = finding.technical_details
    assert details['dataflow_support']['trace_status'] == 'NOT_PROVIDED'
    assert not details.get('scanner_evidence_metadata', {}).get('dataflow_trace')
    assert 'dataflow_trace' not in details
    assert 'source' not in details['dataflow_support'] and 'edges' not in details['dataflow_support']


def test_over_budget_trace_is_unavailable_rather_than_fabricated(tmp_path, monkeypatch):
    finding, _ = scan_stub(tmp_path, monkeypatch, trace={'content': 'synthetic' * 4000}, include_trace=True)
    details = finding.technical_details
    assert details['scanner_evidence_metadata']['availability'] == 'SCANNER_METADATA_BUDGET_EXCEEDED'
    assert details['dataflow_support']['trace_status'] == 'NOT_PROVIDED'
    assert 'dataflow_trace' not in details['scanner_evidence_metadata']


def test_structural_rule_never_claims_taint_from_engine_metadata(tmp_path, monkeypatch):
    finding, _ = scan_stub(tmp_path, monkeypatch, taint=False,
                           trace={'taint_source': ['CliLoc', {'location': {'path': 'route.js'}}]},
                           include_trace=True)
    assert 'dataflow_support' not in finding.technical_details
