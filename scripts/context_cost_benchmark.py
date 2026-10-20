"""Repeatable synthetic transport comparison; makes no model or scanner calls."""
from __future__ import annotations

import argparse
from copy import deepcopy
import html
import json
from pathlib import Path
import subprocess
import types

from security_runtime.mcp_tools.presentation import _agent_result
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.triage_handoff import bound_handoff
from security_runtime.triage_models import RESULT_SCHEMA, INSTRUCTIONS


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def scan_fixture(files=1000, packages=2000):
    paths = [f'src/service_{index:05d}.py' for index in range(files)]
    return ScanResult('synthetic-scan', 'release', TargetProfile('/synthetic', files=paths),
        'PARTIAL', [], [
            ScannerRun('semgrep', 'synthetic', 'EXECUTED', 100,
                capabilities=('CODE_SAST',), rule_coverage=dict(status='EXECUTED',
                    total_files=files, scope_files=paths, total_selected=100, total_executed=100)),
            ScannerRun('trivy-vuln', 'synthetic', 'PARTIAL', 100,
                capabilities=('DEPENDENCY_VULN',), coverage_contract='PARTIAL',
                coverage_notes=['Complete dependency graph is not attested.'],
                dependency_inventory=dict(package_occurrences=packages, unique_packages=packages,
                    complete_dependency_graph_attested=False, package_coordinates=[
                        dict(ecosystem='pypi', package=f'synthetic-package-{index:05d}',
                            version='1.0.0') for index in range(packages)]))],
        'No findings; dependency coverage incomplete.', 'REVIEW', 200, coverage='PARTIAL')


def handoff_fixture():
    text = '\n'.join(f'{index:03d}: synthetic source for a bounded shared evidence window'
                     for index in range(100))
    packets = []
    for index in range(5):
        packets.append(dict(finding_id=f'synthetic-{index}', context_hash=f'{index:064x}',
            context=[dict(file='synthetic.py', start_line=1, end_line=100,
                          trust='UNTRUSTED_CODE', text=text)], related_evidence=[]))
    return dict(scan_id='synthetic-scan', packets=packets, selected=5, remaining=0,
                errors=[], cached_finding_ids=[], retained_finding_ids=[],
                deferred_failed_finding_ids=[], required_output_schema=RESULT_SCHEMA,
                triage_instructions=INSTRUCTIONS)


def restored_packets(data):
    packets = deepcopy(data['packets'])
    for packet in packets:
        for field in ('context', 'related_evidence'):
            for item in packet[field]:
                reference = item.pop('shared_evidence_ref', None)
                if reference is not None:
                    source = data['shared_evidence'][reference]
                    start = item['start_line'] - source['start_line']
                    end = item['end_line'] - source['start_line'] + 1
                    item['text'] = '\n'.join(source['text'].split('\n')[start:end])
    return packets


def compare(baseline_ref):
    baseline_commit = subprocess.run(['git', 'rev-parse', '--verify', f'{baseline_ref}^{{commit}}'],
        check=True, capture_output=True, text=True).stdout.strip()
    source = subprocess.run(['git', 'show', f'{baseline_commit}:src/security_runtime/mcp_tools/presentation.py'],
        check=True, capture_output=True, text=True, encoding='utf-8').stdout
    baseline = types.ModuleType('security_runtime.mcp_tools._cost_baseline')
    baseline.__package__ = 'security_runtime.mcp_tools'
    exec(compile(source, '<committed-baseline-presentation>', 'exec'), baseline.__dict__)
    result = scan_fixture()
    old = baseline._agent_result(result)
    old.pop('findings', None)  # The old explicit summary=True path only removed findings.
    new = _agent_result(result, summary=True)
    assert old['status'] == new['status'] == 'PARTIAL'
    assert old['coverage'] == new['coverage'] == 'PARTIAL'
    assert new['finding_count'] == len(old.get('findings', [])) == 0
    assert new['scanner_runs'][1]['dependency_inventory']['complete_dependency_graph_attested'] is False
    handoff = handoff_fixture()
    projected = bound_handoff(handoff, 65_536)
    assert restored_packets(projected) == handoff['packets']
    assert projected['remaining'] == 0 and len(projected['packets']) == 5
    cases = []
    for name, before, after, meaning in (
        ('zero_findings_1000_files_2000_packages', old, new,
         'Same zero findings, scanner statuses and incomplete dependency coverage; inventories stay local.'),
        ('five_findings_identical_source_window', handoff, projected,
         'Five complete evidence packets, hashes and allowed ranges preserved; source excerpt shared once.'),
    ):
        before_bytes, after_bytes = len(encoded(before)), len(encoded(after))
        cases.append(dict(scenario=name, baseline_bytes=before_bytes, candidate_bytes=after_bytes,
            saved_bytes=before_bytes-after_bytes,
            reduction_percent=round(100*(before_bytes-after_bytes)/before_bytes, 2),
            contract_check='PASS', meaning=meaning))
    return dict(schema_version=1, kind='SYNTHETIC_TRANSPORT_COMPARISON', baseline_commit=baseline_commit,
        actual_model_tokens=None, actual_model_token_savings=None,
        caveat='UTF-8 compact JSON bytes, not model input tokens or billing. No model, scanner or network calls.',
        scenarios=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', default='3925babaf57aea2de9096c15a1f7b4739e3b443c')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = compare(args.baseline)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    rows = ''.join('<tr><td>'+html.escape(row['scenario'])+'</td><td>'+str(row['baseline_bytes'])+
        '</td><td>'+str(row['candidate_bytes'])+'</td><td>'+str(row['reduction_percent'])+'%</td></tr>'
        for row in report['scenarios'])
    args.output.with_suffix('.html').write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
        '<title>上下文数据量对比</title><style>body{font:16px system-ui;max-width:1000px;margin:48px auto;'
        'line-height:1.6}td,th{padding:12px;border-bottom:1px solid #ddd;text-align:left}</style>'
        '<h1>优化前后：固定合成场景</h1><p>数值是 UTF-8 JSON 字节。实际模型 token 节省：尚无实测数据。</p>'
        '<table><tr><th>场景</th><th>优化前 bytes</th><th>优化后 bytes</th><th>减少</th></tr>'+rows+
        '</table><p>扫描覆盖状态、待复核成员、证据哈希和允许引用范围均经校验。无模型、扫描或网络调用。</p></html>',
        encoding='utf-8')
    print(json.dumps(report, ensure_ascii=True))


if __name__ == '__main__':
    main()
