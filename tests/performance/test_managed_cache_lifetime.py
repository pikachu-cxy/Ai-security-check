"""Opt-in real engines, not deterministic timing substitutes."""
import os
from pathlib import Path
import subprocess
import sys
import json

import pytest

pytestmark = pytest.mark.skipif(os.getenv('SECURITY_RUNTIME_PERFORMANCE_BENCHMARK') != '1',
                               reason='Explicit managed real Scanner benchmark environment required')


def test_real_managed_three_edits_rebuilt_cache_and_five_target_batch(tmp_path):
    root = Path(__file__).resolve().parents[2]
    output = tmp_path/'result.json'
    subprocess.run([sys.executable, str(root/'scripts/cache_lifetime_benchmark.py'), '--output', str(output)],
                   check=True, capture_output=True, timeout=180)
    data = json.loads(output.read_text())
    assert data['status'] == 'PASS' and data['kind'] == 'ACTUAL_MANAGED_SCANNER'
    scans = data['samples'][:6]
    identities = {row['diagnostics']['runtime_instance_id'] for row in scans}
    assert len(identities) == 1
    for provider in ('semgrep', 'gitleaks'):
        flags = [row['diagnostics']['providers'][provider]['cache']['version_probe'] for row in scans[:3]]
        assert flags == ['MISS', 'HIT', 'HIT']
        assert scans[3]['diagnostics']['providers'][provider]['cache']['version_probe'] == 'HIT'
    for row in scans:
        secret = row['diagnostics']['providers']['gitleaks']
        assert secret['invocation_count'] == 1
    assert scans[4]['diagnostics']['providers']['gitleaks']['scope']['target_files'] == 5
    recheck = data['samples'][-1]['scanner_runs'][0]
    assert recheck['engine_process_observed'] and recheck['scanner_diagnostics']['scope']['rules'] == 1
    assert recheck['scanner_diagnostics']['cache']['version_probe'] == 'HIT'
    assert not recheck['scanner_diagnostics']['scope']['scanner_results_reused']


def test_real_gitleaks_batch_preserves_per_file_findings_and_redaction(tmp_path, monkeypatch):
    from security_runtime.toolchain import ToolManager, ToolSource
    from security_runtime.scanners import GitleaksAdapter
    from security_runtime.models import ScanContext, ScanMode
    from security_runtime.findings import FindingNormalizer
    manager = ToolManager(); tool = manager.ensure('gitleaks', offline=True)
    assert tool.source == ToolSource.MANAGED and tool.status == 'READY'
    root = tmp_path/'project'; root.mkdir()
    names = ('src/A.java', 'notes/one.txt', 'notes/two.txt', 'README.md', 'settings.properties')
    # Synthetic detector canary; never an active credential and never exported.
    token = 'ghp_'+'aB3dE5gH7jK9mN2pQ4sT6vW8yZ1cD3fG5hJ7'
    for index, name in enumerate(names):
        path = root/name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f'ordinary line\n'+(f'credential = "{token}"\n' if index in (1,3) else 'ordinary content\n'))
    (root/'unrelated.txt').write_text(token)
    context = ScanContext(str(root), ScanMode.QUICK, names)
    adapter = GitleaksAdapter(manager); normalizer = FindingNormalizer(root)
    original = {name:(root/name).read_bytes() for name in names}
    per_file = adapter._scan_targets(tool.path, [str(root/name) for name in names], context, normalizer)
    batched, run = adapter.scan(context, normalizer)
    coordinates = lambda findings: {(f.file_path, f.line_start, f.technical_details['rule_id']) for f in findings}
    assert len(per_file) >= 2 and coordinates(batched) == coordinates(per_file)
    assert run.status == 'SUCCESS' and run.scanner_diagnostics['invocation_count'] == 1
    assert all(f.evidence == '[REDACTED_SECRET]' for f in batched)
    assert token not in json.dumps(run.scanner_diagnostics)
    assert all((root/name).read_bytes() == value for name,value in original.items())
