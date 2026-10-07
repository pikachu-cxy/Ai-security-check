"""Explicit offline real-engine performance diagnostic, not a fake timing test."""
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.skipif(os.getenv('SECURITY_RUNTIME_PERFORMANCE_BENCHMARK')!='1',
                    reason='Explicit managed real Scanner benchmark environment required')
def test_actual_managed_scanner_benchmark(tmp_path):
    root=Path(__file__).resolve().parents[2]
    output=tmp_path/'evidence.json'
    proc=subprocess.run([sys.executable,str(root/'scripts/scanner_hot_path_benchmark.py'),
                         '--samples','1','--output',str(output)],cwd=root,capture_output=True,
                         env=dict(os.environ,SECURITY_RUNTIME_OFFLINE='1'),timeout=180)
    assert proc.returncode==0,proc.stderr[-2000:]
    evidence=json.loads(output.read_text())
    assert evidence['kind']=='ACTUAL_MANAGED_SCANNER'
    assert all(value>0 for value in evidence['medians_ms'].values())
    for sample in evidence['samples']:
        assert any(op['phase']=='semgrep_invocation' and op['scanned_files']==1 for op in sample['operations'])
    assert not evidence['network'] and not evidence['daemon']
