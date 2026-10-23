"""Offline internal timing: security summary and real existing-test commands.

This does not run security scanners or authenticate production fix receipts.
It never feeds simulated execution results into the Runtime. Test startup and
execution are measured separately from model/UI latency, which requires a
real desktop trial.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
import timeit

from security_runtime.functional_feedback import pending_feedback
from security_runtime.functional_verifiers import PythonVerifier
from security_runtime.hook_reply_context import render_hook_context


def timing(values):
    ordered = sorted(values)
    return dict(median_ms=round(statistics.median(values), 3),
                p95_ms=round(ordered[min(len(ordered)-1, int(len(ordered)*.95))], 3),
                samples=len(values))


def measure(repeats):
    arguments = dict(task_ref='synthetic-task', remediation_ref='synthetic-ref', workspace_path='synthetic-root')
    # Personal presentation is security-only; this internal benchmark does not
    # re-enable verifier offers or authorize project execution in the product.
    iterations = 1000
    notice = [seconds * 1000 / iterations for seconds in timeit.repeat(
        lambda: pending_feedback(arguments=arguments), number=iterations, repeat=20)]
    summary = dict(status='SCANNED', coverage='FULL', scanner_run=True)
    baseline = dict(action='NONE', reason_code='SCANNER_VERIFIED_RESOLVED')
    offered = dict(baseline, **pending_feedback(arguments=arguments))
    old_message = '这个问题已修复，并通过了原规则的重新检查。'
    new_message = offered['verification_summary']['security']
    render_times = {}
    for label, decision, message in [('without_summary', baseline, old_message),
                                      ('security_summary', offered, new_message)]:
        render_times[label] = timing([elapsed * 1000 / iterations for elapsed in timeit.repeat(
            lambda: render_hook_context(summary, decision, message), number=iterations, repeat=20)])
    rendering = dict(timings=render_times, extra_context_chars=(
        len(render_hook_context(summary, offered, new_message))-
        len(render_hook_context(summary, baseline, old_message))))
    rows = []
    with tempfile.TemporaryDirectory(prefix='asr-functional-benchmark-') as folder:
        root = Path(folder)
        (root/'tests').mkdir()
        (root/'service.py').write_text('def total(values):\n    return sum(values)\n', encoding='utf-8')
        (root/'pytest.ini').write_text('[pytest]\n', encoding='utf-8')
        for i in range(16):
            name = 'service' if i == 0 else f'other_{i}'
            tests = 'from service import total\n\n' + ''.join(
                f'def test_total_{n}():\n    assert total(range({n+10})) == sum(range({n+10}))\n\n'
                for n in range(4))
            (root/'tests'/f'test_{name}.py').write_text(tests, encoding='utf-8')
        steps = PythonVerifier().detect_host(root, ('service.py',))
        if not steps or not steps[0].executable:
            return dict(notice=timing(notice), hook_rendering=rendering,
                        test_execution='LOCAL_PYTEST_UNAVAILABLE')
        selected = steps[0].argv()
        full = [*selected[:-1], 'tests']
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PIP_NO_INDEX='1')
        # Alternate order to reduce warm filesystem/startup bias.
        measurements = {'selected_existing_tests': [], 'full_existing_tests': []}
        for i in range(repeats):
            cases = [('selected_existing_tests', selected), ('full_existing_tests', full)]
            for name, command in cases if i % 2 == 0 else reversed(cases):
                started = time.perf_counter()
                run = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                     text=True, timeout=30, check=True)
                measurements[name].append((time.perf_counter()-started)*1000)
                rows.append(dict(scope=name, output=run.stdout.strip(), exit_code=run.returncode))
    return dict(notice=timing(notice), hook_rendering=rendering,
                test_execution={k: timing(v) for k,v in measurements.items()},
                observations=rows, limitations=[
                    'Synthetic 16-file suite; selected scope has 4 tests and full scope 64 tests.',
                    'Selected tests do not prove cross-module coverage; report the actual scope.',
                    'No-choice flow runs no tests; repeat verification uses existing matching result cache.',
                    'Model, network, desktop UI and real customer project latency are not measured.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--output', type=Path, required=True)
    options = parser.parse_args()
    if not 1 <= options.repeats <= 20:
        parser.error('repeats must be between 1 and 20')
    report = measure(options.repeats)
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2))
