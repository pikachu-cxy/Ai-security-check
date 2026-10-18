"""Reproducible local synthetic architecture measurements, never desktop acceptance.

First reads and fresh processes are reported honestly; this does not flush OS
caches or simulate real host/model latency. No target code or scanner runs.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import time

from security_runtime import scan_history_index as history
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore
from security_runtime.scan_request import ScanRequest, SourceKind
from security_runtime.scan_input import capture_scan_input


def measured(fn, count):
    values = []
    for _ in range(count):
        started = time.perf_counter()
        fn()
        values.append((time.perf_counter()-started)*1000)
    ordered = sorted(values)
    return dict(n=count, p50_ms=round(statistics.median(values), 3),
        p95_ms=round(ordered[math.ceil(.95*count)-1], 3),
        minimum_ms=round(ordered[0], 3), maximum_ms=round(ordered[-1], 3))


def legacy_latest(path, workspace):
    with closing(sqlite3.connect(path)) as db:
        for row in db.execute('SELECT data FROM scans ORDER BY rowid DESC'):
            value = json.loads(row[0])
            if Path(value['target_profile']['path']).resolve() == workspace.resolve():
                return value


def run(samples=25, sizes=(1000, 10000)):
    report = dict(contract='architecture-local-benchmark-v1', platform=platform.system(),
        python=platform.python_version(), scope='SYNTHETIC_LOCAL_NO_SCANNERS_NO_DESKTOP',
        percentile_note='Observed nearest-rank samples; OS caches are not flushed; no population latency guarantee.',
        history=[], fixed_inputs=[])
    with tempfile.TemporaryDirectory(prefix='architecture-measure-') as temporary:
        base = Path(temporary).resolve()
        for count in sizes:
            path = base / ('history-'+str(count)+'.db')
            wanted, other = base/'wanted', base/'other'
            values = [dict(scan_id='wanted', target_profile=dict(path=str(wanted)), findings=[])]
            values += [dict(scan_id='other-'+str(n), target_profile=dict(path=str(other)),
                            findings=[], synthetic_padding='x'*512) for n in range(count-1)]
            with closing(sqlite3.connect(path)) as db, db:
                db.execute('CREATE TABLE scans (id TEXT PRIMARY KEY,data TEXT NOT NULL)')
                db.executemany('INSERT INTO scans VALUES (?,?)', [(v['scan_id'],json.dumps(v)) for v in values])
            started = time.perf_counter()
            store = SQLiteStore(path)
            upgrade_first = (time.perf_counter()-started)*1000
            # A read during interrupted bounded backfill must remain correct.
            assert ReadOnlySQLiteStore(path).latest_scan(wanted)['scan_id'] == 'wanted'
            batches = 0
            with closing(sqlite3.connect(path)) as db:
                while db.execute("SELECT value FROM scan_history_meta WHERE name='seed_complete'").fetchone()[0] != '1':
                    with db:
                        history.reconcile(db)
                    batches += 1
            reader = ReadOnlySQLiteStore(path)
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            first = measured(lambda: reader.latest_scan(wanted), 1)
            indexed = measured(lambda: reader.latest_scan(wanted), samples)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == before
            legacy = measured(lambda: legacy_latest(path, wanted), samples)
            # The original two-value INSERT/REPLACE remains a supported writer.
            with closing(sqlite3.connect(path)) as db, db:
                value = dict(scan_id='from-old-writer', target_profile=dict(path=str(wanted)), findings=[])
                db.execute('INSERT OR REPLACE INTO scans VALUES (?,?)', ('from-old-writer',json.dumps(value)))
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            assert reader.latest_scan(wanted)['scan_id'] == 'from-old-writer'
            assert hashlib.sha256(path.read_bytes()).hexdigest() == before
            report['history'].append(dict(rows=count, upgrade_first_ms=round(upgrade_first,3),
                subsequent_backfill_batches=batches, index_first_read=first, index_subsequent=indexed,
                legacy_subsequent=legacy, read_only_unchanged=True, legacy_write_visible=True,
                sqlite_schema='ORIGINAL_TWO_COLUMN_SCANS_PRESERVED'))
        for files in (5, 100):
            workspace = base / ('source-'+str(files))
            workspace.mkdir()
            names = tuple('source'+str(n)+'.py' for n in range(files))
            for name in names:
                (workspace/name).write_text('def value():\n    return 1\n'*25, encoding='utf-8')
            request = ScanRequest(workspace, 'quick', SourceKind.WORKTREE, names)
            def capture_once():
                with capture_scan_input(request) as view:
                    assert view.check_current().state == 'CURRENT'
                assert not view.execution_root.exists()
            report['fixed_inputs'].append(dict(files=files, bytes=files*len(('def value():\n    return 1\n'*25).encode()),
                capture_validate_cleanup=measured(capture_once, samples)))
        env = dict(os.environ, SECURITY_RUNTIME_STATE_DIR=str(base/'isolated-state'), SECURITY_RUNTIME_OFFLINE='1')
        def startup():
            value = subprocess.run([sys.executable, '-m', 'security_runtime.cli', '--version'],
                check=True, capture_output=True, timeout=30, env=env)
        report['fresh_cli_process'] = measured(startup, samples)
    from security_runtime.host_guidance import HOST_INSTRUCTIONS
    from security_runtime.review_skill import skill_files
    report['guidance_bytes'] = dict(mcp_core=len(HOST_INSTRUCTIONS.encode()),
        skill_core=len(skill_files()['SKILL.md']),
        detailed_workflow=len(skill_files()['references/runtime-workflow.md']))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=25)
    args = parser.parse_args()
    if args.samples < 5 or args.samples > 100:
        parser.error('samples must be between 5 and 100')
    result = run(args.samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
