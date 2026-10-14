"""Read-only source measurements; executes Runtime/scanners, never sample apps.

Samples are projections of the authorized Ai-security-check immutable archive.
No synthetic result is called a scanner result. Process-first/warm observations
do not claim that the Windows filesystem cache has been flushed.
"""
import argparse
from collections import Counter
from contextlib import contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import time
import zipfile

from security_runtime import task_security as ts
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hooks import HookEvent
from security_runtime.verification_policy import local_recheck


@contextmanager
def measured(label, rows):
    reads, hashes, counts, times = Counter(), Counter(), Counter(), Counter()
    first_reads = {}
    orig_read, orig_hash = ts.WorkspaceReader.read, ts.hash_bytes
    originals = {name: getattr(ts, name) for name in ('capture', '_inventory', 'safe_source')}
    def read(reader, path, *a, **kw):
        start = time.perf_counter()
        try:
            result = orig_read(reader, path, *a, **kw)
            reads[str(path)] += len(result[0]); counts['read'] += 1
            first_reads.setdefault(str(path), len(result[0]))
            return result
        finally:
            times['read_ms'] += (time.perf_counter()-start)*1000
    def hash_raw(raw):
        start = time.perf_counter()
        result = orig_hash(raw)
        times['hash_ms'] += (time.perf_counter()-start)*1000
        hashes[result] += len(raw)
        counts['hash'] += 1
        return result
    def wrap(name, fn):
        def call(*a, **kw):
            counts[name] += 1; start = time.perf_counter()
            try: return fn(*a, **kw)
            finally: times[name+'_ms'] += (time.perf_counter()-start)*1000
        return call
    ts.WorkspaceReader.read, ts.hash_bytes = read, hash_raw
    for name, fn in originals.items(): setattr(ts, name, wrap(name, fn))
    start = time.perf_counter()
    try: yield
    finally:
        elapsed = (time.perf_counter()-start)*1000
        ts.WorkspaceReader.read, ts.hash_bytes = orig_read, orig_hash
        for name, fn in originals.items(): setattr(ts, name, fn)
        rows.append(dict(stage=label, wall_ms=elapsed, calls=dict(counts),
                         timing_ms=dict(times), read_bytes=sum(reads.values()),
                         repeated_read_bytes=sum(reads.values())-sum(first_reads.values()),
                         read_bytes_by_path=dict(reads), hash_bytes=sum(hashes.values()),
                         task_snapshot_cache_hits=0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--archive', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--work', type=Path, required=True)
    ap.add_argument('--runs', type=int, default=3)
    ap.add_argument('--samples', nargs='+', choices=['component','full'], default=['component','full'])
    args = ap.parse_args()
    args.work = args.work.resolve()
    args.archive = args.archive.resolve()
    args.output = args.output.resolve()
    args.work.mkdir(parents=True, exist_ok=False)
    os.environ['SECURITY_RUNTIME_OFFLINE'] = '1'
    os.environ['SECURITY_RUNTIME_DATA_DIR'] = str(args.work/'data')
    os.environ['SECURITY_RUNTIME_GITLEAKS_PATH'] = str(Path.home()/'AppData/Local/AI-Security-Runtime/tools/gitleaks/8.30.0/gitleaks.exe')
    rows = []
    code_root = Path(ts.__file__).resolve().parent
    rule_hashes = {p.relative_to(code_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted((code_root/'rules').rglob('*')) if p.is_file()}
    environment = dict(machine=os.environ.get('COMPUTERNAME'),
        runtime_task_source_sha256=hashlib.sha256(Path(ts.__file__).read_bytes()).hexdigest(),
        archive_sha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
        rules_identity=ts.digest_value(rule_hashes),
        dependencies={p: importlib.metadata.version(p) for p in ('PyYAML','mcp','semgrep')},
        dependency_database='NOT_APPLICABLE_CODE_ONLY_SCOPE; no dependency evidence reused',
        offline=True, os_file_cache='UNCONTROLLED')
    for sample in args.samples:
        root = args.work/sample; root.mkdir()
        with zipfile.ZipFile(args.archive) as z:
            for name in z.namelist():
                if name.endswith('/'): continue
                if sample == 'component' and not name.startswith('src/security_runtime/'):
                    continue
                target = root/name
                if not target.resolve().is_relative_to(root.resolve()):
                    raise ValueError('Archive path outside sample root')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(z.read(name))
        for cmd in (['git','init','-q',str(root)], ['git','-C',str(root),'add','.'],
                    ['git','-C',str(root),'-c','user.name=Performance measurement',
                     '-c','user.email=measurement@example.invalid','commit','-qm','fixed baseline source']):
            subprocess.run(cmd, check=True, capture_output=True)
        target = root/'src/security_runtime/task_security.py'
        original = target.read_bytes()
        js_target = root/'src/security_runtime/assets/arithmetic_regression.mjs'
        original_js = js_target.read_bytes()
        manifest = ts.capture(root)
        project = dict(sample=sample, files=len(manifest['hashes']),
            inventory_files=len(manifest['inventory']),
            bytes=sum((root/p).stat().st_size for p in manifest['hashes']),
            manifest_sha256=ts.digest_value(manifest['hashes']),
            limitations=manifest['limitations'], languages=['Python','JavaScript'],
            sample_commit='755e411c4383003a5da54330890fb49c6f96c967')
        for n in range(args.runs):
            target.write_bytes(original)
            js_target.write_bytes(original_js)
            hooks = HookStateStore(args.work/f'state-{sample}-{n}')
            runtime = SecurityRuntime(ScannerRegistry(tool_manager=ToolManager()),
                                      SQLiteStore(args.work/f'scans-{sample}-{n}.db'))
            service = ts.TaskSecurityService(runtime, hooks)
            stages = []
            with measured('begin_inventory_hash', stages): ref = service.begin(root, f'run-{n}')['task_ref']
            target.write_bytes(original+b'\n# bounded performance measurement edit\n')
            js_target.write_bytes(original_js+b'\n// bounded performance measurement edit\n')
            with local_recheck():
                with measured('hook_static', stages):
                    hook = HookCoordinator(runtime, hooks, cooldown_ms=0).handle(
                        HookEvent.FILE_CHANGED, root, 'codex', f'run-{n}')
                with measured('finish_rescan', stages): finish = service.finish(root, ref)
                with measured('finish_idempotent', stages): retry = service.finish(root, ref)
            with measured('prepare', stages): packet = service.prepare(root, ref)
            pages = []
            if packet.get('review_session'):
                for low in (1,81,161):
                    with measured('context_page', stages):
                        pages.append(service.read(root, ref, packet['review_session'],
                                     'src/security_runtime/task_security.py', low, low+79))
                with measured('context_repeat_page', stages):
                    service.read(root, ref, packet['review_session'],
                                 'src/security_runtime/task_security.py', 1,80)
                with measured('host_partial_submission', stages):
                    service.submit(root, ref, packet['review_session'], [], 'PARTIAL',
                        ['Performance harness only; no model or semantic review; remaining source unreviewed.'])
            with measured('result_output', stages): result = service.get(root, ref)
            total_reads = Counter()
            for v in stages: total_reads.update(v['read_bytes_by_path'])
            rows.append(dict(project=project, iteration=n,
                cache_state='process_first_os_cache_uncontrolled' if not rows else 'process_warm_new_task_state',
                stages=stages, hook=hook, finish=finish, retry=retry,
                result=result, static_record=service.load(root, ref).get('static'),
                pages=[{k:p[k] for k in ('path','file_sha256','start_line','end_line')} for p in pages],
                final_file_hashes={p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in (target,js_target)},
                read_bytes_all_stages=sum(total_reads.values()),
                repeated_read_bytes_all_stages=sum(total_reads.values())-sum(
                    (root/p).stat().st_size for p in total_reads)))
            args.output.write_text(json.dumps(dict(rows=rows, environment=environment, model_tokens='NOT_MEASURED',
                model_reasoning_time='NOT_MEASURED', cache_hits='see scanner observations; task capture has no cache'),
                indent=2, ensure_ascii=False, default=str), encoding='utf-8')
        target.write_bytes(original)
        js_target.write_bytes(original_js)
    print(json.dumps([dict(sample=x['project']['sample'], iteration=x['iteration'],
        status=x['finish']['status'], stages={v['stage']:round(v['wall_ms'],2) for v in x['stages']}) for x in rows]))


if __name__ == '__main__': main()
