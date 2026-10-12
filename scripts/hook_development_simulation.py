"""Exercise the real global MCP Hook handler on a disposable project copy.

These are synthetic host events, NOT proof of Codex Desktop automatic dispatch.
Only generated fixture files in the copy are edited. No application is started.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

EXCLUDED = {'.git', '.codex', '.cursor', '.agents', '.codebuddy', '.workbuddy',
            'node_modules', 'dist', 'build', 'target', '.venv', '__pycache__',
            '.security-runtime', 'coverage', '.next', '.tools'}
MAX_FILES, MAX_BYTES = 5000, 100_000_000
BINARY_DOCUMENT_EXTENSIONS = {'.docx', '.xlsx', '.pptx', '.pdf', '.png', '.jpg', '.jpeg',
                              '.gif', '.bmp', '.ico', '.woff', '.woff2'}


def copy_sources(source, destination, exclude_binary_documents=False):
    count, size = 0, 0
    originals = {}
    for directory, subdirs, names in os.walk(source, followlinks=False):
        subdirs[:] = sorted(name for name in subdirs if name not in EXCLUDED
                           and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or name.startswith('.env') or path.suffix in {'.db', '.sqlite', '.log'}:
                continue
            if exclude_binary_documents and path.suffix.lower() in BINARY_DOCUMENT_EXTENSIONS:
                continue
            count += 1
            size += path.stat().st_size
            if count > MAX_FILES or size > MAX_BYTES:
                raise ValueError('COPY_LIMIT_EXCEEDED: select a smaller project directory')
            content = path.read_bytes()
            relative = path.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            originals[relative.as_posix()] = hashlib.sha256(content).hexdigest()
    return originals, size


def response_data(response):
    value = response.structuredContent
    if value is None:
        value = json.loads(next(item.text for item in response.content if item.type == 'text'))
    if response.isError:
        raise RuntimeError('MCP rejected a synthetic test call')
    return value.get('result', value)


async def run(args):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    source = args.project.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    output = args.output.absolute()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('Test output must be separate from the original project')
    if output.exists():
        raise ValueError('Output already exists; choose a new directory')
    output.mkdir(parents=True)
    project = output / 'project'
    project.mkdir()
    originals, size = copy_sources(source, project, args.exclude_binary_documents)
    print(f'Copied {len(originals)} files / {size} bytes. Original project is read-only.', flush=True)
    fixtures = project / 'security-hook-test'
    fixtures.mkdir(exist_ok=False)
    for number in range(20):
        (fixtures / f'fixture_{number:02}.ts').write_text(f'export const fixture{number} = 0;\n', encoding='utf-8')
    (fixtures / 'canary.txt').write_text('Synthetic secret test is disabled.\n', encoding='utf-8')
    git = shutil.which('git')
    if not git:
        raise ValueError('Git is required for a repeatable dirty-file test')
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('SECURITY_RUNTIME_', 'TRIVY_', 'GITLEAKS_', 'SEMGREP_', 'OSV_'))
                   and key not in {'CODEX_HOME', 'PYTHONPATH', 'PYTHONHOME'}}
    environment.update(CODEX_HOME=str(output / 'codex-home'),
        SECURITY_RUNTIME_CODEX_HOME=str(output / 'codex-home'),
        SECURITY_RUNTIME_SKILLS_DIR=str(output / 'skills'),
        SECURITY_RUNTIME_STATE_DIR=str(output / 'state'),
        SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_WORKSPACE='',
        SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_DATA_DIR=str(args.data_dir.resolve()),
        SECURITY_RUNTIME_TRIVY_CACHE_DIR=str(args.data_dir.resolve() / 'cache/trivy'),
        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(output / 'empty-gitconfig'))
    (output / 'empty-gitconfig').write_text('', encoding='utf-8')
    no_hooks = output / 'no-hooks'
    no_hooks.mkdir()
    def git_run(*arguments):
        subprocess.run([git, '-c', 'core.hooksPath=' + str(no_hooks), '-c', 'commit.gpgsign=false',
                        '-C', str(project), *arguments], env=environment,
                       stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=45)
    if args.workspace_kind == 'git':
        git_run('init', '-b', 'codex/hook-simulation', '--quiet')
        git_run('config', 'user.name', 'Local Hook simulation')
        git_run('config', 'user.email', 'fixture@example.invalid')
        git_run('add', '--all')
        git_run('commit', '-m', 'Disposable source snapshot and safe fixtures', '--quiet')
    setup = subprocess.run([str(runtime), 'setup', 'codex', '--json'], env=environment,
                           capture_output=True, stdin=subprocess.DEVNULL, timeout=120)
    if setup.returncode or json.loads(setup.stdout).get('overall') != 'CONFIGURED':
        raise RuntimeError('Isolated global setup failed; original Codex configuration was not changed')
    records = []
    session_id = 'synthetic-' + uuid.uuid4().hex
    turn_id = 'simulation-turn'
    sequence = 0
    async with stdio_client(StdioServerParameters(command=str(runtime), args=['mcp'],
            env=environment, cwd=str(project)), errlog=(output / 'mcp-private-stderr.log').open('w', encoding='utf-8')) as (reader, writer):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=130)) as client:
            await client.initialize()
            info = response_data(await client.call_tool('get_runtime_info', {}))
            deadline = time.monotonic() + 120
            while True:
                value = response_data(await client.call_tool('handle_readiness_event',
                    {'event':'SessionStart', 'workspace_path':str(project), 'session_id':session_id}))
                state = value.get('workspace_readiness', {}).get('status', value.get('status'))
                if state == 'READY':
                    break
                if state != 'INITIALIZING' or time.monotonic() > deadline:
                    report = {'result':'NEEDS_REVIEW', 'failure_stage':'SESSION_BASELINE',
                        'baseline_status':state, 'baseline_response':value,
                        'protocol':'REAL_GLOBAL_MCP_WITH_SYNTHETIC_HOST_EVENTS',
                        'desktop_auto_dispatch_verified':False, 'mutations_started':False,
                        'copied_files':len(originals), 'exclude_binary_documents':args.exclude_binary_documents,
                        'original_project_unchanged':all(hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
                                                       for name, digest in originals.items())}
                    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                    print('Baseline not ready:', state, '; report:', output / 'report.json', flush=True)
                    return 2
                await asyncio.sleep(.5)
            baseline_response = value
            async def event(case, tool='apply_patch', command=None):
                nonlocal sequence
                sequence += 1
                payload = {'event':'PostToolUse', 'workspace_path':str(project), 'session_id':session_id,
                           'turn_id':turn_id, 'tool_use_id':f'synthetic-call-{sequence}', 'tool_name':tool,
                           'tool_input':{'command':command} if tool == 'Bash' else {}}
                started = time.perf_counter()
                try:
                    value = response_data(await client.call_tool('handle_hook_event', payload))
                    record = {key:value.get(key) for key in ('status', 'coverage', 'last_check_status',
                        'scanner_run', 'changed_file_count', 'snapshot_file_count', 'scanner_skipped_reason',
                        'new_families', 'persisting_families', 'resolved_families', 'capabilities', 'timing_ms',
                        'host_claim_status', 'scan_id', 'reason', 'pre_snapshot_match')}
                except Exception as error:
                    record = {'status':'TRANSPORT_ERROR', 'exception_type':type(error).__name__}
                record.update(case=case, wall_seconds=round(time.perf_counter()-started, 3))
                records.append(record)
                print(case, record['status'], record.get('scanner_run'), record['wall_seconds'], 'seconds', flush=True)
                return record
            revision = 0
            def edit(numbers):
                nonlocal revision
                revision += 1
                for number in numbers:
                    (fixtures / f'fixture_{number:02}.ts').write_text(
                        f'export const fixture{number} = {revision};\n', encoding='utf-8')
            if args.scenario in {'all', 'batch'}:
                await event('read_only', tool='Bash', command='git status --short')
                edit(range(20))
                await event('one_tool_twenty_files')
                await asyncio.sleep(1.1)
                if args.scenario == 'all':
                    for number in range(10):
                        edit([number])
                        await event(f'ten_separate_tools_{number+1}')
                await asyncio.sleep(1.1)
                await event('unchanged_tool_call')
                if args.scenario == 'all':
                    edit(range(20))
                    await asyncio.gather(*(event(f'concurrent_{number+1}') for number in range(4)))
                    await asyncio.sleep(1.1)
                    await event('retry_after_concurrent')
            if args.secret_canary:
                # Fictional GitHub PAT with the documented format; never used for authentication.
                canary = 'ghp_' + hashlib.sha256(b'public synthetic token, not a credential').hexdigest()[:36]
                (fixtures / 'canary.txt').write_text('token = "' + canary + '"\n', encoding='utf-8')
                await asyncio.sleep(1.1)
                await event('fictional_secret_added')
                (fixtures / 'canary.txt').write_text('Synthetic secret removed.\n', encoding='utf-8')
                await asyncio.sleep(1.1)
                await event('fictional_secret_removed')
            stop = response_data(await client.call_tool('handle_stop_event', {'event':'Stop',
                'workspace_path':str(project), 'session_id':session_id, 'turn_id':turn_id, 'stop_hook_active':False}))
    unchanged = all(hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
                    for name, digest in originals.items())
    assert unchanged, 'Original project changed during this test; results need review'
    problems = [row for row in records if row['status'] in {'TRANSPORT_ERROR','FAILED','PARTIAL','INCONCLUSIVE'}
                or str(row['status']).startswith('WORKSPACE_') or row['wall_seconds'] >= 120]
    cases = {row['case']:row for row in records}
    checks = {}
    if args.scenario in {'all', 'batch'}:
        checks.update(read_only_skipped=cases['read_only'].get('scanner_run') is False,
            batch_scanned=cases['one_tool_twenty_files'].get('scanner_run') is True,
            unchanged_skipped=cases['unchanged_tool_call'].get('scanner_run') is False)
        if args.scenario == 'all':
            checks['separate_calls_scanned'] = all(cases[f'ten_separate_tools_{i}'].get('scanner_run') is True for i in range(1,11))
    if args.secret_canary:
        checks.update(secret_detected=(cases['fictional_secret_added'].get('new_families') or 0) > 0,
                      secret_resolved=(cases['fictional_secret_removed'].get('resolved_families') or 0) > 0)
    checks_failed = sum(value is False for value in checks.values())
    report = {'protocol':'REAL_GLOBAL_MCP_WITH_SYNTHETIC_HOST_EVENTS', 'desktop_auto_dispatch_verified':False,
        'original_project_unchanged':unchanged, 'copied_files':len(originals), 'excluded':sorted(EXCLUDED) + ['.env*', '*.db', '*.sqlite', '*.log'],
        'exclude_binary_documents':args.exclude_binary_documents,
        'runtime_build':info.get('build_identity'), 'baseline_response':baseline_response,
        'workspace_kind':args.workspace_kind, 'records':records, 'stop_status':stop.get('status'),
        'scanner_runs':sum(row.get('scanner_run') is True for row in records),
        'busy_events':sum(row['status'] == 'BUSY' for row in records), 'needs_review':len(problems) + checks_failed,
        'checks':checks, 'scenario':args.scenario,
        'result':'NEEDS_REVIEW' if problems or checks_failed else 'MEASURED_REVIEW_REQUIRED',
        'limits':'No application build, LLM, deployment or functional feature test. Stop is not a guaranteed deferred-scan queue. Cached DB can be stale. No transport timeout is not proof of security coverage.'}
    (output / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Report:', output / 'report.json', flush=True)
    return 2 if problems or checks_failed else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--data-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='New disposable directory, outside the original project')
    parser.add_argument('--secret-canary', action='store_true', help='Add and remove a fictional token in the copy only')
    parser.add_argument('--exclude-binary-documents', action='store_true', help='Explicit reduced-scope second trial; document exclusions remain untested')
    parser.add_argument('--scenario', choices=['all','batch','secret'], default='all')
    parser.add_argument('--workspace-kind', choices=['git','source-directory'], default='git')
    raise SystemExit(asyncio.run(run(parser.parse_args())))
