"""Build a verified Windows repair-impact candidate using existing dependencies.

Internal product regressions only. This script never installs dependencies or a
Runtime, restarts a host, runs a target project's tests, or marks desktop acceptance.
The latest pointer is published only after every gate succeeds; failures retain a
separate run receipt and leave previous candidates unchanged.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
# Use the existing editable environment: putting src first also shadows the
# installed license-bearing dist-info with setuptools' source egg-info.
import security_runtime
if Path(security_runtime.__file__).resolve().parent != ROOT / 'src/security_runtime':
    raise SystemExit('The build environment must import this checkout through its local editable install.')

from dependency_notices import preflight
from build_standalone import STANDALONE_DOCUMENTS
from security_runtime.delivery import package_metadata
from security_runtime.hook_state import no_links

CONTRACT = 'repair-impact-v1'
TOOLS = ('prepare_repair_impact', 'read_repair_impact_context',
         'submit_repair_impact', 'get_repair_impact')
HIDDEN_TOOLS = {'prepare_functional_verification', 'run_functional_verification'}
# These are product regressions, not a new personal-edition testing capability.
REGRESSIONS = (
    'tests/test_reply_plan.py', 'tests/test_risk_decision_experience.py',
    'tests/test_feedback_contract_v2.py', 'tests/test_finding_disposition.py',
    'tests/test_task_risk_dispositions.py', 'tests/test_task_risk_feedback.py',
    'tests/test_task_fix.py', 'tests/test_task_triage.py',
    'tests/test_remediation.py', 'tests/test_remediation_episodes.py',
    'tests/test_confirmation.py', 'tests/test_agent_fix_envelope.py',
    'tests/test_agent_fix_ticket.py', 'tests/test_fix_context.py',
    'tests/test_hook_advice_feedback.py', 'tests/test_hook_user_feedback.py',
    'tests/test_hook_dispositions.py', 'tests/test_host_feedback_contract.py',
    'tests/test_host_orchestration.py', 'tests/test_codex_code_mode_contract.py',
    'tests/test_review_mcp.py', 'tests/test_review_skill.py',
    'tests/test_global_integration.py', 'tests/test_global_ownership_v2.py',
    'tests/test_global_workspace_binding.py', 'tests/test_global_workspace_root_regression.py',
    'tests/test_task_context_global_transport.py', 'tests/test_task_ownership.py',
    'tests/test_task_preimages.py', 'tests/test_task_review_revisions.py',
    'tests/test_task_review_adaptive_budget.py', 'tests/test_task_review_transport_v3.py',
    'tests/test_task_review_results.py', 'tests/test_review_evidence.py',
    'tests/test_local_evidence_comments.py', 'tests/test_post_fix_functional_prompt.py',
    'tests/test_functional_remediation.py',
    'tests/test_personal_install.py', 'tests/test_distribution.py',
    'tests/test_standalone_documents.py', 'tests/test_cli_json_encoding.py',
    'tests/test_dependency_notices.py',
)
SOURCE_PREFIXES = ('src/', 'distribution/', 'scripts/', 'tests/')
SOURCE_NAMES = {'pyproject.toml', 'LICENSE', 'EULA.md', 'LICENSING.md',
                'THIRD_PARTY_NOTICES.md', 'SOURCE_OFFER.md', 'MANIFEST.in'}
SOURCE_SUFFIXES = {'.py', '.md', '.json', '.yml', '.yaml', '.toml', '.mjs', '.c',
                   '.h', '.spec', '.txt', '.ini', '.cfg'}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value, *, replace=False):
    no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=True, indent=2) + '\n'
    if not replace:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(payload)
        return
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(payload)
        no_links(path)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def git(*arguments):
    result = subprocess.run(['git', '--no-optional-locks', '-c',
        'safe.directory=' + ROOT.as_posix(), '-c', 'core.fsmonitor=false',
        '-C', str(ROOT), *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    if len(result.stdout) > 2_000_000:
        raise ValueError('Source provenance exceeds the bounded inventory size')
    return result.stdout.decode('utf-8', errors='strict')


def source_snapshot():
    commit = git('rev-parse', 'HEAD').strip()
    if len(commit) != 40 or any(char not in '0123456789abcdef' for char in commit):
        raise ValueError('Source commit is unverifiable')
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all').split('\0')
    dirty, index = [], 0
    while index < len(status) and status[index]:
        entry = status[index]
        row = {'status': entry[:2], 'path': entry[3:]}
        index += 1
        if 'R' in row['status'] or 'C' in row['status']:
            row['original_path'] = status[index]
            index += 1
        dirty.append(row)
    names = set(git('ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0'))
    hashes, total = {}, 0
    for name in sorted(names):
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or '..' in relative.parts or ':' in name:
            if name:
                raise ValueError('Source inventory contains an unsafe path')
            continue
        selected = (name in SOURCE_NAMES or name.startswith('LICENSES/')
            or name.startswith(SOURCE_PREFIXES) and relative.suffix.lower() in SOURCE_SUFFIXES
            or name in {'docs/REPAIR_IMPACT_ACCEPTANCE.zh-CN.md',
                'docs/REPAIR_IMPACT_ASSESSMENT_PLAN.zh-CN.md',
                'docs/design/REPAIR_IMPACT_ASSESSMENT_DESIGN.zh-CN.md'}
            or name in STANDALONE_DOCUMENTS)
        if not selected:
            continue
        file = ROOT / name
        no_links(file)
        if not file.exists():
            continue  # Deleted inputs are described by the dirty inventory.
        raw = file.read_bytes()
        total += len(raw)
        if total > 50_000_000 or len(hashes) >= 5000:
            raise ValueError('Source manifest capacity exceeded')
        hashes[name] = hashlib.sha256(raw).hexdigest()
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return {'source_commit': commit, 'source_dirty': bool(dirty),
            'source_dirty_entries': dirty, 'source_files': hashes,
            'source_manifest_sha256': hashlib.sha256(encoded).hexdigest(),
            'source_file_count': len(hashes), 'source_input_bytes': total}


def same_inputs(before, after):
    if (before['source_commit'], before['source_files'], before['source_dirty_entries']) != (
            after['source_commit'], after['source_files'], after['source_dirty_entries']):
        raise ValueError('Source inputs changed during validation; preserve this run and build a new candidate')


def regression_targets():
    feature = sorted(path.relative_to(ROOT).as_posix()
                     for path in (ROOT / 'tests').glob('test_repair_impact*.py'))
    if not feature:
        raise ValueError('Repair-impact regression files are required before packaging')
    missing = [name for name in REGRESSIONS if not (ROOT / name).is_file()]
    if missing:
        raise ValueError('Required regression files are missing: ' + ', '.join(missing))
    return list(dict.fromkeys([*feature, *REGRESSIONS]))


def junit_counts(path):
    document = ET.parse(path).getroot()
    cases = list(document.iter('testcase'))
    failed = sum(case.find('failure') is not None for case in cases)
    errors = sum(case.find('error') is not None for case in cases)
    skipped = sum(case.find('skipped') is not None for case in cases)
    feature = [case for case in cases if 'repair_impact' in case.get('classname', '')]
    feature_passed = sum(not any(case.find(tag) is not None for tag in ('failure', 'error', 'skipped'))
                         for case in feature)
    return {'total': len(cases), 'passed': len(cases)-failed-errors-skipped,
            'failed': failed, 'errors': errors, 'skipped': skipped,
            'repair_impact_cases': len(feature), 'repair_impact_passed': feature_passed}


def clean_environment(profile):
    env = {name: value for name, value in os.environ.items()
           if not name.startswith('SECURITY_RUNTIME_') and name not in {'PYTHONHOME', 'PYTHONPATH'}}
    env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_OFFLINE='1',
        SECURITY_RUNTIME_INTEGRATION='codex', SECURITY_RUNTIME_HOST='codex',
        SECURITY_RUNTIME_STATE_DIR=str(profile / 'state'),
        SECURITY_RUNTIME_DATA_DIR=str(profile / 'data'),
        SECURITY_RUNTIME_CONFIG=str(profile / 'config.toml'), PYTHONUTF8='1')
    return env


def decoded_tool(result):
    if result.isError:
        raise ValueError('Frozen runtime-info returned a tool error')
    if result.structuredContent is not None:
        return result.structuredContent
    return json.loads(next(item.text for item in result.content if item.type == 'text'))


def has_contract(value, token):
    if isinstance(value, str):
        return token in value
    if isinstance(value, dict):
        return any(has_contract(item, token) for item in value.values())
    if isinstance(value, list):
        return any(has_contract(item, token) for item in value)
    return False


async def frozen_mcp(executable, env, errors):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    async with stdio_client(StdioServerParameters(command=str(executable), args=['mcp'],
        cwd=str(ROOT), env=env), errlog=errors) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=60)) as client:
            await client.initialize()
            info = decoded_tool(await client.call_tool('get_runtime_info', {}))
            rows, cursor = {}, None
            for _ in range(20):
                page = await client.list_tools(cursor=cursor)
                rows.update((tool.name, tool.inputSchema) for tool in page.tools)
                cursor = page.nextCursor
                if cursor is None:
                    break
            else:
                raise ValueError('Frozen tool list exceeded bounded pagination')
    if not set(TOOLS).issubset(rows) or HIDDEN_TOOLS.intersection(rows):
        raise ValueError('Frozen repair-impact tools missing or personal hidden tools exposed')
    for name in ('prepare_task_fix', 'confirm_remediation'):
        if 'impact_ref' not in rows.get(name, {}).get('properties', {}):
            raise ValueError('Frozen repair gate is missing impact_ref: ' + name)
    for contract in (CONTRACT, 'security-reply-plan-v1', 'risk-decisions-v2'):
        if not has_contract(info, contract):
            raise ValueError('Frozen Runtime does not advertise required contract: ' + contract)
    return {'status': 'PASSED', 'runtime_info': info,
            'tool_names': sorted(rows), 'required_tools': list(TOOLS),
            'hidden_personal_tools_absent': True, 'impact_gate_parameters_present': True,
            'scanner_run': False, 'hook_dispatch': False, 'runtime_installed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher-bundle', type=Path,
        help='Explicit verified local bundle for an unchanged launcher; no downloads or installs')
    args = parser.parse_args(argv)
    if os.name != 'nt':
        raise SystemExit('This candidate workflow targets Windows.')
    for name in ('pytest', 'PyInstaller', 'mcp'):
        if importlib.util.find_spec(name) is None:
            raise SystemExit('Existing build environment is missing ' + name + '; no dependency was installed.')
    if not any((Path(sys.base_prefix) / name).is_file() for name in ('LICENSE.txt', 'LICENSE')):
        raise SystemExit('A local CPython license is required; this workflow does not fetch build inputs.')
    dependencies = preflight()
    if args.launcher_bundle is None and not shutil.which('gcc'):
        raise SystemExit('Existing GCC or an explicit verified --launcher-bundle is required; no compiler was installed.')
    if args.launcher_bundle is not None:
        package_metadata(args.launcher_bundle)
    targets = regression_targets()
    candidate = 'repair-impact-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:6]
    run_dir = ROOT / 'artifacts' / candidate
    no_links(run_dir)
    run_dir.mkdir(parents=True, exist_ok=False)
    run_path = run_dir / 'run.json'
    receipt = {'candidate_kind': 'LOCAL_REPAIR_IMPACT_ACCEPTANCE', 'candidate': candidate,
        'created_at': stamp(), 'status': 'RUNNING', 'installed': False,
        'desktop_acceptance': 'PENDING_USER', 'repair_impact_contract': CONTRACT,
        'reply_plan_contract': 'security-reply-plan-v1', 'risk_decision_contract': 'risk-decisions-v2',
        'python': sys.executable, 'reviewed_build_dependencies': dependencies,
        'test_scope': targets, 'full_repository_suite_claimed': False,
        'acceptance_guide': 'docs/REPAIR_IMPACT_ACCEPTANCE.zh-CN.md'}
    stage = 'SOURCE_SNAPSHOT'
    try:
        snapshot = source_snapshot()
        manifest_path = run_dir / 'source-manifest.json'
        write_json(manifest_path, snapshot)
        receipt.update({key: snapshot[key] for key in
            ('source_commit', 'source_dirty', 'source_dirty_entries', 'source_manifest_sha256')})
        receipt['source_manifest'] = str(manifest_path)
        stage = 'INTERNAL_REGRESSIONS'
        started = time.perf_counter()
        xml = run_dir / 'regression.xml'
        with tempfile.TemporaryDirectory(prefix='ai-security-repair-impact-tests-') as temporary:
            command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                '--basetemp', str(Path(temporary) / 'cases'), '--junitxml', str(xml), *targets]
            result = subprocess.run(command, cwd=ROOT, check=False)
        counts = junit_counts(xml) if xml.is_file() else {}
        receipt['regression'] = {'status': 'PASSED' if result.returncode == 0 else 'FAILED',
            'exit_code': result.returncode, 'duration_seconds': round(time.perf_counter()-started, 3),
            'junit': str(xml), **counts}
        if (result.returncode or not counts.get('repair_impact_passed')
                or counts.get('failed') or counts.get('errors')):
            raise ValueError('Required internal regressions did not pass')
        same_inputs(snapshot, source_snapshot())
        stage = 'BUILD_STANDALONE'
        command = [sys.executable, str(ROOT / 'scripts/build_standalone.py'),
            '--output-dir', 'dist/' + candidate, '--work-dir', 'build/' + candidate]
        if args.launcher_bundle is not None:
            command.extend(['--launcher-bundle', str(args.launcher_bundle.resolve(strict=True))])
        with (run_dir / 'build.log').open('w', encoding='utf-8') as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        bundle = ROOT / 'dist' / candidate / 'security-check'
        executable = bundle / 'security-check.exe'
        stage = 'PACKAGE_INTEGRITY'
        metadata = package_metadata(bundle)
        same_inputs(snapshot, source_snapshot())
        if (metadata['source_commit'] != snapshot['source_commit']
                or metadata['source_dirty'] != snapshot['source_dirty']):
            raise ValueError('Bundle commit differs from the validated source')
        stage = 'FROZEN_IDENTITY_AND_TOOLS'
        with tempfile.TemporaryDirectory(prefix='ai-security-repair-impact-probe-') as temporary:
            env = clean_environment(Path(temporary))
            identity = subprocess.run([str(executable), 'runtime-info', '--json'], cwd=ROOT,
                env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=True)
            cli_info = json.loads(identity.stdout.decode('utf-8-sig'))
            with (run_dir / 'mcp-stderr.log').open('w', encoding='utf-8') as errors:
                probe = asyncio.run(asyncio.wait_for(frozen_mcp(executable, env, errors), timeout=120))
        for info in (cli_info, probe['runtime_info']):
            built = info.get('build_identity', {})
            if (info.get('version') != metadata['version']
                    or any(built.get(key) != metadata[key]
                           for key in ('version', 'build_id', 'source_commit', 'source_dirty'))):
                raise ValueError('Frozen process identity differs from version.json')
        write_json(run_dir / 'frozen-probe.json', dict(probe, cli_runtime_info=cli_info))
        same_inputs(snapshot, source_snapshot())
        receipt.update(status='PASSED', completed_at=stamp(), bundle=str(bundle), executable=str(executable),
            version=metadata['version'], build_id=metadata['build_id'],
            source_dirty=metadata['source_dirty'],
            package_integrity={'status': 'PASSED', 'method': 'package_metadata full inventory and SHA-256',
                'verified_file_count': len(metadata['files'])},
            source_inputs_unchanged=True, frozen_probe=str(run_dir / 'frozen-probe.json'),
            necessary_tools=list(TOOLS), build_log=str(run_dir / 'build.log'))
        write_json(run_path, receipt)
        # Only this feature's pointer changes, and only after all gates passed.
        write_json(ROOT / 'artifacts/repair-impact-latest.json', receipt, replace=True)
    except Exception as exc:
        receipt.update(status='FAILED', failed_stage=stage, completed_at=stamp(),
                       failure_type=type(exc).__name__, latest_pointer_updated=False)
        write_json(run_path, receipt, replace=run_path.exists())
        print(json.dumps(receipt, ensure_ascii=True, indent=2))
        raise
    print(json.dumps(receipt, ensure_ascii=True, indent=2))
    print('Candidate ready. Desktop acceptance is still PENDING_USER; no host was installed or restarted.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
