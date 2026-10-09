"""Offline native delivery/upgrade/MCP/index acceptance in a disposable profile.

Provider paths are explicit preinstalled engines. Nothing is installed/downloaded
and Desktop natural-language/Hook visibility is always PENDING.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path

from security_runtime.delivery import EXE, package_metadata
from security_runtime.trial import TrialProfile, isolated_environment


def cli(executable, args, root, env, expected=(0,)):
    result = subprocess.run([str(executable), *args], cwd=root, env=env, capture_output=True, timeout=120)
    if result.returncode not in expected:
        raise ValueError(f'Native acceptance command failed: {args[0]} ({result.returncode})')
    return json.loads(result.stdout) if result.stdout.strip().startswith(b'{') else result


async def scan_mcp(executable, project, env):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    environment = dict(env, SECURITY_RUNTIME_GLOBAL='0', SECURITY_RUNTIME_WORKSPACE=str(project))
    parameters = StdioServerParameters(command=str(executable), args=['mcp'], cwd=project, env=environment)
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
        async with stdio_client(parameters, errlog=errors) as (read, write):
            async with ClientSession(read, write) as client:
                await asyncio.wait_for(client.initialize(), 30)
                response = await asyncio.wait_for(client.call_tool('scan_project', {'summary': True}), 120)
                if response.isError:
                    raise ValueError('Native explicit whole-project MCP scan failed')
                payload = response.structuredContent or json.loads(response.content[0].text)
                payload = payload.get('result', payload)
                summary = await client.call_tool('get_security_summary', {})
                if summary.isError:
                    raise ValueError('Native scan summary failed')
                value = summary.structuredContent or json.loads(summary.content[0].text)
                value = value.get('result', value)
                if value['scan_context']['mode'] != 'release':
                    raise ValueError('Whole-project MCP request reused a quick scan')
                return {'mode': value['scan_context']['mode'], 'coverage': value['scan_coverage'],
                        'execution_state': value['scan_context']['execution_state'],
                        'files': value['scan_context']['actual_files'], 'scanners': value['scan_context']['scanners'],
                        'source_freshness': value['scan_context']['source_freshness']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--previous-bundle', type=Path)
    parser.add_argument('--semgrep', type=Path)
    parser.add_argument('--gitleaks', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    current = package_metadata(args.bundle)
    record = {'build_id': current['build_id'], 'source_commit': current['source_commit'],
              'source_dirty': current['source_dirty'], 'desktop': 'PENDING_ACTUAL_USER_TRIAL',
              'publisher_authenticity': 'USER_SUPPLIED_LOCAL_PACKAGE', 'network': False}
    with tempfile.TemporaryDirectory(prefix='runtime-upgrade-acceptance-') as temporary:
        profile = Path(temporary) / 'profile'
        TrialProfile(profile).create()
        project = profile / 'workspace'
        env = isolated_environment(profile)
        executable = args.bundle.absolute() / EXE
        trial_info = cli(executable, ['trial', 'run', '--root', str(profile), '--', 'runtime-info', '--json'], project, env)
        if trial_info.get('build_identity', {}).get('build_id') != current['build_id']:
            raise ValueError('Frozen trial child did not use the selected native Runtime')
        record['native_trial_run'] = 'PASS'
        for rejected in (['review-skill', 'install', '--skills-d=' + str(profile.parent / 'outside')],
                         ['setup', 'cursor', '--scope', 'global']):
            cli(executable, ['trial', 'run', '--root', str(profile), '--', *rejected], project, env, expected=(2,))
        if (profile.parent / 'outside').exists():
            raise ValueError('Native trial abbreviated path escaped isolation')
        record['native_trial_argument_boundary'] = 'PASS'
        installation = profile / 'delivery'
        bundles = [args.previous_bundle, args.bundle] if args.previous_bundle else [args.bundle]
        builds = []
        prior_key = None
        for package in bundles:
            result = cli(executable, ['delivery', 'activate', '--root', str(installation), '--bundle', str(package.absolute()), '--json'], project, env)
            builds.append(result['active_build'])
            launcher = Path(result['launcher'])
            plan_file = profile / ('plan-' + str(len(builds)) + '.json')
            cli(launcher, ['upgrade', 'plan', '--path', str(project), '--output', str(plan_file), '--json'], project, env)
            result = cli(launcher, ['upgrade', 'apply', '--plan', str(plan_file), '--json'], project, env)
            if result['status'] != 'UPGRADED':
                raise ValueError('Native coordinated upgrade did not complete')
            keys = sorted((profile / 'state').rglob('snapshot.key'))
            identity = {str(p.relative_to(profile)): p.read_bytes() for p in keys}
            if prior_key and any(identity.get(p) != key for p, key in prior_key.items()):
                raise ValueError('Native upgrade replaced signing keys')
            prior_key = identity
            server = tomllib.loads((profile / 'codex-home/config.toml').read_text(encoding='utf-8'))['mcp_servers']['ai_security_runtime']
            if Path(server['command']) != launcher:
                raise ValueError('Global installation did not persist stable launcher')
        record.update(delivery='PASS', coordinated_upgrade='PASS', builds=builds, keys='PRESERVED',
                      multiple_builds='PASS' if len(set(builds)) > 1 else 'NOT_EXERCISED')
        if len(set(builds)) > 1:
            rollback = cli(executable, ['delivery', 'rollback', '--root', str(installation), '--json'], project, env)
            if rollback['active_build'] != builds[0]:
                raise ValueError('Native rollback did not restore prior package')
            cli(executable, ['delivery', 'activate', '--root', str(installation), '--bundle', str(args.bundle.absolute()), '--json'], project, env)
            record['rollback'] = 'PASS'
        # Reproduce unknown generic shadowing, preserving sibling content.
        folder = project / '.codex'
        folder.mkdir()
        path = folder / 'config.toml'
        path.write_bytes(b'[mcp_servers.ai_security_runtime]\ncommand="fixture-never-executed"\n[mcp_servers.sibling]\ncommand="keep"\n')
        plan_file = profile / 'shadow-plan.json'
        cli(launcher, ['upgrade', 'plan', '--path', str(project), '--output', str(plan_file), '--json'], project, env)
        cli(launcher, ['upgrade', 'apply', '--plan', str(plan_file), '--json'], project, env, expected=(2,))
        if 'ai_security_runtime' not in tomllib.loads(path.read_text())['mcp_servers']:
            raise ValueError('Unknown entry removed without approval')
        cli(launcher, ['upgrade', 'apply', '--plan', str(plan_file), '--approve-user-managed', '--json'], project, env)
        if tomllib.loads(path.read_text())['mcp_servers'] != {'sibling': {'command': 'keep'}}:
            raise ValueError('Native shadow migration changed sibling configuration')
        record['unknown_approval_and_sibling_preservation'] = 'PASS'
        if args.semgrep and args.gitleaks:
            if not args.semgrep.is_file() or not args.gitleaks.is_file():
                raise ValueError('Explicit scanner engines missing; no automatic installation')
            env.update(SECURITY_RUNTIME_SEMGREP_PATH=str(args.semgrep.absolute()), SECURITY_RUNTIME_GITLEAKS_PATH=str(args.gitleaks.absolute()))
            subprocess.run(['git', '-C', str(project), 'init', '-q'], check=True, capture_output=True)
            safe = b'import javax.net.ssl.HttpsURLConnection;\nclass Fixture { void apply(HttpsURLConnection c) { } }\n'
            risky = b'import javax.net.ssl.HttpsURLConnection;\nclass Fixture { void apply(HttpsURLConnection c) { c.setHostnameVerifier((hostname, session) -> true); } }\n'
            source = project / 'Fixture.java'
            source.write_bytes(risky)
            subprocess.run(['git', '-C', str(project), 'add', 'Fixture.java'], check=True, capture_output=True)
            source.write_bytes(safe)
            result = cli(launcher, ['scan', '--path', str(project), '--staged', '--gate', 'strict', '--no-progress', '--json'], project, env, expected=(0,1,2))
            if result['release_status'] != 'BLOCKED' or result['scanner_diagnostics']['source_kind'] != 'GIT_INDEX_PROJECTION':
                diagnostic = {'status':result['status'], 'execution':result['execution_state'],
                              'release':result['release_status'], 'coverage':result['coverage'],
                              'runs':[{k:r.get(k) for k in ('scanner','status','error_code')} for r in result['scanner_runs']],
                              'findings':[{k:f.get(k) for k in ('severity','confidence','file_path')} for f in result['findings']]}
                raise ValueError('Real native scanner did not block risky index: ' + json.dumps(diagnostic))
            subprocess.run(['git', '-C', str(project), 'add', 'Fixture.java'], check=True, capture_output=True)
            source.write_bytes(risky)
            result = cli(launcher, ['scan', '--path', str(project), '--staged', '--gate', 'strict', '--no-progress', '--json'], project, env)
            if result['coverage'] != 'FULL' or result['findings']:
                raise ValueError('Real native safe index gate incomplete')
            record['real_scanner_index_gate'] = 'PASS'
            record['explicit_no_hook_mcp'] = asyncio.run(scan_mcp(launcher, project, env))
        else:
            record['real_scanner_index_gate'] = 'NOT_EXERCISED_MISSING_EXPLICIT_ENGINES'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
