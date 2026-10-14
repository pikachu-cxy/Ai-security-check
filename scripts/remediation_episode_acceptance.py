"""Offline actual MCP/scanner recurrence; driver edits are NOT Desktop dispatch."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from codex_hook_fixture import invocation_claims
from remediation_acceptance import assert_closed_scanner_proof

SAFE = '''import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
class CodeModeTlsService {
 void request(String url) throws Exception {
  HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
  connection.setConnectTimeout(1000);
 }
}
'''
UNSAFE = SAFE.replace('  connection.setConnectTimeout',
                      '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout')


async def run():
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='runtime-episode-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'project'
        root.mkdir()
        subprocess.run(['git', 'init', str(root)], check=True, capture_output=True)
        path = root / 'src/main/java/demo/CodeModeTlsService.java'
        path.parent.mkdir(parents=True)
        path.write_text(SAFE)
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_STATE_DIR=str(parent / 'state'), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=sys.executable, args=['-m', 'security_runtime.cli', 'mcp'],
                                      env=env, cwd=root)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    async def call(name, arguments):
                        response = await client.call_tool(name, invocation_claims(name, arguments))
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data)
                    claims = dict(event='PostToolUse', workspace_path=str(root),
                                  session_id='episode-acceptance', tool_name='apply_patch')
                    baseline = await call('handle_hook_event', claims)
                    assert baseline['status'] == 'BASELINE_ESTABLISHED'
                    episodes = []
                    original = None
                    family = None
                    for number in (1, 2):
                        await asyncio.sleep(1.1)
                        path.write_text(UNSAFE)  # Host simulation, never Runtime.
                        detected = await call('handle_hook_event', claims)
                        pending = detected['remediation']
                        assert pending['action'] == 'CONFIRM_REQUIRED' and 'prepare' not in pending
                        assert path.read_text() == UNSAFE
                        # Simulated explicit user choice for each new episode.
                        grant = await call('confirm_remediation', dict(pending['confirmation']['arguments'], approve=True))
                        assert grant['authorization_kind'] == 'USER_CONFIRMED'
                        assert grant['action'] == 'AUTO_FIX', detected
                        assert grant['episode_number'] == number and grant['attempt_count'] == 1
                        # References are copied exactly, never decoded/reconstructed.
                        arguments = dict(grant['prepare']['arguments'])
                        if original is not None:
                            assert arguments['task_ref'] != original['task_ref']
                            assert arguments['remediation_ref'] != original['remediation_ref']
                            assert grant['finding_family'] == family
                            assert grant['episode_reason_code'] == 'RECURRENCE_AFTER_RESOLUTION'
                            rejected = await call('prepare_task_fix', original)
                            assert rejected['reason_code'] == 'REPAIR_GRANT_REJECTED'
                        packet = await call('prepare_task_fix', arguments)
                        assert packet['status'] == 'READY_FOR_HOST_FIX', packet
                        assert packet['task_ref'] == arguments['task_ref']
                        assert packet['verification_plan']['arguments']['remediation_ref'] == arguments['remediation_ref']
                        await asyncio.sleep(1.1)
                        path.write_text(SAFE)
                        closed = await call('handle_hook_event', claims)
                        receipt = closed['remediation']['security_verification']
                        assert receipt['status'] == 'SCANNER_VERIFIED_RESOLVED' and receipt['phase'] == 'CLOSED'
                        assert receipt['task_ref'] == arguments['task_ref'] and receipt['grant_id'] == grant['grant_id']
                        cycle_points = closed['remediation_cycle_timepoints_ms']
                        cycle_breakdown = closed['remediation_cycle_breakdown_ms']
                        assert all(cycle_points[name] is not None for name in (
                            'risk_hook_started', 'initial_scan_finished', 'policy_finished',
                            'auto_fix_authorized', 'initial_hook_response_ready',
                            'host_continuation_observed', 'prepare_task_fix_started',
                            'prepare_task_fix_finished', 'host_edit_observed',
                            'fix_edit_hook_started', 'security_rescan_started',
                            'security_rescan_finished', 'episode_closed', 'return_to_host')), cycle_points
                        assert cycle_breakdown['unaccounted'] >= 0
                        assert abs(sum(v for v in cycle_breakdown.values() if v is not None)
                                   - closed['remediation_cycle_wall_ms']) <= 0.01
                        assert cycle_points['host_edit_completed'] is None
                        assert cycle_points['initial_hook_response_sent'] is None
                        verified = await call('verify_task_fix', arguments)
                        assert verified['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
                        assert_closed_scanner_proof(closed, verified, arguments, grant['grant_id'])
                        episodes.append(dict(number=number, episode_id=grant['episode_id'],
                                             action=grant['action'], reason_code=grant['reason_code'],
                                             episode_reason_code=grant['episode_reason_code'],
                                             attempt_count=grant['attempt_count'], prepare_status=packet['status'],
                                             resolved_families=closed['resolved_families'],
                                             cycle_wall_ms=closed['remediation_cycle_wall_ms'],
                                             cycle_breakdown=cycle_breakdown,
                                             verification_status=verified['verification_status'],
                                             final_stage=receipt['phase']))
                        original = original or arguments
                        family = family or grant['finding_family']
                    assert episodes[0]['episode_id'] != episodes[1]['episode_id']
            errors.seek(0)
            assert '0x80131506' not in errors.read()
    return dict(status='PASS', transport='ACTUAL_LOCAL_MCP_STDIO',
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE', episodes=episodes,
                same_family=True, references_distinct=True, old_grant_rejected=True,
                exact_reference_roundtrip=True, raw_references_persisted=False,
                host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER', actual_desktop='PENDING',
                runtime_source_edit=False, model=False, target_build=False, network=False,
                functional_credential_lifecycle='NOT_TESTED_OUT_OF_SCOPE',
                duration_seconds=round(time.monotonic()-start, 2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = asyncio.run(run())
    if args.output:
        args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
