"""Actual local SDK/scanner acceptance; simulated host edits, NOT Codex dispatch."""
import argparse
import asyncio
from contextlib import asynccontextmanager
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

SAFE = '''import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
class UnsafeTlsService {
 void request(String url) throws Exception {
  HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
  connection.setConnectTimeout(1000);
 }
}
'''
UNSAFE = SAFE.replace('  connection.setConnectTimeout',
                      '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout')


def assert_closed_scanner_proof(closed, verified, arguments, grant_id):
    """A real original-rule recheck followed by reuse of its matching proof."""
    remediation = closed['remediation']
    assert remediation['verification']['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert remediation['verification']['runtime_observed_execution']['engine_process_observed']
    receipt = remediation['security_verification']
    assert receipt['status'] == 'SCANNER_VERIFIED_RESOLVED' and receipt['phase'] == 'CLOSED'
    assert receipt['task_ref'] == arguments['task_ref'] and receipt['grant_id'] == grant_id
    assert verified['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
    assert verified['proof_source'] == 'SAVED_SCANNER_PROOF'
    assert verified['security_receipt']['grant_id'] == grant_id
    assert verified['runtime_observed_execution']['engine_process_observed'] is False


async def approve_reported_risk(call, pending, source):
    """Synthetic host choice only; never claim a Desktop human interaction."""
    before = source.read_bytes()
    assert pending['action'] == 'CONFIRM_REQUIRED', 'Legacy unconfirmed repair is unsupported'
    assert not {'prepare', 'fast_fix_plan', 'agent_fix_ticket'} & pending.keys()
    message = pending['user_feedback']['message']
    assert '修复' in message and '忽略' in message
    grant = await call('confirm_remediation', dict(pending['confirmation']['arguments'], approve=True))
    assert grant['authorization_kind'] == 'USER_CONFIRMED'
    assert grant['approval_trust'] == 'UNTRUSTED_HOST_REPORT'
    assert source.read_bytes() == before
    return grant


async def run(command, mode='ask_before_fix', approve=True):
    requested_mode = mode
    mode = 'ask_before_fix' if mode == 'smart_auto' else mode
    from security_runtime._version import __version__
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='runtime-remediation-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'project'; root.mkdir()
        for args in [('init',), ('config','user.name','Synthetic Fixture'),
                     ('config','user.email','fixture@example.invalid')]:
            subprocess.run(['git','-C',str(root),*args], check=True, capture_output=True)
        (root / 'README.md').write_text('Disposable local acceptance.\n')
        subprocess.run(['git','-C',str(root),'add','.'], check=True, capture_output=True)
        subprocess.run(['git','-C',str(root),'commit','-m','fixture'], check=True, capture_output=True)
        path = root / 'UnsafeTlsService.java'; path.write_text(SAFE)
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root),
                   SECURITY_RUNTIME_STATE_DIR=str(parent / 'state'), SECURITY_RUNTIME_OFFLINE='1',
                   SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        state = parent / 'state'; state.mkdir()
        (state / 'remediation.json').write_text(json.dumps({'remediation': {'mode': requested_mode}}))
        params = StdioServerParameters(command=command[0], args=command[1:] + ['mcp'], env=env, cwd=root)
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = {t.name:t for t in (await client.list_tools()).tools}
                    async def call(name, arguments):
                        response = await client.call_tool(name, invocation_claims(name, arguments))
                        assert not response.isError, name
                        data = response.structuredContent or json.loads(response.content[0].text)
                        return data.get('result', data), response
                    claims = dict(event='PostToolUse', workspace_path=str(root),
                                  session_id='local-sdk-remediation', tool_name='apply_patch')
                    info, _ = await call('get_runtime_info', {})
                    assert info['remediation']['mode'] == mode
                    assert info['remediation']['configuration_status'] == 'VALID'
                    assert str(state) not in json.dumps(info)
                    baseline, _ = await call('handle_hook_event', claims)
                    assert baseline['status'] == 'BASELINE_ESTABLISHED'
                    assert baseline['new_families'] == 0
                    # Simulate host reading/editing time; retain the existing
                    # 1s Hook cooldown rather than bypassing its debounce.
                    await asyncio.sleep(1.1)
                    path.write_text(UNSAFE)
                    new, response = await call('handle_hook_event', claims)
                    assert new['new_families'] == 1, new
                    text = json.loads(response.content[0].text)
                    if mode == 'ask_before_fix':
                        assert new['continue'] is text['continue'] is False
                        assert new['stopReason'] == text['stopReason'] == new['remediation']['user_feedback']['message']
                        assert 'decision' not in new and 'decision' not in text
                        assert 'reason' not in new and 'reason' not in text
                        interaction = new['remediation']['interaction']
                        assert interaction['edit_already_applied'] is True
                        assert interaction['requested_user_decision'] == 'REMEDIATE_SECURITY_FINDING'
                        assert interaction['must_not_retry_previous_edit'] is True
                        assert 'Do NOT retry, re-apply, or repeat' in new['remediation']['guidance']
                        assert path.read_text() == UNSAFE
                    if mode == 'report_only' or not approve:
                        if mode == 'report_only':
                            assert new['remediation']['action'] == 'ADVISE' and 'decision' not in new
                            decision_status = 'REPORTED_WITHOUT_FORCED_CONFIRMATION'
                        else:
                            assert new['remediation']['action'] == 'CONFIRM_REQUIRED'
                            confirmation_args = dict(new['remediation']['confirmation']['arguments'], approve=False)
                            refused, _ = await call('confirm_remediation', confirmation_args)
                            assert refused['status'] == 'DECLINED'
                            decision_status = refused['status']
                        await asyncio.sleep(1.1)
                        (root / 'Other.java').write_text('class Other {}\n')
                        later, _ = await call('handle_hook_event', claims)
                        assert 'decision' not in later and not later['remediation']['feedback_required']
                        assert path.read_text() == UNSAFE
                        proof = dict(baseline_status=baseline['status'], new_families=new['new_families'],
                                     action=new['remediation']['action'], decision_status=decision_status,
                                     prepare_called=False, verify_called=False, affected_source_unchanged=True,
                                     unrelated_edit_feedback=False)
                        if mode == 'ask_before_fix':
                            proof.update(interaction=interaction, hook_continue=False,
                                         hook_decision_present=False, retry_or_reapply_requested=False)
                        return dict(mode=requested_mode, effective_mode=mode, proof=proof, host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',
                                    codex_native_dispatch='PENDING', scanner_network=False)
                    if mode == 'ask_before_fix':
                        decision = new['remediation']
                        assert decision['action'] == 'CONFIRM_REQUIRED' and decision['feedback_required']
                        assert 'rem-v1.' not in json.dumps(decision) and 'prepare' not in decision
                        assert 'Proactively ask the user' in decision['guidance']
                        for name in ('prepare_task_fix', 'verify_task_fix'):
                            rejected, _ = await call(name, {'task_ref': decision['task_ref']})
                            assert rejected['reason_code'] == 'CONFIRMATION_HANDOFF_REQUIRED'
                        assert path.read_text() == UNSAFE
                        # This is a simulated explicit host-reported reply.
                        # It cannot prove a real human interaction in Desktop.
                        authorization, _ = await call('confirm_remediation',
                            dict(decision['confirmation']['arguments'], approve=True))
                        assert authorization['status'] == 'AUTHORIZED'
                        assert authorization['approval_trust'] == 'UNTRUSTED_HOST_REPORT'
                        arguments = authorization['prepare']['arguments']
                        repeated, _ = await call('confirm_remediation', dict(decision['confirmation']['arguments'], approve=True))
                        assert repeated['reason_code'] == 'CONFIRMATION_ALREADY_CONSUMED'
                    packet, _ = await call('prepare_task_fix', arguments)
                    assert packet['status'] == 'READY_FOR_HOST_FIX'
                    assert packet['remediation_authorization']['authorization_kind'] == 'USER_CONFIRMED'
                    assert not any(packet['execution'].values())
                    authorization_fields = packet['remediation_authorization']
                    prepare_status = packet['status']
                    await asyncio.sleep(1.1)
                    # This driver plays the host editor. Runtime never edits.
                    path.write_text(SAFE)
                    closed, _ = await call('handle_hook_event', claims)
                    assert closed['resolved_families'] == 1, closed
                    assert closed['remediation']['verification']['verification_status'] == 'SCANNER_VERIFIED_RESOLVED', closed
                    assert 'decision' not in closed
                    verified, _ = await call('verify_task_fix', arguments)
                    assert_closed_scanner_proof(closed, verified, arguments, authorization['grant_id'])
                    await asyncio.sleep(1.1)
                    (root / 'Other.java').write_text('class Other {}\n')
                    later, _ = await call('handle_hook_event', claims)
                    assert later['remediation']['action'] == 'NONE' and 'decision' not in later
                    assert path.read_text() == SAFE
                    # Metadata export only; bounded fix evidence is not saved.
                    proof = dict(baseline_status=baseline['status'], new_families=new['new_families'],
                                 action=new['remediation']['action'], attempt_count=authorization_fields['attempt_count'],
                                 authorization_kind=authorization_fields['authorization_kind'],
                                 preconfirmation_grant_available=False,
                                 hook_feedback='continue:false',
                                  interaction=new['remediation'].get('interaction'), prepare_status=prepare_status,
                                  observed_mode=info['remediation']['mode'],
                                 resolved_families=closed['resolved_families'],
                                 automatic_verification=closed['remediation']['verification'],
                                 explicit_verification=verified['verification_status'],
                                 observed_execution=verified['runtime_observed_execution'],
                                 unrelated_edit_action=later['remediation']['action'])
            errors.seek(0)
            assert '0x80131506' not in errors.read()
    return dict(runtime_version=__version__, mode=requested_mode, effective_mode=mode, transport='ACTUAL_LOCAL_MCP_STDIO',
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE', host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',
                codex_native_dispatch='PENDING', same_turn_codex_model_continuation='PENDING',
                runtime_model_invoked=False, runtime_source_edit=False, target_build=False,
                scanner_network=False, ground_truth='UNREVIEWED', command_hook_runner_used=False,
                duration_ms=round((time.monotonic()-started)*1000), proof=proof,
                schemas={name:tools[name].inputSchema for name in ('handle_hook_event','confirm_remediation','prepare_task_fix','verify_task_fix')})


async def measured_case(coroutine, *, timeout):
    started = time.monotonic()
    result = await asyncio.wait_for(coroutine, timeout=timeout)
    result['case_wall_ms'] = round((time.monotonic() - started) * 1000)
    result['case_wall_measurement'] = 'ACTUAL_DRIVER_WITH_STDIO_CLOSE_NOT_DESKTOP_LATENCY'
    return result


async def run_all(command):
    # Four independent cold-server/scanner cases; bound each one rather than
    # mistake their aggregate wall time for one product repair timeout.
    record = await measured_case(run(command), timeout=120)
    record['legacy_alias_approval'] = await measured_case(run(command, 'smart_auto'), timeout=120)
    record['confirmation_decline'] = await measured_case(run(command, 'ask_before_fix', approve=False), timeout=120)
    record['report_only'] = await measured_case(run(command, 'report_only'), timeout=120)
    return record


async def run_cross_turn(command, approve):
    """Close actual server A, launch server B with signed state, then replay C.

    This proves process persistence, not Desktop dispatch or a human reply.
    """
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='runtime-confirmation-restart-') as temporary:
        parent = Path(temporary).resolve()
        root = parent / 'project'; root.mkdir()
        for args in [('init',), ('config','user.name','Synthetic Fixture'),
                     ('config','user.email','fixture@example.invalid')]:
            subprocess.run(['git','-C',str(root),*args], check=True, capture_output=True)
        (root / 'README.md').write_text('Disposable offline cross-process acceptance.\n')
        subprocess.run(['git','-C',str(root),'add','.'], check=True, capture_output=True)
        subprocess.run(['git','-C',str(root),'commit','-m','fixture'], check=True, capture_output=True)
        path = root / 'UnsafeTlsService.java'; path.write_text(SAFE)
        state = parent / 'state'; state.mkdir()
        (state / 'remediation.json').write_text(json.dumps({'remediation':{'mode':'ask_before_fix'}}))
        env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_STATE_DIR=str(state),
                   SECURITY_RUNTIME_OFFLINE='1', SECURITY_RUNTIME_MCP_SELF_TEST='1', PYTHONUTF8='1')
        params = StdioServerParameters(command=command[0], args=command[1:] + ['mcp'], env=env, cwd=root)
        @asynccontextmanager
        async def connection():
            with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
                async with stdio_client(params, errlog=errors) as (read, write):
                    async with ClientSession(read, write) as client:
                        await client.initialize()
                        async def call(name, arguments):
                            response = await client.call_tool(name, invocation_claims(name, arguments))
                            assert not response.isError, name
                            data = response.structuredContent or json.loads(response.content[0].text)
                            return data.get('result', data), response
                        yield call
                errors.seek(0)
                assert '0x80131506' not in errors.read()
        def record():
            states = list((state / 'remediation').glob('*/*.json'))
            assert len(states) == 1
            rows = json.loads(states[0].read_bytes())['records']
            assert len(rows) == 1
            return next(iter(rows.values()))
        claims = dict(event='PostToolUse', workspace_path=str(root),
                      session_id='cross-turn-confirmation', tool_name='apply_patch')
        async with connection() as call_a:
            baseline, _ = await call_a('handle_hook_event', claims)
            assert baseline['status'] == 'BASELINE_ESTABLISHED'
            await asyncio.sleep(1.1)
            path.write_text(UNSAFE)  # Simulated host side effect, never Runtime.
            pending, response = await call_a('handle_hook_event', claims)
            assert pending['new_families'] == 1 and pending['remediation']['action'] == 'CONFIRM_REQUIRED'
            assert pending['continue'] is json.loads(response.content[0].text)['continue'] is False
            assert 'decision' not in pending
            arguments = pending['remediation']['confirmation']['arguments']
            expires = record()['confirmation_expires_at_epoch']
        # A's stdio context has exited; B is a distinct OS server process.
        assert path.read_text() == UNSAFE and record()['phase'] == 'PENDING_CONFIRMATION'
        async with connection() as call_b:
            out, _ = await call_b('confirm_remediation', dict(arguments, approve=approve))
            assert out['status'] == ('AUTHORIZED' if approve else 'DECLINED'), out
            assert record()['confirmation_expires_at_epoch'] == expires
            proof = dict(pending_from_server_a=True, confirmation_in_server_b=out['status'],
                         deadline_unchanged=True, source_unsafe_before_choice=True,
                         original_session_namespace=True, mcp_server_launches=3)
            if approve:
                assert out['approval_trust'] == 'UNTRUSTED_HOST_REPORT'
                grant = out['prepare']['arguments']
                prepared, _ = await call_b('prepare_task_fix', grant)
                assert prepared['status'] == 'READY_FOR_HOST_FIX'
                assert path.read_text() == UNSAFE and not any(prepared['execution'].values())
                await asyncio.sleep(1.1)
                path.write_text(SAFE)
                closed, _ = await call_b('handle_hook_event', claims)
                assert closed['resolved_families'] == 1
                assert closed['remediation']['verification']['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'
                verified, _ = await call_b('verify_task_fix', grant)
                assert_closed_scanner_proof(closed, verified, grant, out['grant_id'])
                proof.update(prepare_status=prepared['status'], resolved_families=1,
                             verification_status=verified['verification_status'],
                             observed_execution=closed['remediation']['verification']['runtime_observed_execution'],
                             explicit_verification_reused_proof=verified['proof_source'])
            else:
                await asyncio.sleep(1.1)
                (root / 'Other.java').write_text('class Other {}\n')
                later, _ = await call_b('handle_hook_event', claims)
                assert not later['remediation']['feedback_required'] and 'continue' not in later
                assert path.read_text() == UNSAFE
                proof.update(prepare_called=False, verify_called=False, unsafe_source_remains=True,
                             unrelated_edit_feedback=False)
        async with connection() as call_c:
            replay, _ = await call_c('confirm_remediation', dict(arguments, approve=True))
            assert replay['reason_code'] == 'CONFIRMATION_ALREADY_CONSUMED'
            proof['cross_process_replay'] = replay['reason_code']
            if approve:
                lost, _ = await call_c('prepare_task_fix', grant)
                assert lost['reason_code'] == 'REPAIR_GRANT_STALE'
                proof['authorized_grant_after_restart'] = lost['reason_code']
    return dict(transport='ACTUAL_LOCAL_MCP_STDIO_CLOSE_AND_RELAUNCH', proof=proof,
                approve=approve, duration_ms=round((time.monotonic()-started)*1000),
                scanner='ACTUAL_MANAGED_SEMGREP_GITLEAKS_OFFLINE', scanner_network=False,
                user_choice='SIMULATED_BY_ACCEPTANCE_DRIVER', host_edits='SIMULATED_BY_ACCEPTANCE_DRIVER',
                runtime_source_edit=False, runtime_model_invoked=False, target_build=False,
                codex_native_dispatch='PENDING', real_human_confirmation='NOT_EXECUTED')


async def run_cross_turn_all(command):
    return {'approval': await measured_case(run_cross_turn(command, True), timeout=180),
            'decline': await measured_case(run_cross_turn(command, False), timeout=180)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', help='Optional built standalone executable')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cross-turn-only', action='store_true', help='Actual stdio server recreation approval/decline')
    args = parser.parse_args()
    command = [args.runtime] if args.runtime else [sys.executable, '-m', 'security_runtime.cli']
    record = asyncio.run(run_cross_turn_all(command) if args.cross_turn_only else run_all(command))
    if args.output:
        args.output.write_text(json.dumps(record, indent=2), encoding='utf-8')
    print(json.dumps(record, indent=2))
