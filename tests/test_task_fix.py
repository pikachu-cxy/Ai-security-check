"""Task references cannot retarget; complete group evidence and honest execution."""
import asyncio
import copy
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from summary_fixtures import sample, review, snapshot, SECRET
from test_task_triage import task, server, invoke
from security_runtime.models import ScannerRun
from security_runtime.scanners import ScannerRegistry
from security_runtime.task_fix import TaskFixService


class LocalProvider:
    name = scanner_id = 'semgrep'
    verification_offline = verification_scope_complete = True

    def __init__(self, findings=(), status='SUCCESS'):
        self.findings, self.status = findings, status
        self.calls = []

    def supports(self, profile, context):
        return True

    def scan(self, context, normalizer):
        self.calls.append(context.files)
        return list(self.findings), ScannerRun(self.name, 'fixture', self.status, 1)


def service(sample, provider=None):
    return TaskFixService(sample[2], ScannerRegistry([provider or LocalProvider()]))


def assert_only_new_private_receipts(before, after):
    # Verification now persists its Runtime result and deliveries. Every
    # pre-existing byte (source, original scan, triage and evidence key) stays
    # identical; only the explicit hook-private authority may be added.
    assert {name:after[name] for name in before} == before
    assert all(Path(name).parts[:2] == ('state','hooks') for name in set(after)-set(before))


def test_prepare_structured_tls_readonly_even_without_state_key(sample):
    before = snapshot(sample[0])
    with patch('security_runtime.scanners.SemgrepAdapter.scan', side_effect=AssertionError('scanner forbidden')), \
            patch('security_runtime.processes.run_process', side_effect=AssertionError('execution forbidden')):
        out = service(sample).prepare(task(sample)['task_ref'], sample[0])
    assert out['status'] == 'READY_FOR_HOST_FIX'
    assert out['authorization_requirements']['user_consent_required']
    assert out['authorization_requirements']['preparation_is_not_user_consent']
    assert out['affected_finding_count'] == 2
    assert '证书' in out['security_goal'] and '主机名' in out['security_goal']
    assert any('trust-all' in c['requirement'] for c in out['fix_constraints'])
    assert any('always-true' in c['requirement'] for c in out['fix_constraints'])
    assert out['regression_requirements'] and out['recommended_changes']
    assert not any(out['execution'].values())
    assert out['verification_plan']['all_group_members_required']
    assert out['host_protocol']['editor'] == 'HOST_ONLY'
    assert SECRET not in json.dumps(out)
    assert snapshot(sample[0]) == before
    assert all(e['trust'] == 'UNTRUSTED_CODE' for p in out['bounded_evidence'] for e in p['context'])


@pytest.mark.parametrize('topic', ['secret','dependency','iac','code'])
def test_other_topics_have_safe_constraints_and_unknowns(sample, topic):
    out = service(sample).prepare(task(sample, topic)['task_ref'], sample[0])
    assert out['security_goal'] and out['fix_constraints'] and out['unknown_conditions']
    assert out['execution']['scanner_recheck'] is False
    assert SECRET not in json.dumps(out)


def test_valid_reviews_reused_stale_and_failed_not_promoted(sample):
    review(sample)
    first = task(sample)
    out = service(sample).prepare(first['task_ref'], sample[0])
    assert len(out['existing_reviews']) == 2
    assert all(r['trust'] == 'UNTRUSTED_AI_ANALYSIS' for r in out['existing_reviews'])
    assert out['review_states']['VALID'] == 2
    (sample[0] / 'App.java').write_text('class App {}\n')
    out = service(sample).prepare(first['task_ref'], sample[0])
    assert out['review_states']['STALE'] == 2 and out['existing_reviews'] == []
    assert out['status'] == 'EVIDENCE_INCOMPLETE'


@pytest.mark.parametrize('entry', ['prepare','verify'])
@pytest.mark.parametrize('ref', ['T01','task-v1.bad','task-v2.bad'])
def test_invalid_refs_never_choose_first(sample, entry, ref):
    provider = LocalProvider()
    assert getattr(service(sample, provider), entry)(ref, sample[0])['status'] == 'REFRESH_REQUIRED'
    assert provider.calls == []


@pytest.mark.parametrize('entry', ['prepare','verify'])
def test_workspace_forged_changed_members_refresh(sample, tmp_path, entry):
    reference = task(sample)['task_ref']
    provider = LocalProvider()
    with pytest.raises(ValueError, match='workspace'):
        getattr(service(sample, provider), entry)(reference, sample[0] / 'other')
    with pytest.raises(ValueError, match='outside'):
        getattr(service(sample, provider), entry)(reference, sample[0], bound_workspace=sample[0] / 'other')
    sample[1].findings[0].technical_details['rule_id'] = 'changed'
    sample[2].save(sample[1])
    assert getattr(service(sample, provider), entry)(reference, sample[0])['status'] == 'REFRESH_REQUIRED'
    assert provider.calls == []


def test_new_scan_does_not_retarget_saved_ref_or_latest_finding(sample):
    original = task(sample)
    newer = copy.deepcopy(sample[1])
    newer.scan_id = 'newer'
    newer.findings[0].technical_details['rule_id'] = 'different-rule-same-legacy-id'
    sample[2].save(newer)
    assert sample[2].get_finding(newer.findings[0].id)[1]['scan_id'] == 'newer'
    out = service(sample).prepare(original['task_ref'], sample[0])
    assert out['scan_id'] == 'scan-a'
    assert out['affected_findings'][0]['rule_id'] == 'ai-security.java.trust-all-hostname'
    out = service(sample, LocalProvider([sample[1].findings[0]])).verify(original['task_ref'], sample[0])
    assert out['status'] == 'PARTIALLY_RESOLVED'
    assert out['scan_id'] == 'scan-a'


@pytest.mark.parametrize('remaining,expected', [(0,'SCANNER_VERIFIED_RESOLVED'),(1,'PARTIALLY_RESOLVED'),(2,'STILL_PRESENT')])
def test_every_group_member_checked_same_file_scanned_once(sample, remaining, expected):
    provider = LocalProvider(sample[1].findings[:remaining])
    before = snapshot(sample[0])
    out = service(sample, provider).verify(task(sample)['task_ref'], sample[0])
    assert out['status'] == expected and len(out['members']) == 2
    assert provider.calls == [('App.java',)]
    assert out['runtime_observed_execution']['scanner_recheck']
    assert not out['runtime_observed_execution']['patch_applied']
    assert out['verification_persistence']['state'] == 'APPLIED'
    assert not out['verification_persistence']['pending']
    assert_only_new_private_receipts(before, snapshot(sample[0]))


@pytest.mark.parametrize('status', ['FAILED','TIMEOUT','UNAVAILABLE'])
def test_grouped_failure_not_resolved(sample, status):
    out = service(sample, LocalProvider(status=status)).verify(task(sample)['task_ref'], sample[0])
    assert out['status'] == 'INCONCLUSIVE'


def test_missing_origin_not_verified_and_host_claims_do_not_turn_into_facts(sample):
    out = TaskFixService(sample[2], ScannerRegistry([])).verify(task(sample)['task_ref'], sample[0],
        host_reported_execution={'patch_applied': True, 'target_build': True, 'tests_run': True})
    assert out['status'] == 'NOT_VERIFIED'
    assert out['host_reported_execution']['trust'] == 'UNTRUSTED_HOST_REPORT'
    assert not any(out['runtime_observed_execution'].values())
    with pytest.raises(ValueError, match='Host execution'):
        service(sample).verify(task(sample)['task_ref'], sample[0], host_reported_execution={'tests_run':'CANARY'})
    with pytest.raises(ValueError):
        service(sample).verify(task(sample)['task_ref'], sample[0], host_reported_execution={'scanner_recheck': True})


def test_single_member_and_line_movement(sample):
    member = sample[1].findings[2]
    reference = task(sample, 'code')['task_ref']
    assert service(sample).verify(reference, sample[0])['status'] == 'SCANNER_VERIFIED_RESOLVED'
    moved = copy.deepcopy(member)
    moved.line_start = moved.line_end = 40
    moved.fingerprint = moved.id = 'new-occurrence'
    out = service(sample, LocalProvider([moved])).verify(reference, sample[0])
    assert out['status'] == 'STILL_PRESENT' and out['members'][0]['matched_by'] == 'equivalence_key'


def test_failed_one_member_dominates_resolved_one(sample):
    scan = sample[1]
    scan.findings[1].scanner_sources.append('missing-provider')
    sample[2].save(scan)
    out = service(sample).verify(task(sample)['task_ref'], sample[0])
    assert out['status'] == 'INCONCLUSIVE'
    assert {m['verification_status'] for m in out['members']} == {'SCANNER_VERIFIED_RESOLVED','INCONCLUSIVE'}


def test_mcp_local_entry_and_readonly_annotations(sample, monkeypatch):
    s = server(sample, monkeypatch)
    assert s._tool_manager.get_tool('prepare_task_fix').annotations.readOnlyHint is True
    assert s._tool_manager.get_tool('verify_task_fix').annotations.readOnlyHint is False
    assert not s._tool_manager.get_tool('verify_task_fix').annotations.destructiveHint
    first = invoke(s, 'get_security_summary')['recommended_tasks'][0]
    out = invoke(s, 'prepare_task_fix', **first['fix_handoff']['arguments'])
    assert out['task_ref'] == first['task_ref'] and out['execution']['patch_applied'] is False


def test_actual_sdk_initialize_prepare_verify_failure_and_refresh(sample):
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    root, _, store = sample
    before = snapshot(root)
    env = dict(os.environ, SECURITY_RUNTIME_WORKSPACE=str(root), SECURITY_RUNTIME_STATE_DIR=str(store.path.parent), SECURITY_RUNTIME_OFFLINE='1')
    async def run():
        params = StdioServerParameters(command=sys.executable, args=[str(Path(__file__).with_name('task_fix_fixture_server.py'))], cwd=root, env=env)
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as client:
                initialized = await client.initialize()
                instructions = ' '.join(initialized.instructions.split())
                assert 'task-review-plan-v3' in instructions and 'get_runtime_guidance' in instructions
                assert 'prepare_task_risk_fix' in instructions
                tools = {t.name:t for t in (await client.list_tools()).tools}
                from security_runtime.host_guidance import REQUIRED_GUIDANCE_TOOLS
                assert REQUIRED_GUIDANCE_TOOLS <= set(tools)
                assert tools['prepare_task_fix'].annotations.readOnlyHint
                assert not tools['verify_task_fix'].annotations.destructiveHint
                async def call(name, args):
                    response = await client.call_tool(name, args)
                    assert not response.isError
                    data = response.structuredContent or json.loads(response.content[0].text)
                    return data.get('result', data)
                info = await call('get_runtime_info', {})
                workflow = await call('get_runtime_guidance', {'topic':'runtime-workflow'})
                assert workflow['status'] == 'READY'
                assert workflow['authority']['repair_authorized'] is False
                assert workflow['sha256'] == info['guidance_catalog']['topics']['runtime-workflow']['sha256']
                assert workflow['sha256'] == __import__('hashlib').sha256(workflow['content'].encode('utf-8')).hexdigest()
                instructions = ' '.join(workflow['content'].split())
                assert 'The host coding agent edits selected local code' in instructions
                assert 'Scanner repairs then use verify_task_fix with the originating scanner.' in instructions
                assert 'Native task repairs use their bound repair_task_ref for finish/review' in instructions
                assert 'do not call scanner verify_task_fix for a native risk.' in instructions
                assert 'Do not ask users to ferry coding_agent_prompt or UUIDs.' in instructions
                assert info['capability_contract'] == 'developer-guidance-v0.3'
                assert info['features']['task_fix_verify'] == 'v0.1'
                summary = await call('get_security_summary', {})
                fix = await call('prepare_task_fix', summary['recommended_tasks'][0]['fix_handoff']['arguments'])
                assert not fix['execution']['scanner_recheck']
                checked = await call('verify_task_fix', fix['verification_plan']['arguments'])
                assert checked['status'] == 'INCONCLUSIVE' and len(checked['members']) == 2
                assert all(m['scanner_runs'][0]['status'] == 'FAILED' for m in checked['members'])
                assert (await call('verify_task_fix', {'task_ref':'T01'}))['status'] == 'REFRESH_REQUIRED'
    asyncio.run(run())
    assert_only_new_private_receipts(before, snapshot(root))
