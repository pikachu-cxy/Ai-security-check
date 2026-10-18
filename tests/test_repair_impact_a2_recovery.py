"""Real four-file native-review recovery; no sample code or scanner is executed.

The scanner records task scope. Task snapshots, evidence reads, v3 batches,
native-risk registration, impact tools, repair baseline and risk resolution use
the real services. No task/review records are fabricated or marked complete.
"""
import asyncio
import copy
from dataclasses import replace
import subprocess

import pytest

from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.mcp_server import create_server
from security_runtime.native_repair_intent import NativeRepairIntents
from security_runtime.storage import SQLiteStore
from security_runtime.task_ownership import issue_session_ref, session_owner
from security_runtime.task_security import TaskSecurityService
from test_global_integration import structured
from test_task_review_submission_recovery import (
    DOWNLOAD, ORIGINAL_FILES, candidate as native_candidate, complete_plan, source_hashes,
)
from test_task_security import LedgerRuntime


PATCHED_DOCUMENTS = (
    'from permissions import can_read\n\n\n'
    'def read_document(user_id, document_id, repository):\n'
    '    document = repository.get(document_id)\n'
    '    if not can_read(user_id, document):\n'
    '        raise PermissionError("Access denied")\n'
    '    return {"id": document["id"], "body": document["body"]}\n'
)


class RecordingRuntime(LedgerRuntime):
    def __init__(self, path):
        super().__init__()
        self.store = SQLiteStore(path)

    def scan(self, root, mode, **kwargs):
        result = replace(super().scan(root, mode, **kwargs),
                         scan_id='a2-recording-static-' + str(len(self.calls)))
        self.store.save(result)
        return result


def call(case, tool, **arguments):
    return structured(asyncio.run(case['server'].call_tool(tool, arguments)))


def impact_call(case, tool, **arguments):
    return call(case, tool, **dict(case['common'], **arguments))


def read_report(case, assessment_ref):
    rows, offset = [], 0
    while True:
        page = impact_call(case, 'get_repair_impact', assessment_ref=assessment_ref,
                           offset=offset, limit=10)
        assert page.get('assessment_ref') == assessment_ref, page
        rows.extend(page['items'])
        if not page['page']['has_more']:
            return page, rows
        offset = page['page']['next_offset']


@pytest.fixture
def four_file_case(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    for name, content in ORIGINAL_FILES.items():
        (root / name).write_text(content, encoding='utf-8')
    runtime = RecordingRuntime(tmp_path / 'static-records.sqlite3')
    hooks = HookStateStore(tmp_path / 'private-state')
    raw_session = 'a2-four-file-recovery'
    owner = session_owner('codex', raw_session)
    tasks = TaskSecurityService(runtime, hooks, owner=owner)
    ref = tasks.begin(root, 'add-download-forwarder')['task_ref']
    baseline = copy.deepcopy(tasks.load(root, ref)['baseline'])
    assert set(baseline['hashes']) == set(ORIGINAL_FILES)
    (root / 'download.py').write_text(DOWNLOAD, encoding='utf-8')
    assert tasks.finish(root, ref)['status'] == 'READY'
    packet = tasks.prepare(root, ref, protocol_version=3)
    assert packet['protocol_version'] == 3
    session = packet['review_session']
    download = tasks.read(root, ref, session, 'download.py', 4, 5)
    complete_plan(tasks, root, ref, packet)
    evidence = {'download.py': download['evidence_id']}
    for name, content in ORIGINAL_FILES.items():
        evidence[name] = tasks.read(root, ref, session, name, 1,
                                    len(content.splitlines()))['evidence_id']
    expanded = dict(review_session=session, plan=tasks.review_plan(root, ref, session))
    assert set(complete_plan(tasks, root, ref, expanded)) == {*ORIGINAL_FILES, 'download.py'}
    case = dict(root=root, tasks=tasks, hooks=hooks, runtime=runtime, owner=owner,
                ref=ref, session=session, evidence=evidence)
    result = tasks.submit(root, ref, session, [native_candidate(case)], 'REVIEWED', [])
    assert result['status'] == 'COMPLETE'
    original = tasks.load(root, ref)
    assert original['baseline'] == baseline
    assert original['review']['coverage'] == 'REVIEWED'
    assert len(original['review']['findings']) == 1
    finding = original['review']['findings'][0]
    assert finding['risk_scope'] == 'RELATED_EXISTING'
    assert finding['file_path'] == 'documents.py'
    assert finding['task_evidence'] == evidence['download.py']
    ledger = tasks.risk_ledger(root, ref)
    assert len(ledger['items']) == 1 and ledger['items'][0]['status'] == 'OPEN'
    assert set(ledger['items'][0]['required_source_paths']) == {*ORIGINAL_FILES, 'download.py'}
    case.update(finding_id=finding['id'], before=source_hashes(root), baseline=baseline,
        source=dict(kind='HOST_TASK_RISK', task_ref=ref, finding_id=finding['id'],
                    origin_review_revision=original.get('review_revision', 1)))
    server = create_server(runtime, hook_coordinator=HookCoordinator(runtime, hooks), global_mode=False)
    token = issue_session_ref(hooks, root, 'codex', raw_session)
    case.update(server=server, common=dict(workspace_path=str(root), session_ref=token),
                intents=NativeRepairIntents(hooks, root, owner))
    return case


def prepare_and_read(case, proposal=None):
    proposal = proposal or dict(
        security_goal='Keep owner and member reads; reject unrelated readers.',
        summary='Reuse the existing can_read policy before read_document returns the body.',
        preserve=['Owner and member reads and downloads.', 'The shared list and successful return shape.'],
        changes=[dict(file_path='documents.py', start_line=1, end_line=3,
                      reason='Call the existing owner-or-member check before returning private content.')])
    packet = impact_call(case, 'prepare_repair_impact', source=case['source'], proposal=proposal)
    assert packet.get('assessment_ref'), packet
    evidence = {}
    for name in ('documents.py', 'download.py', 'permissions.py', 'sharing.py'):
        high = len((case['root'] / name).read_text(encoding='utf-8').splitlines())
        read = impact_call(case, 'read_repair_impact_context', assessment_ref=packet['assessment_ref'],
            file_path=name, start_line=1, end_line=high,
            reason='Trace the existing owner/member rule and shared read/download/list paths.')
        assert read.get('evidence_ref'), read
        evidence[name] = read['evidence_ref']
    return packet, evidence


def known_impacts(evidence):
    refs = list(evidence.values())
    return [dict(kind='EXPECTED_SECURITY_RESTRICTION', evidence_refs=refs,
        summary='Reject readers who are neither the owner nor a member, including download calls.'),
        dict(kind='NO_ADDITIONAL_CHANGE_IDENTIFIED', evidence_refs=refs,
        summary='The existing can_read rule keeps owners and members eligible; download forwards to the same read and sharing already uses that rule.')]


def scope_unknown(evidence):
    return dict(classification='SCOPE_LIMITATION', critical=False,
        summary='External identity binding, HTTP handlers, repository internals and production deployment are not provided.',
        decision_basis='The user-defined owner/member rule and existing can_read body determine this local patch. No external API, repository or deployment behavior is changed.',
        evidence_refs=list(evidence.values()))


def prepare_native(case, assessment_ref):
    return impact_call(case, 'prepare_task_risk_fix', task_ref=case['ref'],
        finding_id=case['finding_id'], origin_review_revision=case['source']['origin_review_revision'],
        impact_ref=assessment_ref, user_requested=True)


def test_a2_legacy_block_can_be_corrected_on_same_assessment_and_original_risk(four_file_case):
    case = four_file_case
    packet, evidence = prepare_and_read(case)
    ref = packet['assessment_ref']
    scopes_before = copy.deepcopy(case['runtime'].calls)
    assert source_hashes(case['root']) == case['before']
    assert case['intents'].get() is None
    assert len(case['tasks'].store(case['root']).records()) == 1
    legacy_impacts = known_impacts(evidence)
    legacy_impacts[1]['kind'] = 'UNDETERMINED'
    legacy_impacts[1]['summary'] = 'Missing external identity and deployment code was treated as inability to assess this local patch.'
    blocked = impact_call(case, 'submit_repair_impact', assessment_ref=ref, coverage='REVIEWED',
        impacts=legacy_impacts, unknowns=[dict(summary='External identity and deployment are not supplied.',
            critical=True, evidence_refs=list(evidence.values()))])
    assert blocked.get('gate') == 'CRITICAL_CONTEXT_MISSING', blocked
    waiting = prepare_native(case, ref)
    assert waiting['status'] == 'IMPACT_REQUIRED' and waiting['ready_for_host_fix'] is False
    assert waiting['new_approval_required'] is False
    assert 'repair_task_ref' not in waiting
    assert case['intents'].get()['status'] == 'WAITING'
    assert len(case['tasks'].store(case['root']).records()) == 1
    assert source_hashes(case['root']) == case['before']

    ready = impact_call(case, 'submit_repair_impact', assessment_ref=ref, coverage='REVIEWED',
        impacts=known_impacts(evidence), unknowns=[scope_unknown(evidence)])
    assert ready.get('gate') == 'READY_FOR_EXISTING_AUTH', ready
    assert ready['assessment_ref'] == ref and ready['proposal_revision'] == packet['proposal_revision']
    # Correcting host reasoning does not replace the proposal/source revision.
    assert ready['revision'] == blocked['revision']
    assert ready['repair_authorized'] is False and ready['source_modified'] is False
    assert source_hashes(case['root']) == case['before']
    assert case['runtime'].calls == scopes_before == [('download.py',)]
    history, rows = read_report(case, ref)
    saved_unknown = next(row for row in rows if row['row_type'] == 'UNKNOWN')
    assert saved_unknown['classification'] == 'SCOPE_LIMITATION'
    assert saved_unknown['critical'] is False and saved_unknown['decision_basis']
    assert not any(row.get('kind') == 'UNDETERMINED' for row in rows)
    assert history['lifecycle'] == 'CURRENT'
    assert history['unknown_count'] == 1 and history['unread_window_count'] == 0

    prepared = prepare_native(case, ref)
    assert prepared['status'] == 'NATIVE_RISK_FIX_PREPARED' and prepared['ready_for_host_fix'] is True
    assert prepared['authorization']['new_approval_required'] is False
    repair_ref = prepared['repair_task_ref']
    repair_record = case['tasks'].load(case['root'], repair_ref)
    assert repair_ref != case['ref'] and repair_record['phase'] == 'ACTIVE'
    assert repair_record['baseline']['hashes'] == case['before']
    assert repair_record['native_repair']['assessment_ref'] == ref
    assert repair_record['native_repair']['source_hashes'] == case['before']
    assert case['intents'].get()['repair_task_ref'] == repair_ref
    assert source_hashes(case['root']) == case['before']

    # The first repair edit occurs only after the bound pre-edit task exists.
    (case['root'] / 'documents.py').write_text(PATCHED_DOCUMENTS, encoding='utf-8')
    assert case['tasks'].finish(case['root'], repair_ref)['status'] == 'READY'
    review = case['tasks'].prepare(case['root'], repair_ref, protocol_version=3)
    current = {}
    for name in ('documents.py', 'download.py', 'permissions.py', 'sharing.py'):
        high = len((case['root'] / name).read_text(encoding='utf-8').splitlines())
        current[name] = case['tasks'].read(case['root'], repair_ref, review['review_session'],
                                         name, 1, high)['evidence_id']
    expanded = dict(review_session=review['review_session'],
                    plan=case['tasks'].review_plan(case['root'], repair_ref, review['review_session']))
    assert set(complete_plan(case['tasks'], case['root'], repair_ref, expanded)) == set(current)
    resolution = dict(original_task_ref=case['ref'], finding_id=case['finding_id'],
        evidence_refs=list(current.values()), outcome='CODE_REVIEWED_RESOLVED',
        rationale='read_document now uses the existing owner-or-member policy before returning content; download shares it and the list keeps its existing filter.',
        tests='No sample code was executed. Current source and original pre-edit windows were reviewed; this is host code review, not scanner proof.')
    completed = impact_call(case, 'submit_task_security_review', task_ref=repair_ref,
        review_session=review['review_session'], findings=[], coverage='REVIEWED',
        limitations=['External identity binding, repository internals and production behavior are outside this four-file source review.'],
        risk_resolutions=[resolution])
    assert completed.get('status') == 'COMPLETE', completed
    ledger = call(case, 'get_task_risk_ledger', workspace_path=str(case['root']), task_ref=case['ref'])
    assert len(ledger['items']) == 1
    row = ledger['items'][0]
    assert row['finding_id'] == case['finding_id'] and row['status'] == 'CODE_REVIEWED_RESOLVED'
    assert row['evidence_type'] == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
    assert row['review_task_ref'] == repair_ref and ledger['pending_count'] == 0
    after = source_hashes(case['root'])
    assert after['documents.py'] != case['before']['documents.py']
    assert all(after[name] == case['before'][name] for name in ('download.py', 'permissions.py', 'sharing.py'))
    assert case['tasks'].load(case['root'], case['ref'])['baseline'] == case['baseline']
    assert case['runtime'].calls == [('download.py',), ('documents.py',)]


def test_scope_limitation_cannot_hide_an_undetermined_current_business_effect(four_file_case):
    case = four_file_case
    packet, evidence = prepare_and_read(case)
    impacts = known_impacts(evidence)
    impacts[1]['kind'] = 'UNDETERMINED'
    impacts[1]['summary'] = 'The effect on legitimate shared-member reads is not determined for this proposal.'
    blocked = impact_call(case, 'submit_repair_impact', assessment_ref=packet['assessment_ref'],
        coverage='REVIEWED', impacts=impacts, unknowns=[scope_unknown(evidence)])
    assert blocked.get('gate') == 'CRITICAL_CONTEXT_MISSING', blocked
    waiting = prepare_native(case, packet['assessment_ref'])
    assert waiting['ready_for_host_fix'] is False and 'repair_task_ref' not in waiting
    assert len(case['tasks'].store(case['root']).records()) == 1
    assert source_hashes(case['root']) == case['before']
    assert case['runtime'].calls == [('download.py',)]


def test_critical_unknown_about_a_new_permission_dependency_still_blocks(four_file_case):
    case = four_file_case
    proposal = dict(security_goal='Preserve owner/member access while enforcing a new tenant policy.',
        summary='Replace the local policy with an external tenant-membership decision whose implementation is not provided.',
        preserve=['Preserve current owner and shared-member access.'],
        changes=[dict(file_path='documents.py', start_line=1, end_line=3, reason='Call the proposed tenant policy before returning content.'),
                 dict(file_path='permissions.py', start_line=1, end_line=5, reason='Replace local membership semantics with the unprovided dependency.')])
    packet, evidence = prepare_and_read(case, proposal)
    blocked = impact_call(case, 'submit_repair_impact', assessment_ref=packet['assessment_ref'],
        coverage='REVIEWED', impacts=known_impacts(evidence), unknowns=[dict(
            classification='BLOCKING_CONTEXT', critical=True,
            summary='The proposed new tenant-policy dependency is missing, so preservation of the existing owner/member decision cannot be established.',
            decision_basis='Replacing can_read changes the permission decision. The new dependency must show how an existing owner and shared member remain eligible before this proposal can be implemented.',
            evidence_refs=[evidence['permissions.py'], evidence['documents.py']])])
    assert blocked.get('gate') == 'CRITICAL_CONTEXT_MISSING', blocked
    waiting = prepare_native(case, packet['assessment_ref'])
    assert waiting['ready_for_host_fix'] is False and 'repair_task_ref' not in waiting
    assert source_hashes(case['root']) == case['before']
    assert len(case['tasks'].store(case['root']).records()) == 1


def test_public_unknown_contract_and_guidance_explain_scope_limits_without_granting_repairs():
    import json
    server = create_server(global_mode=False)
    schema = server._tool_manager.get_tool('submit_repair_impact').parameters
    unknown = schema['$defs']['RepairImpactUnknown']['properties']
    assert 'classification' in unknown and 'decision_basis' in unknown
    assert 'SCOPE_LIMITATION' in json.dumps(unknown['classification'])
    instructions = server._mcp_server.instructions
    assert 'repair-impact' in instructions
    from security_runtime.host_guidance import RUNTIME_WORKFLOW
    assert 'SCOPE_LIMITATION' in RUNTIME_WORKFLOW and 'decision_basis' in RUNTIME_WORKFLOW
    guidance = structured(asyncio.run(server.call_tool('get_runtime_guidance', {'topic':'repair-impact'})))
    assert guidance['status']=='READY'
    assert 'SCOPE_LIMITATION' in guidance['content'] and 'decision_basis' in guidance['content']
    assert guidance['authority']['repair_authorized'] is False
    assert guidance['authority']['guidance_is_not_authorization'] is True
    info = structured(asyncio.run(server.call_tool('get_runtime_info', {})))
    assert 'repair-impact-v1' in info['features']['repair_impact']
