"""Refresh a choice for an unchanged, never-authorized TLS repair scope.

This handoff is not user consent and never issues an edit grant. The host must
report the explicit choice through the original strict confirmation tool.
"""
from __future__ import annotations

import copy
import hmac
import math
import os
from pathlib import Path
import re
import time

from .equivalence import equivalence_key
from .hook_state import no_links
from .remediation_guard import preservation_proof, source_proof
from .remediation_policy import RULE
from .security_summary import SecuritySummaryService, decode_task_reference

USER_MESSAGE = '当前确认或证据已变化，先重新核查此问题，尚未修复。'
DETECTOR_FIELDS = ('rule_id', 'rule_version', 'rule_pack', 'rule_pack_version',
                   'rule_pack_checksum', 'engine')
MEMBER_FIELDS = ('id', 'fingerprint', 'file_path', 'line_start', 'line_end',
                 'scanner_sources', 'category', 'severity', 'confidence')


class RecoveryRejected(ValueError):
    """Fixed diagnostic only; no rejected claims or scanner prose."""


def failure(service, reason):
    return dict(service._confirmation_fail(
        'CONFIRMATION_RECOVERY_REJECTED_REFRESH_REQUIRED', reason),
        user_message=USER_MESSAGE)


def _require(condition, reason):
    if not condition:
        raise RecoveryRejected(reason)


def _member(scan, family, target):
    members = [finding for finding in scan['findings']
               if equivalence_key(finding) == family]
    _require(len(members) == 1, 'CONFIRMATION_RECOVERY_FAMILY_SCOPE_CHANGED')
    finding = members[0]
    details = finding.get('technical_details', {})
    _require(finding['file_path'] == target and target in scan['target_profile']['files'] and
             finding.get('scanner_sources') == ['semgrep'] and
             finding.get('confidence') == 'HIGH' and finding.get('severity') == 'HIGH' and
             details.get('rule_id') == RULE and details.get('rule_pack') == 'ai-security-core' and
             details.get('engine') == 'semgrep' and
             isinstance(details.get('rule_pack_version'), str) and bool(details['rule_pack_version']) and
             isinstance(details.get('rule_version'), str) and bool(details['rule_version']) and
             isinstance(details.get('rule_pack_checksum'), str) and
             re.fullmatch('[a-f0-9]{64}', details['rule_pack_checksum']),
             'CONFIRMATION_RECOVERY_DETECTOR_SCOPE_CHANGED')
    return finding


def _evidence(service, record, root, key, scan_id):
    mode, policy_binding = service._policy_binding(key)
    _require(mode == 'ask_before_fix' and policy_binding == record.get('policy_binding'),
             'CONFIRMATION_RECOVERY_POLICY_CHANGED')
    snapshot = service._snapshot(root)
    _require(snapshot == record['last_snapshot_digest'] and service._guard(root, record, key),
             'CONFIRMATION_RECOVERY_SOURCE_CHANGED')
    latest = service.store.latest_scan(root)
    _require(latest is not None and latest.get('scan_id') == scan_id and
             Path(latest['target_profile']['path']).resolve() == root,
             'CONFIRMATION_RECOVERY_SCAN_NOT_CURRENT')
    _require(latest.get('status') == 'COMPLETED' and latest.get('coverage') == 'FULL' and
             latest.get('execution_state') == 'EXECUTED' and
             latest.get('capability_results', {}).get('CODE_SAST') == 'EXECUTED',
             'CONFIRMATION_RECOVERY_SCAN_NOT_COMPLETE')
    runs = [run for run in latest.get('scanner_runs', []) if run.get('scanner') == 'semgrep']
    _require(len(runs) == 1 and runs[0].get('status') == 'SUCCESS' and
             runs[0].get('coverage_contract') == 'FULL' and
             isinstance(runs[0].get('version'), str) and bool(runs[0]['version']),
             'CONFIRMATION_RECOVERY_SCANNER_NOT_COMPLETE')
    origin = service.store.get_scan(record['origin_scan_id'])
    _require(origin is not None and origin.get('scan_id') == record['origin_scan_id'] and
             Path(origin['target_profile']['path']).resolve() == root,
             'CONFIRMATION_RECOVERY_ORIGIN_CHANGED')
    original_member = _member(origin, record['family_key'], record['target'])
    current_member = _member(latest, record['family_key'], record['target'])
    _require(all(current_member.get(name) == original_member.get(name) for name in MEMBER_FIELDS) and
             all(current_member.get('technical_details', {}).get(name) ==
                 original_member.get('technical_details', {}).get(name) for name in DETECTOR_FIELDS),
             'CONFIRMATION_RECOVERY_MEMBER_CHANGED')
    origin_runs = [run for run in origin.get('scanner_runs', []) if run.get('scanner') == 'semgrep']
    _require(len(origin_runs) == 1 and origin_runs[0].get('status') == 'SUCCESS' and
             origin_runs[0].get('version') == runs[0]['version'],
             'CONFIRMATION_RECOVERY_ENGINE_VERSION_CHANGED')
    _require(service._member_current(record, root), 'CONFIRMATION_RECOVERY_ORIGINAL_TASK_CHANGED')
    summary = SecuritySummaryService(service.store).get(root, scan_id, details=True, bound_workspace=root)
    tasks = [task for task in summary['tasks']
             if any(member['finding_id'] == current_member['id'] for member in task['members'])]
    _require(len(tasks) == 1 and tasks[0]['finding_count'] == 1 and
             tasks[0]['members'][0]['review_status'] == 'UNTRIAGED',
             'CONFIRMATION_RECOVERY_CURRENT_TASK_CHANGED')
    _require(type(current_member.get('line_start')) is int and
             hmac.compare_digest(record['source_guard'], source_proof(
                 root, record['target'], key, original_line=current_member['line_start'])) and
             hmac.compare_digest(record['preservation_guard'], preservation_proof(root, record['target'], key)),
             'CONFIRMATION_RECOVERY_SOURCE_CHANGED')
    # A new host session may produce current evidence for the same workspace.
    # Never move the saved repair namespace to that session or import its grant.
    hook_paths = list(service.hooks.workspace_directory(root).glob('*.json'))
    _require(len(hook_paths) <= 64, 'CONFIRMATION_RECOVERY_HOOK_BUDGET_EXCEEDED')
    hook_matches = []
    for hook_path in hook_paths:
        hook, corrupt = service.hooks.load(hook_path)
        _require(not corrupt, 'CONFIRMATION_RECOVERY_HOOK_STATE_INVALID')
        if hook is not None and hook['last_scan_id'] == scan_id:
            hook_matches.append(hook)
    _require(len(hook_matches) == 1, 'CONFIRMATION_RECOVERY_HOOK_SCAN_NOT_CURRENT')
    hook = hook_matches[0]
    _require(hook['change_digest'] == snapshot and hook['workspace_id'] == record['workspace_id'],
             'CONFIRMATION_RECOVERY_HOOK_SCOPE_CHANGED')
    checked = hook['last_result']
    family = hook['families'].get(record['family_key'])
    _require(checked.get('status') == 'SCANNED' and checked.get('last_check_status') == 'SCANNED' and
             checked.get('coverage') == 'FULL' and checked.get('execution_state') == 'EXECUTED' and
             isinstance(family, dict) and family.get('count') == 1 and not family.get('uncertain') and
             family.get('file_path') == record['target'],
             'CONFIRMATION_RECOVERY_HOOK_NOT_COMPLETE')
    details = current_member['technical_details']
    proof = family.get('proof', {})
    checked_runs = [run for run in checked.get('scanner_runs', []) if run.get('scanner') == 'semgrep']
    _require(proof.get('rule_pack_checksum') == details['rule_pack_checksum'] and
             proof.get('engine') == details['engine'] and proof.get('rule_version') == details['rule_version'] and
             proof.get('rule_versions') == {RULE: details['rule_version']} and
             len(checked_runs) == 1 and checked_runs[0].get('status') == 'SUCCESS' and
             checked_runs[0].get('coverage_contract') == 'FULL' and
             checked_runs[0].get('version') == runs[0]['version'],
             'CONFIRMATION_RECOVERY_HOOK_DETECTOR_CHANGED')
    _require(service._snapshot(root) == snapshot and service._guard(root, record, key) and
             service._policy_binding(key) == (mode, policy_binding),
             'CONFIRMATION_RECOVERY_EVIDENCE_CHANGED')
    _require(service.store.latest_scan(root) == latest and
             service.store.get_scan(record['origin_scan_id']) == origin,
             'CONFIRMATION_RECOVERY_SCAN_CHANGED_DURING_VALIDATION')
    return snapshot, policy_binding


def refresh_confirmation(service, task_ref, scan_id, root):
    """Rotate a pending choice only; explicit selected fix intent is a host duty."""
    try:
        _require(isinstance(scan_id, str) and bool(re.fullmatch('[A-Za-z0-9-]{1,100}', scan_id)),
                 'CONFIRMATION_RECOVERY_SCAN_INVALID')
        claimed = decode_task_reference(task_ref)
        root = Path(root).resolve()
        no_links(root)
        _require(Path(claimed['workspace']).is_absolute() and
                 not claimed['workspace'].startswith(('\\\\', '//')) and
                 os.path.normcase(os.path.abspath(claimed['workspace'])) == os.path.normcase(str(root)),
                 'CONFIRMATION_RECOVERY_WORKSPACE_CHANGED')
        _require(service.transport.supports_agent_continuation,
                 'CONFIRMATION_RECOVERY_TRANSPORT_UNAVAILABLE')
        directory = service.state.workspace_directory(root)
        _require(directory.exists(), 'CONFIRMATION_RECOVERY_STATE_NOT_FOUND')
        with service.state.lock(root) as acquired:
            _require(acquired, 'REMEDIATION_BUSY')
            key_path = directory / 'snapshot.key'
            no_links(key_path)
            key = key_path.read_bytes()
            _require(len(key) == 32, 'CONFIRMATION_RECOVERY_STATE_INVALID')
            current = service._workspace_families(directory, key)
            matches = [(path, record) for path, record in current.values()
                       if record.get('task_ref') == task_ref]
            _require(len(matches) == 1, 'CONFIRMATION_RECOVERY_TASK_NOT_CURRENT')
            path, record = matches[0]
            rows = service._read(path, key)
            record = rows[record['family_key']]
            _require(record.get('workspace_id') == directory.name and
                     record.get('host_session_namespace') == path.stem,
                     'CONFIRMATION_RECOVERY_NAMESPACE_CHANGED')
            _require(record['phase'] in {'PENDING_CONFIRMATION', 'DECLINED', 'EXPIRED'} and
                     record['attempt_count'] == 0 and record.get('resolution') is None and
                     not any(name in record for name in ('authorization_kind', 'token_hash',
                         'inline_agent_ticket', 'host_continuation')),
                     'CONFIRMATION_RECOVERY_ALREADY_AUTHORIZED_OR_CONSUMED')
            from .remediation import CONFIRMATION_TTL, POLICY_VERSION
            _require(record.get('mode') == 'ask_before_fix' and record.get('policy_version') == POLICY_VERSION,
                     'CONFIRMATION_RECOVERY_POLICY_CHANGED')
            issued, expires, now = (record.get('confirmation_issued_at_epoch'),
                                    record.get('confirmation_expires_at_epoch'), time.time())
            _require(type(issued) in (int, float) and type(expires) in (int, float) and
                     all(math.isfinite(value) for value in (issued, expires, now)) and
                     0 < expires - issued <= CONFIRMATION_TTL and now >= issued,
                     'CONFIRMATION_RECOVERY_DEADLINE_INVALID')
            # A naturally expired pending choice may still belong to an old
            # namespace when the current Hook ran in a new host session. Only
            # still-valid pending choices retain their original deadline.
            keep_deadline = record['phase'] == 'PENDING_CONFIRMATION' and now < expires
            if keep_deadline:
                _require(service._confirmation_remaining(record) > 0,
                         'CONFIRMATION_RECOVERY_PENDING_EXPIRED')
            snapshot, policy_binding = _evidence(service, record, root, key, scan_id)
            candidate = copy.deepcopy(record)
            output = service._pending(path, candidate, snapshot, key, 'ask_before_fix')
            _require(output.get('status') == 'PENDING_CONFIRMATION',
                     output.get('reason_code', 'CONFIRMATION_RECOVERY_BUDGET_EXCEEDED'))
            if keep_deadline:
                for name in ('confirmation_issued_at_epoch', 'confirmation_expires_at_epoch'):
                    candidate[name] = record[name]
            # Re-read all evidence after candidate generation. No record is
            # changed unless the original snapshot/policy/scope still agrees.
            _require(_evidence(service, record, root, key, scan_id) == (snapshot, policy_binding),
                     'CONFIRMATION_RECOVERY_EVIDENCE_CHANGED')
            remaining = service._confirmation_remaining(candidate)
            _require(remaining > 0, 'CONFIRMATION_RECOVERY_PENDING_EXPIRED')
            output['expires_in_seconds'] = max(0, int(remaining))
            rows[record['family_key']] = candidate
            service._save(path, rows, key)
            output['reason_code'] = 'EXPLICIT_SELECTED_FIX_INTENT_PENDING_REFRESHED'
            output['issues_edit_grant'] = False
            return output
    except RecoveryRejected as error:
        return failure(service, str(error))
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        return failure(service, 'CONFIRMATION_RECOVERY_STATE_OR_EVIDENCE_INVALID')
