"""Owner-bound, read-only source review for feedback on host risk candidates.

Feedback is a separate signed ledger fact, never a source edit, a scanner
verification, a renewed task review, or a change to the original risk status.
"""
from __future__ import annotations

import copy
import ast
import hashlib
import json
import os
import re
from pathlib import PurePosixPath
import time
from threading import RLock
import uuid

from .local_evidence import WorkspaceReader, safe_source, EvidenceUnavailable
from .task_risk_ledger import (TaskRiskLedger, current_hashes, disposition_store,
                               disposition_revision)
from .feedback_redaction import quoted_literals as _quoted_literals


MAX_PACKET_BYTES = 32_000
MAX_PATHS = 10
MAX_CONFIG_PATHS = 20
MAX_EVENTS = 20
TTL = 900
_UNSET = object()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _policy():
    from .build_identity import build_identity
    from .task_security import method
    from .task_review_protocol import PROTOCOL_VERSION
    try:
        identity = build_identity()
        build = identity.get('build_id')
        if (identity.get('status') not in {'DEV', 'IDENTIFIED'} or not isinstance(build, str)
                or len(build) != 64 or any(character not in '0123456789abcdef' for character in build)):
            return None
        guide = method(PROTOCOL_VERSION)
        return _digest(dict(contract='task-risk-feedback-v1', build_id=build,
            method_version=guide['version'], method_sha256=guide['sha256'],
            rule_identity='HOST_CONTEXT_REVIEW; NATIVE_RULES_NOT_APPLICABLE',
            excluded=os.getenv('SECURITY_RUNTIME_EXCLUDE_DIRS', '')))
    except (OSError, ValueError, KeyError):
        return None


def _secret_ranges(record):
    ranges = {}
    for finding in (record.get('static') or {}).get('findings', []):
        if finding.get('category') == 'secret':
            ranges.setdefault(finding['file_path'], []).append(
                (finding['line_start'], finding.get('line_end', finding['line_start'])))
    return ranges


def _known_secrets(root, record):
    """Read bounded known-secret lines locally; never return them to the host."""
    values, incomplete = set(), False
    ranges = _secret_ranges(record)
    if len(ranges) > MAX_PATHS:
        incomplete = True
    for path, spans in list(ranges.items())[:MAX_PATHS]:
        if len(spans) > 20:
            incomplete = True
        try:
            raw, text = WorkspaceReader(root).read(path)
            if hashlib.sha256(raw).hexdigest() != record['end']['hashes'].get(path):
                incomplete = True
                continue
            lines = text.splitlines()
            for low, high in spans[:20]:
                if high-low > 40:
                    incomplete = True
                for line in lines[max(0, low-1):min(high, low+40)]:
                    if len(line) > 1000 or len(values)>64:
                        incomplete = True
                        continue
                    if '`' in line:
                        incomplete = True
                        continue
                    values.add(line.strip())
                    for literal in _quoted_literals(line, strict=True):
                        values.add(literal[1:-1])
                        try:
                            decoded = ast.literal_eval(literal)
                            if isinstance(decoded, str):
                                values.add(decoded)
                        except (SyntaxError, ValueError):
                            incomplete = True
                    match = re.search(r'[:=]\s*([A-Za-z0-9_./+\-=]{8,})', line)
                    if match:
                        values.add(match.group(1))
        except (OSError, ValueError, EvidenceUnavailable, UnicodeError):
            incomplete = True
    return {value for value in values if len(value)>=4}, incomplete


def _scrub_known(value, secrets):
    if isinstance(value, str):
        for secret in sorted(secrets, key=len, reverse=True):
            value = value.replace(secret, '[REDACTED_SECRET]')
        return value
    if isinstance(value, list):
        return [_scrub_known(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _scrub_known(item, secrets) for key, item in value.items()}
    return value


def _config(path):
    name = PurePosixPath(path)
    return (name.suffix.lower() in {'.json', '.yaml', '.yml', '.toml', '.xml', '.properties'}
            or name.name in {'.env', '.gitignore'} or name.name.startswith('.env.'))


def _configuration_state(root):
    from .task_security import _inventory, IGNORED
    ignored = IGNORED | {value.strip() for value in
        os.getenv('SECURITY_RUNTIME_EXCLUDE_DIRS', '').split(',') if value.strip()}
    paths, _, complete, limitations = _inventory(root, ignored)
    selected = [path for path in paths if _config(path)]
    if not complete or limitations or len(selected) > MAX_CONFIG_PATHS:
        return None
    hashes = current_hashes(root, selected)
    return hashes if all(hashes.values()) else None


def project_feedback(row, root, *, configuration=_UNSET):
    """A reversible display projection; original ledger status stays intact."""
    feedback = copy.deepcopy(row.get('feedback'))
    if not feedback:
        return dict(status='NOT_MARKED', folded=False)
    proof = feedback.pop('proof_hashes', {})
    policy = feedback.pop('policy_sha256', None)
    config_hashes = feedback.pop('configuration_hashes', None)
    if feedback['status'] == 'HOST_FALSE_POSITIVE' and configuration is _UNSET:
        configuration = _configuration_state(root)
    if (feedback['status'] == 'HOST_FALSE_POSITIVE' and
            (not proof or current_hashes(root, proof) != proof or policy != _policy()
             or configuration is None or config_hashes != configuration)):
        feedback.update(recorded_status=feedback['status'], status='NEEDS_RECHECK', folded=False,
                        message='误报复核依据对应的源码、配置或检查范围已变化，需要重新核查。')
    return feedback


def project_disposition(hooks, root, row, technical_feedback, *, now=None, include_history=False):
    """User handling, AI assessment and repair status are independent facts."""
    if row.get('assessment_feedback'):
        technical_feedback = project_feedback(dict(feedback=row['assessment_feedback']), root)
    scope = row.get('disposition_scope') or {}
    state = (disposition_store(hooks, root, now=now).status(root, scope['issue_key'],
        current_revision=disposition_revision(root, row), include_history=include_history)
        if scope.get('issue_key') else {})
    kind = state.get('disposition')
    manual = bool(state.get('suppressed'))
    restored = kind == 'RESTORE'
    suppressed = manual or (bool(technical_feedback.get('folded')) and not restored)
    resolution_proof = row.get('proof_hashes') or {}
    resolved = (row['status'] in {'CODE_REVIEWED_RESOLVED', 'VERIFIED_FIXED', 'FIXED', 'RESOLVED'}
                and bool(resolution_proof) and all(resolution_proof.values())
                and current_hashes(root, resolution_proof) == resolution_proof)
    handling = ('RESOLVED' if resolved else 'EXCLUDED' if manual and kind == 'EXCLUDE'
                else 'DEFERRED' if manual and kind == 'DEFER' else 'EXCLUDED'
                if suppressed else 'OPEN')
    labels = {'RESOLVED': '已修复', 'EXCLUDED': '已排除', 'DEFERRED': '已暂缓', 'OPEN': '待处理'}
    source = ('REPAIR_REVIEW' if resolved else 'USER_DECISION' if manual
              else 'AI_ASSESSMENT' if suppressed else 'OPEN')
    return dict(disposition=state, technical_feedback=copy.deepcopy(technical_feedback),
        reminder_suppressed=suppressed or resolved, handling_status=handling,
        handling_label=labels[handling], handling_source=source)


def feedback_for_record(hooks, root, record):
    """Current display facts for original host findings, never rewrite history."""
    ledger = TaskRiskLedger(hooks, root)
    rows = ledger.registration_rows(record, ledger.read()) if record.get('end') else ledger.read()
    selected = [rows.get(record['task_ref']+':'+finding['id'])
                for finding in (record.get('review') or {}).get('findings', [])]
    selected = [row for row in selected if row]
    if not selected:
        return {}
    configuration = (_configuration_state(root) if any(
        (row.get('feedback') or {}).get('status') == 'HOST_FALSE_POSITIVE'
        for row in selected) else None)
    result = {}
    for row in selected:
        technical = project_feedback(row, root, configuration=configuration)
        handling = project_disposition(hooks, root, row, technical)
        result[row['finding_id']] = dict(technical, **handling,
            folded=handling['reminder_suppressed'])
    return result


class TaskRiskFeedbackService:
    def __init__(self, *, now=time.time):
        self.now = now
        self.sessions = {}
        self.session_lock = RLock()

    def _load(self, service, workspace, task_ref, finding_id, *, read_only=False):
        root = service.root(workspace)
        record = service.load(root, task_ref, read_only=read_only)
        ledger = TaskRiskLedger(service.hooks, root)
        rows = ledger.registration_rows(record, ledger.read())
        key = task_ref + ':' + finding_id
        row = rows.get(key)
        if not row or row['source'] != 'HOST_TASK_REVIEW':
            raise ValueError('Use a host task risk candidate; scanner findings use finding feedback')
        finding = next((item for item in (record.get('review') or {}).get('findings', [])
                        if item['id'] == finding_id), None)
        if not finding:
            raise ValueError('Original host risk is unavailable')
        return root, record, ledger, rows, key, finding

    def prepare(self, service, workspace, task_ref, finding_id):
        from .task_review_results import _finding
        root, record, _, rows, key, finding = self._load(service, workspace, task_ref, finding_id)
        row = rows[key]
        policy = _policy()
        known_secrets, secret_context_unknown = _known_secrets(root, record)
        secret_ranges = _secret_ranges(record)
        paths = row['required_source_paths']
        config_paths = sorted(path for path in record['end']['hashes'] if _config(path))
        configuration = _configuration_state(root)
        gaps = []
        if policy is None:
            gaps.append('RUNTIME_BUILD_OR_REVIEW_METHOD_UNAVAILABLE')
        if secret_context_unknown:
            gaps.append('KNOWN_SECRET_CONTEXT_UNAVAILABLE')
        if len(paths) > MAX_PATHS:
            gaps.append('SOURCE_PATH_LIMIT')
        if len(config_paths) > MAX_CONFIG_PATHS:
            gaps.append('CONFIGURATION_PATH_LIMIT')
        if configuration is None:
            gaps.append('CURRENT_CONFIGURATION_SCOPE_UNAVAILABLE')
        elif configuration != {path: record['end']['hashes'][path] for path in config_paths}:
            gaps.append('PROJECT_CONFIGURATION_INVENTORY_CHANGED')
        anchors = dict(row['original_hashes'])
        anchors.update({path: record['end']['hashes'][path]
                        for path in config_paths[:MAX_CONFIG_PATHS]})
        if not all(anchors.values()) or current_hashes(root, anchors) != anchors:
            gaps.append('ORIGINAL_SOURCE_OR_CONFIGURATION_CHANGED')
        category = str(finding.get('category', '')).lower()
        if any(label in category for label in ('secret', 'credential', 'password', 'private_key', 'api_key')):
            gaps.append('SECRET_VALUE_NOT_AVAILABLE_FOR_HOST_VERIFICATION')
        sources = []
        for path in paths[:MAX_PATHS]:
            locations = [location for location in finding.get('evidence_locations', [])
                         if location.get('path') == path]
            if any(location.get('location_version') != 'CURRENT_TASK_END' for location in locations):
                gaps.append('HISTORICAL_SOURCE_IS_NOT_CURRENT:' + path)
            low = max(1, min((location['start_line'] for location in locations), default=1)-3)
            high = max((location['end_line'] for location in locations), default=1)+3
            requested_high = high
            high = min(high, low+39)
            try:
                raw, text = WorkspaceReader(root).read(path)
                truncated = []
                lines = safe_source(text, secret_ranges.get(path, []),
                                    source_path=path, truncation_lines=truncated)
                if any(start <= high and end >= low for start, end in secret_ranges.get(path, [])):
                    gaps.append('KNOWN_SECRET_RANGE_MASKED:' + path)
                high = min(high, len(lines))
                digest = hashlib.sha256(raw).hexdigest()
                if digest != anchors.get(path):
                    gaps.append('SOURCE_VERSION_CHANGED:' + path)
                if low > high:
                    gaps.append('SOURCE_RANGE_UNAVAILABLE:' + path)
                    continue
                if requested_high > low+39 or any(low <= number <= high for number in truncated):
                    gaps.append('SOURCE_WINDOW_LIMIT:' + path)
                sources.append(dict(path=path, start_line=low, end_line=high,
                    evidence_ref='tf-evidence-' + uuid.uuid4().hex,
                    numbered_lines=[f'{number}: {lines[number-1]}' for number in range(low, high+1)],
                    trust='UNTRUSTED_SANITIZED_CURRENT_SOURCE'))
            except (OSError, ValueError, EvidenceUnavailable, UnicodeError):
                gaps.append('SOURCE_UNAVAILABLE:' + path)
        # The full packet, including original explanation, obeys one boundary.
        packet = dict(status='TASK_RISK_FEEDBACK_REVIEW_REQUIRED', task_ref=task_ref,
            finding_id=finding_id, finding=_finding(finding), sources=sources,
            context_complete=not gaps, limitations=sorted(set(gaps)),
            feedback_ref='tfr1-' + uuid.uuid4().hex, expires_at=self.now()+TTL,
            review_type='HOST_CODE_REVIEW_NOT_SCANNER_PROOF',
            scanner_run=False, repair_authorized=False,
            submission_contract=dict(verdict=['FALSE_POSITIVE', 'STILL_RISK', 'NEEDS_CONTEXT'],
                required=['rationale', 'counterevidence', 'evidence_refs'],
                rule='Only complete, unchanged issued source evidence can fold a host-confirmed false positive.'))
        packet = _scrub_known(packet, known_secrets)
        if secret_context_unknown:
            packet['finding'] = dict(id=finding_id, title='原风险说明保留在本地；已知密钥位置无法核验，未返回自由文本。')
            packet['sources'] = []
        while len(json.dumps(packet, ensure_ascii=False).encode()) > MAX_PACKET_BYTES and packet['sources']:
            packet['sources'].pop()
            packet.update(context_complete=False, limitations=['FEEDBACK_RESPONSE_LIMIT'])
        if len(json.dumps(packet, ensure_ascii=False).encode()) > MAX_PACKET_BYTES:
            raise ValueError('Original risk explanation exceeds the feedback response limit')
        with self.session_lock:
            self.sessions = {ref: value for ref, value in self.sessions.items()
                             if value['expires_at'] >= self.now()}
            if len(self.sessions) >= 32:
                raise ValueError('Too many pending feedback reviews')
            self.sessions[packet['feedback_ref']] = dict(root=str(root), task_ref=task_ref,
                finding_id=finding_id, owner=copy.deepcopy(service._owner()), expires_at=packet['expires_at'],
                anchors=anchors, finding_sha256=_digest(finding), context_complete=packet['context_complete'],
                limitations=packet['limitations'], policy_sha256=policy,
                configuration_hashes=configuration,
                evidence_refs=[source['evidence_ref'] for source in packet['sources']])
        return packet

    def _write(self, service, workspace, task_ref, finding_id, event, proof=None, policy=None, configuration=None):
        root = service.root(workspace)
        with service.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return dict(status='BUSY', scanner_run=False, repair_authorized=False)
            root, record, ledger, rows, key, _ = self._load(service, workspace, task_ref, finding_id)
            row = rows[key]
            events = list(row.get('feedback_events') or [])
            if len(events) >= MAX_EVENTS:
                if event['status'] != 'REVOKED':
                    raise ValueError('Feedback audit limit reached; existing events are retained')
                if (row.get('feedback') or {}).get('status') == 'REVOKED':
                    return dict(status='FEEDBACK_RECORDED', task_ref=task_ref, finding_id=finding_id,
                        feedback=project_feedback(row, root), original_risk_status=row['status'],
                        audit_event_count=len(events), scanner_run=False, repair_authorized=False)
                if len(events) > MAX_EVENTS:
                    raise ValueError('Feedback revocation slot is already retained')
            if proof is not None and (not all(proof.values()) or current_hashes(root, proof) != proof
                                      or policy != _policy() or configuration is None
                                      or _configuration_state(root) != configuration):
                raise ValueError('Feedback evidence changed; prepare a fresh feedback review')
            from .task_security import _clean
            event = copy.deepcopy(event)
            secrets, secret_context_unknown = _known_secrets(root, record)
            event = _scrub_known(event, secrets)
            if secret_context_unknown:
                for field in ('rationale', 'reason'):
                    if field in event:
                        event[field] = '[REDACTED_REASON_UNVERIFIABLE_SECRET_CONTEXT]'
                for field in ('counterevidence', 'current_protections', 'unknowns'):
                    if field in event:
                        event[field] = ['[REDACTED_REASON_UNVERIFIABLE_SECRET_CONTEXT]']
            for field in ('rationale', 'reason'):
                if field in event:
                    event[field] = _clean(event[field], 1200)
            for field in ('counterevidence', 'current_protections', 'unknowns'):
                if field in event:
                    event[field] = [_clean(value, 500) for value in event[field]]
            event.update(event_id='tfe1-'+uuid.uuid4().hex, recorded_at=self.now())
            events.append(event)
            row['feedback_events'] = events
            row['feedback'] = dict(event, proof_hashes=proof or {}, policy_sha256=policy,
                                   configuration_hashes=configuration)
            if (event.get('evidence_type') == 'HOST_CODE_REVIEW_NOT_SCANNER_PROOF'
                    or event['status'] == 'REVOKED'):
                row['assessment_feedback'] = copy.deepcopy(row['feedback'])
            ledger.save(rows)
            scope = row.get('disposition_scope') or {}
            if event['status'] == 'STILL_PRESENT' and proof is not None and scope.get('issue_key'):
                revision, precise = disposition_revision(root, row, with_precision=True)
                decisions = disposition_store(service.hooks, root, now=self.now)
                saved_choice = decisions.status(root, scope['issue_key'], current_revision=revision)
                if precise and saved_choice.get('active') and saved_choice.get('reassessment_required'):
                    decisions.confirm_material_change(
                        root, scope['issue_key'], revision, assessment_id=event['event_id'],
                        verdict='STILL_RISK', fresh=True, evidence_backed=True)
            result = project_feedback(row, root)
            return dict(status='FEEDBACK_RECORDED', task_ref=task_ref, finding_id=finding_id,
                feedback=result, original_risk_status=row['status'], audit_event_count=len(events),
                scanner_run=False, repair_authorized=False)

    def submit(self, service, workspace, task_ref, finding_id, feedback_ref, verdict,
               rationale, counterevidence, evidence_refs, current_protections=None, unknowns=None):
        # Consume a connection-local token at most once, including concurrent
        # transport calls. Workspace state has its own signed-file lock below.
        with self.session_lock:
            return self._submit(service, workspace, task_ref, finding_id, feedback_ref, verdict,
                                rationale, counterevidence, evidence_refs, current_protections, unknowns)

    def _submit(self, service, workspace, task_ref, finding_id, feedback_ref, verdict,
                rationale, counterevidence, evidence_refs, current_protections=None, unknowns=None):
        root, _, _, _, _, finding = self._load(service, workspace, task_ref, finding_id)
        session = self.sessions.get(feedback_ref)
        if (not session or session['root'] != str(root) or session['task_ref'] != task_ref
                or session['finding_id'] != finding_id or session['owner'] != service._owner()
                or session['expires_at'] < self.now() or session['finding_sha256'] != _digest(finding)):
            raise ValueError('Feedback review is expired, consumed, or belongs to another session')
        if verdict not in {'FALSE_POSITIVE', 'STILL_RISK', 'NEEDS_CONTEXT'}:
            raise ValueError('Invalid feedback verdict')
        if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 1200:
            raise ValueError('A bounded feedback rationale is required')
        current_protections = [] if current_protections is None else current_protections
        unknowns = [] if unknowns is None else unknowns
        for values in (counterevidence, current_protections, unknowns):
            if (not isinstance(values, list) or len(values) > 10 or
                    any(not isinstance(value, str) or not value.strip() or len(value)>500 for value in values)):
                raise ValueError('Use bounded feedback evidence and uncertainty lists')
        if (not isinstance(evidence_refs, list) or len(evidence_refs)>MAX_PATHS
                or any(not isinstance(ref, str) for ref in evidence_refs)
                or len(set(evidence_refs)) != len(evidence_refs)
                or any(ref not in session['evidence_refs'] for ref in evidence_refs)):
            raise ValueError('Feedback requires original issued evidence references')
        complete = (session['context_complete'] and bool(counterevidence) and not unknowns
                    and set(evidence_refs) == set(session['evidence_refs']) and bool(evidence_refs))
        status = ('HOST_FALSE_POSITIVE' if verdict == 'FALSE_POSITIVE' and complete else
                  'STILL_PRESENT' if verdict == 'STILL_RISK' and complete else 'INCONCLUSIVE')
        event = dict(status=status, requested_verdict=verdict, rationale=rationale,
                     counterevidence=counterevidence, current_protections=current_protections,
                     unknowns=unknowns, evidence_refs=evidence_refs,
                     limitations=list(session['limitations']), folded=status == 'HOST_FALSE_POSITIVE',
                     evidence_type='HOST_CODE_REVIEW_NOT_SCANNER_PROOF')
        result = self._write(service, workspace, task_ref, finding_id, event,
                             session['anchors'] if status != 'INCONCLUSIVE' else None,
                             session['policy_sha256'], session['configuration_hashes'])
        if result['status'] == 'FEEDBACK_RECORDED':
            del self.sessions[feedback_ref]
        return result

    def mark(self, service, workspace, task_ref, finding_id, reason, *, user_requested=False):
        if user_requested is not True:
            raise ValueError('User marking requires an explicit user request')
        if not isinstance(reason, str) or not reason.strip() or len(reason)>1200:
            raise ValueError('A bounded user reason is required')
        return self._write(service, workspace, task_ref, finding_id,
            dict(status='USER_MARKED_FALSE_POSITIVE', reason=reason, folded=False,
                 evidence_type='USER_REPORT_NOT_CONFIRMED'))

    def revoke(self, service, workspace, task_ref, finding_id, reason, *, user_requested=False):
        if user_requested is not True:
            raise ValueError('Revocation requires an explicit user request')
        if not isinstance(reason, str) or not reason.strip() or len(reason)>1200:
            raise ValueError('A bounded revocation reason is required')
        return self._write(service, workspace, task_ref, finding_id,
            dict(status='REVOKED', reason=reason, folded=False, evidence_type='USER_REVOKED'))

    def set_disposition(self, service, workspace, task_ref, finding_id, disposition,
                        reason='', *, user_requested=False, until=None, request_id=None):
        """Apply the user's handling choice without asking an AI to approve it."""
        if user_requested is not True:
            raise ValueError('A direct user request is required for this reminder choice')
        if not isinstance(reason, str) or len(reason) > 1200:
            raise ValueError('Use a bounded optional disposition reason')
        root = service.root(workspace)
        with service.hooks.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                return dict(status='BUSY', scanner_run=False, repair_authorized=False)
            root, record, ledger, rows, key, _ = self._load(
                service, workspace, task_ref, finding_id)
            row = rows[key]
            scope = row.get('disposition_scope') or {}
            if not scope.get('issue_key'):
                # A missing historical source cannot remove the user's right
                # to handle this exact, owner-validated finding. This fallback
                # deliberately never matches a finding in another task.
                scope = dict(issue_key='rd1-history-'+_digest([task_ref, finding_id]),
                    evidence_revision=None, metadata=dict(evidence_scope='HISTORY_REFERENCE',
                                                          material_change_confirmable=False))
                row['disposition_scope'] = scope
            secrets, unknown = _known_secrets(root, record)
            safe_reason = ('[REDACTED_REASON_UNVERIFIABLE_SECRET_CONTEXT]' if unknown
                           else _scrub_known(reason, secrets))
            # Persist only locators/digests so reads can still identify the
            # selected issue when its original source later becomes unavailable.
            ledger.save(rows)
            store = disposition_store(service.hooks, root, now=self.now)
            state = store.set(root, scope['issue_key'], disposition, safe_reason,
                user_requested=True, until=until, request_id=request_id,
                evidence_revision=disposition_revision(root, row),
                metadata=dict(scope.get('metadata') or {}, reference=_digest([task_ref, finding_id])))
            history = state.pop('history', [])
            handling = project_disposition(service.hooks, root, row,
                project_feedback(row, root), now=self.now)
            messages = {
                'EXCLUDE': '已按你的决定排除此项，不再重复提醒。技术评估和原风险记录仍保留，可随时恢复提醒。',
                'DEFER': '已暂缓此项，本次不再追问。风险记录仍保留，可随时恢复处理。',
                'RESTORE': '已恢复此项提醒，原有技术评估和处置历史仍保留。',
            }
            return dict(status='DISPOSITION_RECORDED', task_ref=task_ref, finding_id=finding_id,
                **handling, original_risk_status=row['status'],
                audit_event_count=len(history), message=messages[disposition],
                scanner_run=False, repair_authorized=False, raw_findings_changed=False)

    def get(self, service, workspace, task_ref, finding_id, offset=0, limit=2):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 2:
            raise ValueError('Use bounded feedback audit pages')
        root, _, _, rows, key, _ = self._load(service, workspace, task_ref, finding_id, read_only=True)
        row = rows[key]
        events = row.get('feedback_events') or []
        projected = project_feedback(row, root)
        compact = {key: projected[key] for key in
                   ('status', 'folded', 'recorded_status', 'evidence_type', 'recorded_at', 'event_id', 'message')
                   if key in projected}
        packet = dict(task_ref=task_ref, finding_id=finding_id, feedback=compact,
            audit_events=copy.deepcopy(events[offset:offset+limit]),
            current_event_offset=len(events)-1 if events else None,
            original_risk_status=row['status'], scanner_run=False, repair_authorized=False)
        handling = project_disposition(service.hooks, root, row, projected,
                                        now=self.now, include_history=True)
        disposition_history = handling['disposition'].pop('history', [])
        packet.update(handling)
        packet['disposition_audit_events'] = disposition_history[offset:offset+limit]
        packet['disposition_audit_page'] = dict(offset=offset, total_count=len(disposition_history),
            next_offset=offset+limit if offset+limit < len(disposition_history) else None)
        while len(json.dumps(packet, ensure_ascii=False).encode()) > MAX_PACKET_BYTES and len(packet['audit_events'])>1:
            packet['audit_events'].pop()
        packet['audit_page'] = dict(offset=offset, total_count=len(events),
            next_offset=offset+len(packet['audit_events']) if offset+len(packet['audit_events'])<len(events) else None)
        if len(json.dumps(packet, ensure_ascii=False).encode()) > MAX_PACKET_BYTES:
            packet['audit_events'] = []
            packet.update(reason_code='FEEDBACK_AUDIT_DETAIL_LIMIT', audit_details_complete=False)
            packet['audit_page']['next_offset'] = offset
        return packet
