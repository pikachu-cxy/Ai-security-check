"""User metadata and versioned management operations on the authoritative risk."""
import hashlib
import json
import re
import time
from copy import deepcopy
from .redactor import SecretRedactor


def revision(risk):
    return hashlib.sha256(json.dumps(risk, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def bind_disposition(root, risk):
    from .local_evidence import WorkspaceReader
    raw, _ = WorkspaceReader(root).read(risk['finding']['file_path'])
    risk['management']['source_sha256'] = hashlib.sha256(raw).hexdigest()
    risk['management']['disposition_review_required'] = False


def revalidate_dispositions(root, risks):
    from .local_evidence import WorkspaceReader
    hashes = {}
    for risk in risks.values():
        management = risk.get('management', {})
        if risk.get('disposition') not in {'EXCLUDE', 'DEFER'} or not management.get('source_sha256'):
            continue
        name = risk['finding']['file_path']
        if name not in hashes:
            try:
                raw, _ = WorkspaceReader(root).read(name)
                hashes[name] = hashlib.sha256(raw).hexdigest()
            except (OSError, ValueError):
                hashes[name] = None
        if hashes[name] != management['source_sha256']:
            risk['disposition'] = 'ACTIVE'
            management['disposition_review_required'] = True


def apply(risk, request):
    if not isinstance(request, dict) or set(request) - {'action', 'request_id', 'expected_revision', 'fields', 'reason'}:
        raise ValueError('MANAGEMENT_INVALID_REQUEST')
    key = request.get('request_id')
    if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{8,100}', key):
        raise ValueError('MANAGEMENT_INVALID_REQUEST_ID')
    digest = revision(request)
    management = deepcopy(risk.get('management', {}))
    history = management.setdefault('history', [])
    old = next((h for h in history if h['request_id'] == key), None)
    if old:
        if old['payload_hash'] != digest:
            raise ValueError('MANAGEMENT_REQUEST_REUSED')
        return risk, dict(saved=True, repeated=True, revision=revision(risk))
    if request.get('expected_revision') != revision(risk):
        raise ValueError('MANAGEMENT_VERSION_CONFLICT')
    action = request.get('action')
    if action not in {'EDIT', 'ARCHIVE', 'UNARCHIVE', 'DEFER', 'EXCLUDE', 'RESTORE', 'REPAIR', 'CANCEL_REPAIR'}:
        raise ValueError('MANAGEMENT_INVALID_ACTION')
    reason = request.get('reason', '')
    if not isinstance(reason, str) or len(reason) > 4000 or action in {'DEFER', 'EXCLUDE'} and not reason.strip():
        raise ValueError('MANAGEMENT_REASON_REQUIRED')
    fields = request.get('fields', {})
    if not isinstance(fields, dict) or set(fields) - {'note', 'assignee', 'severity', 'impact', 'target_host'}:
        raise ValueError('MANAGEMENT_INVALID_FIELDS')
    if any(not isinstance(v, str) or len(v) > 4000 for v in fields.values()):
        raise ValueError('MANAGEMENT_INVALID_FIELDS')
    if 'severity' in fields and fields['severity'] not in {'', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}:
        raise ValueError('MANAGEMENT_INVALID_SEVERITY')
    if 'target_host' in fields and fields['target_host'] not in {'codex', 'cursor', 'workbuddy'}:
        raise ValueError('MANAGEMENT_INVALID_HOST')
    redact = SecretRedactor().redact
    fields = {k: redact(v) for k, v in fields.items()}
    changed = deepcopy(risk)
    if action == 'EDIT':
        management.update(fields)
    elif action in {'ARCHIVE', 'UNARCHIVE'}:
        management['archived'] = action == 'ARCHIVE'
    elif action in {'DEFER', 'EXCLUDE', 'RESTORE'}:
        changed['disposition'] = 'ACTIVE' if action == 'RESTORE' else action
        management['disposition_reason'] = redact(reason)
        management['disposition_evidence_revision'] = revision(risk.get('finding', {}))
    elif action == 'REPAIR':
        if risk.get('decision') != 'CONFIRMED' or risk.get('status') == 'CODE_REVIEWED_RESOLVED':
            raise ValueError('MANAGEMENT_REPAIR_REQUIRES_CONFIRMED_RISK')
        prior = management.get('repair_request')
        if not prior or prior['status'] in {'CANCELLED', 'FAILED', 'NEEDS_REVIEW'}:
            management['repair_request'] = dict(id=key, status='AWAITING_HOST',
                target_host=fields.get('target_host', 'codex'), risk_revision=revision(risk),
                evidence_revision=revision(risk.get('finding', {})), created_at=time.time())
    elif action == 'CANCEL_REPAIR':
        job = management.get('repair_request')
        if not job or job['status'] != 'AWAITING_HOST':
            raise ValueError('MANAGEMENT_REPAIR_ALREADY_CLAIMED')
        job['status'] = 'CANCELLED'
    if len(history) >= 1000:
        raise ValueError('MANAGEMENT_HISTORY_CAPACITY')
    history.append(dict(request_id=key, payload_hash=digest, action=action,
                        reason=redact(reason), fields=fields, expected_revision=request.get('expected_revision'), at=time.time()))
    changed['management'] = management
    return changed, dict(saved=True, repeated=False, revision=revision(changed))
