"""Transactional, I/O-free state transitions for incremental business audits.

Callers persist the mutated check in their existing transaction. Evidence validity
and owner authorization belong to the service; lease expiry never erases results.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

CONTRACT = 'incremental-business-audit-v1'
LEASE_SECONDS = 300
MAX_ROUNDS = 256
MAX_BATCHES = 1024
MAX_RECEIPTS = 1024
MAX_RESULT_BYTES = 8_000_000


def _require(ok, reason):
    if not ok:
        raise ValueError(reason)


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def enabled(check):
    return bool(check.get('effective_config', {}).get('values', {}).get('agent', {}).get('audit_business_logic'))


def _stream(check):
    return check.setdefault('audit_stream', dict(contract=CONTRACT, rounds=[], batches={}, receipts={},
                                                dependents={}, latest_versions={}, accepted_current={}))


def _round(stream, round_id=None):
    return next((r for r in stream['rounds'] if r['round_id'] == round_id), None) if round_id else (
        stream['rounds'][-1] if stream['rounds'] else None)


def record_changes(check, paths):
    """Merge recorded paths; disabled checks do not allocate or read any state."""
    if not enabled(check) or not paths:
        return
    names = list(dict.fromkeys(paths))
    _require(all(isinstance(p, str) and p for p in names), 'BUSINESS_AUDIT_PATH_INVALID')
    stream = _stream(check)
    current = _round(stream)
    if current is None or current['cutoff_seq'] is not None:
        _require(len(stream['rounds']) < MAX_ROUNDS, 'BUSINESS_AUDIT_CAPACITY_REQUIRED')
        current = dict(round_id='ar-'+secrets.token_hex(12), start_seq=check['dirty_seq'],
                       cutoff_seq=None, required={}, pending={}, accepted={})
        stream['rounds'].append(current)
    affected = set(names)
    for name in names:
        affected.update(stream['dependents'].get(name, []))
    # A frozen historical input cannot be re-read after a subsequent edit.
    # Retain its pending obligation explicitly, but never starve newer work.
    for older in stream['rounds']:
        if older is current:
            continue
        for name in affected & set(older['pending']):
            older.setdefault('superseded', {})[name] = check['dirty_seq']
    for name in sorted(affected):
        stream.setdefault('latest_versions', {})[name] = check['dirty_seq']
        stream.setdefault('accepted_current', {}).pop(name, None)
        current['required'][name] = check['dirty_seq']
        current['pending'][name] = check['dirty_seq']
        current['accepted'].pop(name, None)


def cutoff(check, paths=None):
    """Seal once; later edits create a new round. Optional paths are filtered inputs."""
    if not enabled(check):
        return None
    stream = _stream(check)
    current = _round(stream)
    if current is None:
        record_changes(check, list(paths if paths is not None else check.get('observed_paths', [])))
        current = _round(stream)
    if current is None:
        return None
    if current['cutoff_seq'] is None:
        if paths is not None:
            related = {p for targets in stream['dependents'].values() for p in targets}
            allowed = set(paths) | related
            for name, seq in current['required'].items():
                if name not in allowed and stream.get('latest_versions', {}).get(name) == seq:
                    stream['latest_versions'].pop(name, None)
                    stream.get('accepted_current', {}).pop(name, None)
            for field in ('required', 'pending', 'accepted'):
                current[field] = {p: v for p, v in current[field].items() if p in allowed}
        current['cutoff_seq'] = check['dirty_seq']
        grant = check.get('audit_delegate') or {}
        if not current['pending'] and grant.get('round_id') == current['round_id']:
            grant['closed'] = True
    return current['round_id']


seal = cutoff


def authenticate(check, batch_id, token, agent_ref=None):
    batch = check.get('audit_stream', {}).get('batches', {}).get(batch_id)
    _require(batch is not None, 'BUSINESS_AUDIT_BATCH_UNKNOWN')
    _require(isinstance(token, str) and hmac.compare_digest(batch['token_hash'],
             hashlib.sha256(token.encode()).hexdigest()), 'BUSINESS_AUDIT_TOKEN_INVALID')
    _require(agent_ref is None or agent_ref == batch['agent_ref'], 'BUSINESS_AUDIT_EXECUTOR_MISMATCH')
    _require(batch['status'] != 'CANCELLED', 'BUSINESS_AUDIT_BATCH_CANCELLED')
    return batch


def claim(check, agent_ref, *, now=None, limit=50, token=None, round_id=None):
    """One active batch per executor; caller may supply its issued task capability."""
    _require(enabled(check), 'BUSINESS_AUDIT_DISABLED')
    _require(isinstance(agent_ref, str) and 0 < len(agent_ref) <= 200, 'BUSINESS_AUDIT_AGENT_REQUIRED')
    _require(type(limit) is int and 1 <= limit <= 50, 'BUSINESS_AUDIT_LIMIT')
    now = time.time() if now is None else now
    stream = _stream(check)
    for batch in stream['batches'].values():
        if round_id is not None and batch['round_id'] != round_id:
            continue
        if batch['agent_ref'] == agent_ref and batch['status'] in {'RUNNING', 'RECEIVED'}:
            if token is not None:
                authenticate(check, batch['batch_id'], token, agent_ref)
            return {k: v for k, v in batch.items() if k != 'token_hash'}
    held = {(b['round_id'], p, seq) for b in stream['batches'].values()
            if b['status'] in {'RUNNING', 'RECEIVED'} for p, seq in b['versions'].items()}
    for current in stream['rounds']:
        if round_id is not None and current['round_id'] != round_id:
            continue
        versions = dict((p, seq) for p, seq in current['pending'].items()
                        if p not in current.get('superseded', {})
                        and (current['round_id'], p, seq) not in held)
        versions = dict(list(versions.items())[:limit])
        if not versions:
            continue
        _require(len(stream['batches']) < MAX_BATCHES, 'BUSINESS_AUDIT_CAPACITY_REQUIRED')
        token = token or secrets.token_urlsafe(32)
        _require(isinstance(token, str) and len(token) >= 24, 'BUSINESS_AUDIT_TOKEN_INVALID')
        batch = dict(batch_id='ab-'+secrets.token_hex(12), round_id=current['round_id'],
                     versions=versions, agent_ref=agent_ref, status='RUNNING', created_at=now,
                     lease_until=now+LEASE_SECONDS, token_hash=hashlib.sha256(token.encode()).hexdigest())
        stream['batches'][batch['batch_id']] = batch
        return dict({k: v for k, v in batch.items() if k != 'token_hash'}, token=token)
    return dict(status='CAUGHT_UP', batch_id=None)


def renew(check, batch_id, token, *, now=None):
    batch = authenticate(check, batch_id, token)
    _require(batch['status'] in {'RUNNING', 'RECEIVED'}, 'BUSINESS_AUDIT_STATE_INVALID')
    batch['lease_until'] = (time.time() if now is None else now)+LEASE_SECONDS


def receive(check, batch_id, token, request_id, payload, *, now=None):
    """Persist received results before evidence verification, including late results."""
    batch = authenticate(check, batch_id, token)
    _require(isinstance(request_id, str) and 8 <= len(request_id) <= 128, 'BUSINESS_AUDIT_REQUEST_INVALID')
    stream = _stream(check)
    payload_hash = _digest(payload)
    previous = stream['receipts'].get(request_id)
    if previous:
        _require(previous['batch_id'] == batch_id and previous['payload_hash'] == payload_hash,
                 'BUSINESS_AUDIT_REQUEST_CONFLICT')
        return previous
    _require(batch['status'] == 'RUNNING', 'BUSINESS_AUDIT_RESULT_ALREADY_RECEIVED')
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
    size = len(encoded)
    _require(len(stream['receipts']) < MAX_RECEIPTS and
             stream.get('retained_payload_bytes', 0)+size <= MAX_RESULT_BYTES,
             'BUSINESS_AUDIT_CAPACITY_REQUIRED')
    now = time.time() if now is None else now
    receipt = dict(request_id=request_id, batch_id=batch_id, payload_hash=payload_hash,
                   payload=json.loads(json.dumps(payload)), received_at=now,
                   late=now > batch['lease_until'], status='RECEIVED', applied_paths=[])
    stream['receipts'][request_id] = receipt
    stream['retained_payload_bytes'] = stream.get('retained_payload_bytes', 0)+size
    batch.update(status='RECEIVED', request_id=request_id)
    return receipt


def complete(check, batch_id, request_id, valid_paths, *, dependencies=None):
    """Apply only service-validated evidence. Changed queued versions remain pending."""
    stream = _stream(check)
    batch = stream['batches'].get(batch_id)
    receipt = stream['receipts'].get(request_id)
    _require(batch and batch['status'] != 'CANCELLED', 'BUSINESS_AUDIT_BATCH_CANCELLED')
    _require(receipt and receipt['batch_id'] == batch_id, 'BUSINESS_AUDIT_RECEIPT_UNKNOWN')
    if receipt['status'] != 'RECEIVED':
        return receipt
    valid = set(valid_paths)
    _require(valid <= set(batch['versions']), 'BUSINESS_AUDIT_PATH_OUTSIDE_BATCH')
    current = _round(stream, batch['round_id'])
    applied = []
    for name in sorted(valid):
        seq = batch['versions'][name]
        if current['required'].get(name) != seq or name in current.get('superseded', {}):
            continue
        current['accepted'][name] = dict(seq=seq, request_id=request_id)
        if stream.get('latest_versions', {}).get(name) == seq:
            stream.setdefault('accepted_current', {})[name] = dict(seq=seq, request_id=request_id)
        current['pending'].pop(name, None)
        applied.append(name)
    for name in applied:
        for dependency in (dependencies or {}).get(name, []):
            targets = stream['dependents'].setdefault(dependency, [])
            if name not in targets:
                targets.append(name)
    receipt.update(status='APPLIED' if len(applied) == len(batch['versions']) else 'NEEDS_REVIEW',
                   applied_paths=applied)
    batch['status'] = 'COMPLETE'
    return receipt


def cancel(check, batch_id):
    batch = check.get('audit_stream', {}).get('batches', {}).get(batch_id)
    _require(batch is not None, 'BUSINESS_AUDIT_BATCH_UNKNOWN')
    batch['status'] = 'CANCELLED'


def progress(check, round_id=None, *, now=None):
    stream = check.get('audit_stream')
    if not stream:
        return dict(status='NOT_STARTED' if enabled(check) else 'DISABLED', pending_paths=[])
    current = _round(stream, round_id)
    if current is None:
        return dict(status='NOT_STARTED', pending_paths=[])
    now = time.time() if now is None else now
    active = [b for b in stream['batches'].values() if b['round_id'] == current['round_id']
              and b['status'] in {'RUNNING', 'RECEIVED'}]
    pending = sorted(current['pending'])
    superseded = sorted(set(pending) & set(current.get('superseded', {})))
    state = ('COMPLETE' if current['cutoff_seq'] is not None else 'CAUGHT_UP') if not pending else (
        'SUPERSEDED' if pending == superseded else
        'RESULT_PENDING' if any(b['status'] == 'RECEIVED' for b in active) else
        'INTERRUPTED' if active and all(b['lease_until'] < now for b in active) else
        'RUNNING' if active else 'READY')
    return dict(status=state, round_id=current['round_id'], cutoff_seq=current['cutoff_seq'],
                pending_paths=pending, superseded_paths=superseded, reviewed_paths=sorted(current['accepted']),
                active_batch_ids=[b['batch_id'] for b in active])
