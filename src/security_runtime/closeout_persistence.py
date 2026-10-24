"""Durable closeout-to-closure facts; replay never executes a provider.

The source transaction holds its intended receipt and a pending public receipt.
The target's inbox precedes source acknowledgement. Session cleanup uses only
the captured namespace/version and pending sequence, never a newest session.
"""
from __future__ import annotations

import copy
import hashlib
import re
import sqlite3

from .closeout_state import digest, encode

CONTRACT = 'closeout-persistence-v1'
MAX_EFFECTS = 2000
MAX_PENDING = 512
MAX_EFFECT_BYTES = 1_000_000
FLAGS = ('current_version', 'check_completed', 'credential_closure_complete', 'risk_fix_complete')


def hook_revision(key, state):
    if state is None:
        return None
    if state.get('schema_version') == 'hook-product-epoch-v1':
        return digest(key, {name: state.get(name) for name in ('schema_version', 'workspace_id',
            'host', 'session_id', 'root_identity', 'epoch_ref', 'policy_digest',
            'kind', 'consistency', 'representation', 'last_processed_ref')})
    # Closure projections may change families/delta; they cannot change the
    # originating scan, source snapshot, host or session represented here.
    return digest(key, {name: state.get(name) for name in ('workspace_id', 'host',
        'session_id', 'last_scan_id', 'change_digest', 'file_digests', 'last_completed_at')})


def make_effect(job, receipt, *, status, coverage, reason, versions, activity_rows,
                closure_version, hook_binding, lease, key):
    body = dict(contract=CONTRACT, closeout_ref=job['closeout_ref'],
        workspace_id=job['workspace_id'], generation=job['generation'],
        scope_files=job['scope_files'], details=copy.deepcopy(job['details']),
        deferred_providers=job['deferred_providers'], receipt=copy.deepcopy(receipt),
        status=status, coverage=coverage, reason=reason, source_versions=dict(versions),
        activity_rows=copy.deepcopy(activity_rows), closure_version=closure_version,
        hook_binding=hook_binding, lease=dict(lease))
    event_id = 'coe1-' + hashlib.sha256(encode(body)).hexdigest()
    effect = dict(body, event_id=event_id)
    effect['pending_receipt_sha256'] = digest(key, pending_receipt(effect))
    validate_effect(effect)
    return effect


def validate_effect(effect):
    if not isinstance(effect, dict):
        raise ValueError('Closeout persistence cannot be verified')
    body = {k: v for k, v in effect.items() if k not in {'event_id', 'pending_receipt_sha256'}}
    if (effect.get('contract') != CONTRACT
            or not re.fullmatch(r'co1-[a-f0-9]{32}', effect.get('closeout_ref', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', effect.get('workspace_id', ''))
            or type(effect.get('generation')) is not int or effect['generation'] < 1
            or effect.get('status') not in {'COMPLETED', 'NEEDS_RETRY'}
            or not isinstance(effect.get('source_versions'), dict)
            or not isinstance(effect.get('receipt'), dict)
            or not isinstance(effect.get('details'), dict)
            or not isinstance(effect.get('activity_rows'), list)
            or len(effect['activity_rows']) > 64
            or not isinstance(effect.get('lease'), dict)
            or effect.get('event_id') != 'coe1-' + hashlib.sha256(encode(body)).hexdigest()
            or not re.fullmatch(r'[a-f0-9]{64}', effect.get('pending_receipt_sha256', ''))
            or len(encode(effect)) > MAX_EFFECT_BYTES):
        raise ValueError('Closeout persistence cannot be verified')


def pending_receipt(effect):
    receipt = copy.deepcopy(effect['receipt'])
    receipt.update({name: False for name in FLAGS})
    receipt.update(persistence_status='INCOMPLETE', persistence_sync=dict(state='PENDING'),
        persistence_effect_id=effect['event_id'])
    return receipt


def source_matches(store, job, effect):
    return (job is not None and job['workspace_id'] == effect['workspace_id']
        and job['closeout_ref'] == effect['closeout_ref']
        and job['generation'] == effect['generation'] and job['lease_owner'] is None
        and job['status'] == 'NEEDS_RETRY'
        and digest(store.key_reader(), job.get('receipt')) == effect['pending_receipt_sha256'])


def _source_current(service, root, effect):
    details = effect['details']
    if details.get('product_epoch_binding') is not None:
        state, corrupt = service.hooks.load(service.hooks.path(root, details['host'], details['session']))
        if corrupt or hook_revision(service._read_key(root), state) != details['product_epoch_binding']:
            return False
    return (service._source_revisions(root, effect['scope_files']) == effect['source_versions']
        and service._plan(root, effect['scope_files'], effect['details']['members'],
            effect['deferred_providers'], effect['details'].get('scope_exclusions', ()))
            == effect['receipt']['plan_fingerprint'])


def _activity_current(service, root, effect, *, target_applied=False):
    current = service.closures.activity_snapshot(root)
    expected = effect['activity_rows']
    if current == expected:
        return True
    details = effect['details']
    if target_applied and details.get('session_key') and details.get('pending_sequence'):
        # A retry after clearing exactly this pending target must still ACK.
        # A new sequence or any other changed session remains a conflict.
        remainder = [row for row in expected if row !=
            [details['session_key'], details['pending_sequence']]]
        return current == remainder
    return False


def _session_cleanup(service, root, effect):
    if effect['status'] != 'COMPLETED':
        return
    details = effect['details']
    if not details.get('session_key'):
        return
    path, state, _ = service._session_cache(root, details['host'], details['session'],
        kind=details.get('scanner_cache_kind', 'LEGACY_SESSION'))
    if details.get('product_epoch_binding') is not None:
        primary, corrupt = service.hooks.load(service.hooks.path(root, details['host'], details['session']))
        if corrupt or hook_revision(service._read_key(root), primary) != details['product_epoch_binding']:
            raise ValueError('Closeout product comparison binding changed')
    if state and hook_revision(service._read_key(root), state) == effect['hook_binding']:
        if state['last_result'].get('deferred_code_providers'):
            state['last_result']['deferred_code_providers'] = []
            service.hooks.save(path, state)
    if details.get('pending_sequence'):
        service.hooks.pending_activity(root, details['host'], details['session'],
            completed=details['pending_sequence'])


def _finish_lane(service, root, effect, outcome):
    from .scan_attempt import AttemptLease, ScanAttemptStore
    attempts = ScanAttemptStore(service.hooks, root)
    lease = AttemptLease(**effect['lease'])
    attempts.finish(lease, input_id=effect['receipt']['scan_attempt']['input_id'],
        scan_id=effect['receipt']['scan_id'], outcome=outcome)


def drain(service, root, ref, *, limit=8):
    """Recover one requested source outside provider execution and source IO locks."""
    store = service._store(root)
    effects = store.pending_effects(ref, service._workspace(root), limit=limit)
    if not effects:
        return None
    applied = superseded = errors = 0
    for effect in effects:
        try:
            current_source = _source_current(service, root, effect)  # Source IO outside OS lock.
            with service.hooks.lock(root) as acquired:
                if not acquired:
                    return dict(job=store.get(ref, service._workspace(root)), state='PENDING',
                        applied=applied, superseded=superseded, errors=errors)
                job = store.get(ref, service._workspace(root))
                service.closures.resume(root)  # Legitimate mutation may resume its authenticated migration.
                prior = service.closures.effect_receipt(root, effect['event_id'])
                applicable = (source_matches(store, job, effect) and current_source
                    and _activity_current(service, root, effect, target_applied=prior is not None))
                if not applicable:
                    store.acknowledge_effect(effect, outcome='SUPERSEDED')
                    _finish_lane(service, root, effect, 'STALE')
                    superseded += 1
                    continue
                result = service.closures.record(root, effect['details']['members'],
                    effect['receipt']['risk_verification'], source=effect['details']['source'],
                    generation=effect['generation'], closeout_ref=ref,
                    expected_activity=digest(b'activity-epoch', effect['activity_rows']),
                    expected_version=effect['closure_version'], effect_id=effect['event_id'], locked=True)
                expected = sum(m['scanner_sources'] == ['gitleaks'] and
                    r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for m, r in
                    zip(effect['details']['members'], effect['receipt']['risk_verification']))
                if result['status'] in {'SUPERSEDED', 'NEW_ACTIVITY'} or result.get('confirmed') != expected:
                    store.acknowledge_effect(effect, outcome='SUPERSEDED')
                    _finish_lane(service, root, effect, 'STALE')
                    superseded += 1
                    continue
                if result['status'] != 'SAVED':
                    raise ValueError('Closeout target is pending')
                _session_cleanup(service, root, effect)
            still_source = _source_current(service, root, effect)  # Recheck outside lock before ACK.
            with service.hooks.lock(root) as acquired:
                if not acquired:
                    errors += 1
                    continue
                applicable = (still_source and _activity_current(service, root, effect, target_applied=True)
                    and service.closures.effect_current(root, effect['event_id']))
                outcome = 'APPLIED' if applicable else 'SUPERSEDED'
                _, accepted = store.acknowledge_effect(effect, outcome=outcome)
                if not accepted:
                    superseded += 1
                elif outcome == 'APPLIED':
                    applied += 1
                else:
                    superseded += 1
                _finish_lane(service, root, effect,
                    ('COMPLETED' if effect['status'] == 'COMPLETED' else 'FAILED')
                    if accepted and outcome == 'APPLIED' else 'STALE')
        except (ValueError, OSError, sqlite3.DatabaseError):
            errors += 1  # Source remains signed and pending, including target-before-ACK failures.
    pending = store.pending_effects(ref, service._workspace(root), limit=limit)
    return dict(job=store.get(ref, service._workspace(root)), state='PENDING' if pending else
        'APPLIED' if applied else 'SUPERSEDED', applied=applied, superseded=superseded, errors=errors)
