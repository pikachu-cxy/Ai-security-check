"""Durable, version-bound outbox. Reading is not report delivery or consent."""
from __future__ import annotations

import hashlib
import json

CONTRACT = 'development-result-delivery-v1'


def key(ref, sequence):
    if type(sequence) is not int or sequence < 1:
        raise ValueError('DEVELOPMENT_RESULT_SEQUENCE_INVALID')
    return f'delivery:{ref}:{sequence}'


def publish(store, db, row):
    """Called in the SAME transaction as the check's terminal publication."""
    if row['scanned_seq'] < 1:
        return
    reference = key(row['check_ref'], row['scanned_seq'])
    value = dict(kind='delivery', contract=CONTRACT, check_ref=row['check_ref'],
        owner=row['owner'], root_identity=row['root_identity'], scanned_seq=row['scanned_seq'],
        scan_id=row['scan_id'], scan_path=row['scan_path'], result=row.get('result'),
        status=row['state'], reason_code=row.get('reason_code'),
        scope=dict(kind='OBSERVED_FILES', paths=row['observed_paths'], scope_unknown=row['scope_unknown'], full_project=False),
        created_at=store.now(), host_report_submitted=False, continuation_count=0)
    value['result_version'] = hashlib.sha256(json.dumps(value, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()
    previous = store._get(db, reference)
    if previous is not None:
        # Never overwrite an undelivered generation, including on repeated finish.
        if previous['scan_id'] != value['scan_id']:
            raise ValueError('DEVELOPMENT_RESULT_ALREADY_PUBLISHED')
        return
    store._put(db, reference, value)


def pending(store, owner, *, ref=None, rows=None):
    from .development_check import root_identity
    identity = root_identity(store.root)
    return sorted((row for row in (store.rows() if rows is None else rows) if row.get('kind') == 'delivery'
        and row.get('owner') == owner and row.get('root_identity') == identity
        and not row.get('host_report_submitted') and (ref is None or row['check_ref'] == ref)),
        key=lambda row: (row['created_at'], row['key']))


def facts(row, *, summary=False):
    scope = row['scope']
    if summary:
        scope = dict(kind='OBSERVED_FILES', path_count=len(scope['paths']),
                     scope_unknown=scope['scope_unknown'], full_project=False)
    return dict(check_ref=row['check_ref'], scanned_seq=row['scanned_seq'], scan_id=row['scan_id'],
        result_version=row['result_version'], status=row['status'], scope=scope,
        delivery='HOST_REPORTED' if row['host_report_submitted'] else 'PENDING',
        host_report_submitted=row['host_report_submitted'], user_consumption='UNKNOWN',
        repair_authorized=False, next_action=dict(tool='get_development_result', arguments=dict(
            check_ref=row['check_ref'], scanned_seq=row['scanned_seq'], workspace_path=row['workspace'])))


def acknowledge(store, owner, ref, sequence, version):
    """Trusted host embedding ONLY, after observing report submission.

    Deliberately not exposed as an MCP tool: a model's boolean is no delivery proof.
    Human consumption remains unknown even after a real submission callback.
    """
    store.load(ref, owner)
    with store.transaction() as db:
        row = store._get(db, key(ref, sequence))
        if not row or row['owner'] != owner or row['result_version'] != version:
            raise ValueError('DEVELOPMENT_DELIVERY_BINDING_MISMATCH')
        row = store._put(db, row['key'], dict(row, host_report_submitted=True))
    return facts(row)
