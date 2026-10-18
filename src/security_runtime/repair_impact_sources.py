"""Resolve existing risk identities for impact analysis, without starting a scan.

Scanner groups, development tasks and analysis references remain distinct.
Historical reads never claim ownership of the originating development task.
"""
from __future__ import annotations

import hashlib
import json


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(',', ':')).encode()).hexdigest()


def resolve_impact_source(source, workspace, scan_store, task_service):
    if not isinstance(source, dict):
        raise ValueError('IMPACT_SOURCE_INVALID')
    allowed = {'kind', 'task_ref', 'finding_id', 'origin_review_revision'}
    if set(source) - allowed or not isinstance(source.get('task_ref'), str):
        raise ValueError('IMPACT_SOURCE_INVALID')
    kind = source.get('kind')
    if kind == 'SCANNER_TASK_GROUP':
        if set(source) - {'kind', 'task_ref'}:
            raise ValueError('IMPACT_SOURCE_INVALID')
        from .task_fix import TaskFixService
        prepared = TaskFixService(scan_store).prepare(source['task_ref'], workspace,
                                                     bound_workspace=workspace)
        members = prepared.get('affected_findings', [])
        if not members or prepared.get('affected_findings_truncated'):
            raise ValueError('IMPACT_SOURCE_UNAVAILABLE')
        if prepared.get('status') not in {'READY_FOR_HOST_FIX', 'EVIDENCE_INCOMPLETE'}:
            raise ValueError('IMPACT_SOURCE_UNAVAILABLE')
        member_ids = sorted(m['finding_id'] for m in members)
        paths = sorted({m['file'] for m in members})
        scan = scan_store.get_scan(prepared['scan_id'])
        secrets = {}
        for finding in (scan or {}).get('findings', []):
            if finding.get('category') == 'secret':
                secrets.setdefault(finding['file_path'], []).append(
                    (finding['line_start'], finding.get('line_end', finding['line_start'])))
        windows = [dict(file_path=m['file'], start_line=max(1, m['line'] - 3),
                        end_line=m['line']) for m in members]
        return dict(binding=dict(kind=kind, task_ref=source['task_ref'],
            scan_id=prepared['scan_id'], member_ids=member_ids,
            members_digest=_digest([{k: m.get(k) for k in
                ('finding_id', 'file', 'line', 'rule_id', 'runtime_priority')}
                for m in members])), source_paths=paths, member_ids=member_ids,
            required_windows=windows, secret_ranges=secrets)
    if kind != 'HOST_TASK_RISK' or not isinstance(source.get('finding_id'), str):
        raise ValueError('IMPACT_SOURCE_INVALID')
    root = task_service.root(workspace)
    record = task_service.load(root, source['task_ref'], read_only=True)
    revision = source.get('origin_review_revision')
    if revision is not None and (type(revision) is not int or revision < 1):
        raise ValueError('IMPACT_SOURCE_INVALID')
    candidates = []
    current_revision = record.get('review_revision', 1)
    snapshot = (record.get('review_plan') or {}).get('snapshot_id')
    if not snapshot and (record.get('end') or {}).get('hashes'):
        snapshot = 'impact-legacy-origin-' + _digest([record['task_ref'], current_revision,
                                                     record['end']['hashes']])
    views = [dict(revision=current_revision, review=record.get('review'),
                  evidence=record.get('evidence', {}),
                  snapshot_id=snapshot, source_hashes=(record.get('end') or {}).get('hashes', {}))]
    views.extend(record.get('review_history', []))
    for view in views:
        if revision is not None and view.get('revision') != revision:
            continue
        review = view.get('review') or {}
        if review.get('source') != 'HOST_TASK_REVIEW':
            continue
        for finding in review.get('findings', []):
            if finding.get('id') == source['finding_id']:
                candidates.append((view, finding))
    if len(candidates) != 1:
        raise ValueError('IMPACT_ORIGIN_REVISION_UNAVAILABLE')
    view, finding = candidates[0]
    if not isinstance(view.get('snapshot_id'), str):
        raise ValueError('IMPACT_ORIGIN_REVISION_UNAVAILABLE')
    locations = finding.get('evidence_locations', [])
    if not locations:
        evidence = view.get('evidence') or {}
        locations = [evidence[ref] for ref in finding.get('evidence_refs', [])
                     if ref in evidence]
    windows = []
    for location in locations:
        if location.get('location_version') != 'CURRENT_TASK_END':
            raise ValueError('IMPACT_HISTORICAL_LOCATION_NOT_CURRENT')
        if not all(k in location for k in ('path', 'start_line', 'end_line')):
            raise ValueError('IMPACT_SOURCE_UNAVAILABLE')
        windows.append(dict(file_path=location['path'], start_line=location['start_line'],
                            end_line=location['end_line']))
    if not windows:
        raise ValueError('IMPACT_SOURCE_UNAVAILABLE')
    # Current handling is independent from the immutable report. Refuse a hidden
    # source rather than turning impact preparation into a reminder restoration.
    rows, offset = [], 0
    while True:
        ledger = task_service.risk_ledger(workspace, source['task_ref'], offset=offset, limit=30)
        rows.extend(r for r in ledger.get('items', []) if r.get('finding_id') == source['finding_id'])
        if not ledger.get('has_more'):
            break
        offset += 30
        if offset > 10_000:
            raise ValueError('IMPACT_SOURCE_CAPACITY_REQUIRED')
    if len(rows) != 1:
        raise ValueError('IMPACT_SOURCE_UNAVAILABLE')
    if ((rows[0].get('feedback') or {}).get('folded') or rows[0].get('reminder_suppressed')
            or rows[0].get('status') in {'CODE_REVIEWED_RESOLVED', 'SCANNER_VERIFIED_RESOLVED'}):
        raise ValueError('IMPACT_SOURCE_NOT_ACTIVE')
    # An old offset is not a current edit locator. A changed origin must be
    # re-established through the native review workflow, never silently reused.
    from .local_evidence import WorkspaceReader
    reader = WorkspaceReader(root)
    expected = dict(view.get('source_hashes') or {})
    authorities = [*(view.get('evidence') or {}).values(),
                   *((view.get('plan') or {}).get('sources') or {}).values()]
    for authority in authorities:
        if authority.get('location_version') != 'CURRENT_TASK_END':
            continue
        name, sha = authority.get('path'), authority.get('file_sha256')
        if name and sha:
            if name in expected and expected[name] != sha:
                raise ValueError('IMPACT_ORIGIN_REVISION_UNAVAILABLE')
            expected[name] = sha
    for window in windows:
        name = window['file_path']
        if not expected.get(name) or hashlib.sha256(reader.read(name)[0]).hexdigest() != expected[name]:
            raise ValueError('IMPACT_ORIGIN_SOURCE_CHANGED')
    member_ids = [source['finding_id']]
    return dict(binding=dict(kind=kind, task_ref=source['task_ref'],
        finding_id=source['finding_id'], origin_review_revision=view['revision'],
        origin_snapshot_id=view.get('snapshot_id'), finding_digest=_digest(finding),
        member_ids=member_ids), member_ids=member_ids,
        source_paths=sorted({w['file_path'] for w in windows}), required_windows=windows)
