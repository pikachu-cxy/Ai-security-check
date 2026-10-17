"""Pure revision transitions; source capture, locking and persistence stay outside.

One task retains its original baseline and cumulative delivery ledger. A changed
snapshot gets a new pending review, while old decisions and evidence stay history.
"""
from __future__ import annotations

import copy
import hashlib
import json


CONTRACT = 'task-review-revision-v1'
_PLAN_FIELDS = frozenset({'contract', 'protocol_version', 'semantic_coverage_version',
    'snapshot_id', 'plan_id', 'review_revision', 'created_at', 'deadline', 'units',
    'sources', 'related_files', 'unverified_paths', 'static_attempts_at_plan',
    'capacity', 'batching', 'metadata_capacity'})


class ReviewRevisionError(ValueError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason_code = reason


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def _pending(record):
    pending = record.get('pending_review_revision')
    history = record.get('review_history', [])
    if (not isinstance(pending, dict) or pending.get('contract') != CONTRACT
            or not isinstance(history, list) or not history or not isinstance(history[-1], dict)
            or type(record.get('review_revision')) is not int
            or type(history[-1].get('revision')) is not int
            or record['review_revision'] != history[-1]['revision'] + 1
            or pending.get('archive_digest') != _digest(history[-1])
            or pending.get('ledger_digest') != _digest(record.get('review_ledger'))
            or pending.get('revision') != record.get('review_revision')
            or pending.get('previous_revision') != history[-1].get('revision')
            or pending.get('previous_snapshot') != history[-1].get('snapshot_id')):
        raise ReviewRevisionError('REVIEW_PLAN_REVISION_INVALID',
            'A pending revision must retain its original signed history and cumulative ledger')
    return pending


def advance_revision(record):
    """Stage a refinish atomically; the caller must first establish a real change.

    No source bodies, baseline copies, sessions or authority are archived. An
    existing pending revision can move to the latest end snapshot before review
    starts, without making extra history entries or resetting any consumption.
    """
    candidate = copy.deepcopy(record)
    plan, ledger = candidate.get('review_plan'), candidate.get('review_ledger')
    if not plan:
        if ledger and ledger.get('protocol_version') == 3:
            _pending(candidate)
        return candidate
    if plan.get('contract') != 'task-review-plan-v3':
        return candidate  # Legacy protocols retain their existing fixed limits.
    if not isinstance(ledger, dict) or ledger.get('protocol_version') != 3:
        raise ReviewRevisionError('REVIEW_PLAN_REVISION_INVALID',
            'An adaptive revision requires its original cumulative ledger')
    from .task_review_plan import _snapshot
    if plan.get('snapshot_id') != _snapshot(record):
        raise ReviewRevisionError('REVIEW_PLAN_REVISION_INVALID',
            'Archive the original snapshot before replacing its source identity')
    revision = candidate.get('review_revision', 1)
    archived_plan = {key: value for key, value in plan.items() if key in _PLAN_FIELDS}
    evidence = dict(plan.get('evidence', {}))
    for identifier, item in candidate.get('evidence', {}).items():
        if identifier in evidence and evidence[identifier] != item:
            raise ReviewRevisionError('REVIEW_PLAN_REVISION_INVALID',
                'Historical evidence cannot change its source binding')
        evidence[identifier] = item
    archive = dict(revision=revision, snapshot_id=plan['snapshot_id'],
        plan=archived_plan, evidence=evidence,
        review=candidate.get('review'), completion=candidate.get('review_completion'),
        check={key: (candidate.get('static') or {}).get(key)
               for key in ('scan_id', 'status', 'coverage')},
        consumption={key: ledger[key] for key in
                     ('source_bytes', 'navigation_bytes', 'control_bytes', 'total_bytes', 'reads')})
    candidate.setdefault('review_history', []).append(archive)
    candidate['review_revision'] = revision + 1
    candidate['pending_review_revision'] = dict(contract=CONTRACT,
        revision=revision+1, previous_revision=revision,
        previous_snapshot=plan['snapshot_id'], archive_digest=_digest(archive),
        ledger_digest=_digest(ledger))
    for key in ('packet', 'review_plan', 'review_session', 'review_completion',
                'completion_delivery', 'review_capacity', 'review_transport', 'review_started_at'):
        candidate.pop(key, None)
    candidate.update(review=None, evidence={}, related_files=[],
                     context_requests={}, context_gaps=[])
    # Charges remain task-wide even when the current revision has no evidence.
    candidate['context_bytes'] = ledger['total_bytes']
    from .task_review_transport import record_capacity
    if not record_capacity(candidate)['fits']:
        raise ReviewRevisionError('TASK_REVIEW_REVISION_CAPACITY',
            'Revision history exceeds signed storage capacity; the previous record is retained')
    return candidate


def revision_ledger(record, units, *, now):
    """Allocate real new obligations without clearing any historical spending."""
    _pending(record)
    from . import task_review_budget as adaptive
    ledger = copy.deepcopy(record['review_ledger'])
    windows = [window for unit in units for window in unit['required_windows']]
    proposal = adaptive.propose_windows(ledger, record, windows,
        new_units=len(units), metadata_bytes=sum(len(json.dumps(unit,
            ensure_ascii=False).encode()) for unit in units))
    # The task owner and source revision were checked by the coordinator. Resume
    # only renews an idle activity lease; it never refreshes cumulative budgets.
    adaptive.renew(proposal, now=now, resume=True)
    return proposal
