"""Finite task-wide delivery allowances across immutable review revisions.

This module only accounts for caller-supplied, version-bound obligations. It
does not read files, invoke scanners, certify reasoning or create evidence.
"""
from __future__ import annotations

import hashlib
import json
import math


CONTRACT = 'adaptive-review-budget-v3'
RESPONSE_BYTES = 16_000
WINDOW_LINES = 80
ACTIVITY_SECONDS = 900
BATCH_TARGET_BYTES = 128_000
HARD_CATEGORY_BYTES = dict(source=96_000_000, navigation=16_000_000, control=16_000_000)
HARD_READS = 100_000
HARD_FILES = 10_000


class AdaptiveBudgetError(ValueError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason_code = reason


def _bytes(value):
    return len(json.dumps(value, ensure_ascii=False).encode('utf-8'))


def _merge(spans):
    out = []
    for low, high in sorted(spans):
        if out and low <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], high)
        else:
            out.append([low, high])
    return out


def _uncovered(low, high, spans):
    cursor = low
    out = []
    for start, end in _merge(spans):
        if end < cursor or start > high:
            continue
        if cursor < start:
            out.append([cursor, min(high, start-1)])
        cursor = max(cursor, end+1)
        if cursor > high:
            break
    if cursor <= high:
        out.append([cursor, high])
    return out


def _range_estimate(record, window, low, high):
    snapshot = record['end' if window['location_version'] == 'CURRENT_TASK_END' else 'baseline']
    lines = snapshot.get('texts', {}).get(window['path'])
    count = high-low+1
    if lines is not None and high <= len(lines):
        # Count the readable source representation, not compressed bytes or
        # whole unrelated files. No source body is retained in the ledger.
        size = sum(_bytes(f'{index}: {lines[index-1]}')+2 for index in range(low, high+1))
    else:
        # Missing source is not empty or proof. This conservative allocation
        # keeps an unknown body bounded until a real read resolves its length.
        size = count * 3_200
    frames = max(math.ceil(count/WINDOW_LINES), math.ceil(size/12_000), 1)
    return size, frames, count


def _proposed(ledger, record, windows):
    # Each touched source gets a newly merged span list. Unchanged sources can
    # share immutable lists in a proposal; do not clone the whole task plan.
    allocations = dict(ledger.get('allocations', {}))
    basis = dict(ledger.get('basis', dict(source_bytes=0, source_lines=0,
                                        source_frames=0, source_ranges=0)))
    grouped = {}
    for window in windows:
        if window['end_line'] is None:
            # This is an honest unknown range, never a fabricated full range.
            continue
        low, high = window['start_line'], window['end_line']
        if type(low) is not int or type(high) is not int or not 1 <= low <= high <= 2_147_483_647:
            raise ValueError('Invalid adaptive source obligation')
        identity = [window[k] for k in ('path', 'file_sha256', 'location_version')]
        # A real new revision creates fresh review obligations, not a fresh
        # spending ledger. Pagination or retry within a revision remains free
        # of additional allowances; all revisions share the same hard ceiling.
        if record.get('review_revision', 1) > 1:
            identity.append(record['review_revision'])
        key = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
        entry = grouped.setdefault(key, dict(window=window, spans=[]))
        entry['spans'].append([low, high])
    for key, entry in grouped.items():
        spans = _merge(allocations.get(key, []))
        incoming = _merge(entry['spans'])
        covered_index = 0
        new_ranges = []
        for low, high in incoming:
            cursor = low
            while covered_index < len(spans) and spans[covered_index][1] < low:
                covered_index += 1
            index = covered_index
            while index < len(spans) and spans[index][0] <= high:
                start, end = spans[index]
                if cursor < start:
                    new_ranges.append([cursor, min(high, start-1)])
                cursor = max(cursor, end+1)
                if cursor > high:
                    break
                index += 1
            if cursor <= high:
                new_ranges.append([cursor, high])
        for start, end in new_ranges:
            size, frames, count = _range_estimate(record, entry['window'], start, end)
            basis['source_bytes'] += size
            basis['source_lines'] += count
            basis['source_frames'] += frames
            basis['source_ranges'] += 1
        allocations[key] = _merge([*spans, *incoming])
    return allocations, basis


def _policy(ledger, record, basis, unit_count, metadata_bytes):
    # Re-reading and frame overhead have explicit finite headroom. Navigation
    # and control do not consume the source allowance.
    required = dict(source=max(64_000, basis['source_bytes']*2 + 32_000),
        navigation=max(64_000, metadata_bytes*4 + unit_count*512 + 32_000),
        control=max(64_000, basis['source_frames']*4_000 + unit_count*2_000 + 32_000))
    old_categories = ledger.get('category_limits', {})
    required = {key: max(value, old_categories.get(key, 0)) for key, value in required.items()}
    reads = max(160, basis['source_frames']*2 + basis['source_ranges']*2)
    reads = max(reads, ledger.get('limits', {}).get('reads', 0))
    reasons = [dict(category=key, required_bytes=value, maximum_bytes=HARD_CATEGORY_BYTES[key])
               for key, value in required.items() if value > HARD_CATEGORY_BYTES[key]]
    if reads > HARD_READS:
        reasons.append(dict(category='reads', required=reads, maximum=HARD_READS))
    if unit_count > HARD_FILES:
        reasons.append(dict(category='units', required=unit_count, maximum=HARD_FILES))
    granted = {key: min(value, HARD_CATEGORY_BYTES[key]) for key, value in required.items()}
    inventory_count = len(set(record['baseline']['hashes']) | set(record['end']['hashes']))
    limits = dict(total_bytes=sum(granted.values()), response_bytes=RESPONSE_BYTES,
                  batch_bytes=BATCH_TARGET_BYTES, reads=min(reads, HARD_READS),
                  changed_files=max(1, len(record['changes'])),
                  related_files=max(1, min(HARD_FILES, inventory_count)))
    capacity = dict(status='CAPACITY_REQUIRED' if reasons else 'READY',
        required_category_bytes=required, hard_category_bytes=dict(HARD_CATEGORY_BYTES),
        maximum_total_bytes=sum(HARD_CATEGORY_BYTES.values()), reasons=reasons,
        required_source_lines=basis['source_lines'], expected_source_frames=basis['source_frames'],
        allocation='ALL_REQUIRED_RANGES_WITH_FINITE_REDELIVERY_AND_FRAME_HEADROOM')
    return granted, limits, capacity


def create_ledger(record, units, *, now):
    if record.get('review_ledger') is not None:
        raise AdaptiveBudgetError('REVIEW_PLAN_PROTOCOL_FIXED', 'An existing ledger cannot be replaced by adaptive allowances')
    if record.get('context_bytes', 0) or record.get('lifetime_context_bytes', 0) or record.get('evidence'):
        raise AdaptiveBudgetError('REVIEW_PLAN_PROTOCOL_FIXED', 'Existing delivered context keeps its original protocol and allowance')
    if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
        raise ValueError('Invalid adaptive activity clock')
    ledger = dict(contract=CONTRACT, protocol_version=3, created_at=now, deadline=now+ACTIVITY_SECONDS,
        control_bytes=0, navigation_bytes=0, source_bytes=0, total_bytes=0,
        reads=0, evidence_ids=[], evidence_bindings={}, batches={}, related_files=[],
        activity_lease=dict(seconds=ACTIVITY_SECONDS, expires_at=now+ACTIVITY_SECONDS,
                            last_progress_at=now, resumes=0),
        allocations={}, basis=dict(source_bytes=0, source_lines=0, source_frames=0, source_ranges=0),
        unit_count=len(units), metadata_bytes=sum(_bytes(unit) for unit in units))
    windows = [window for unit in units for window in unit['required_windows']]
    allocations, basis = _proposed(ledger, record, windows)
    categories, limits, capacity = _policy(ledger, record, basis, len(units), ledger['metadata_bytes'])
    ledger.update(allocations=allocations, basis=basis, category_limits=categories,
                  limits=limits, capacity=capacity)
    return ledger


def propose_windows(ledger, record, windows, *, new_units=0, metadata_bytes=0):
    """Stage new grants without changing consumption, lease or any old span."""
    allocations, basis = _proposed(ledger, record, windows)
    units = ledger['unit_count'] + new_units
    metadata = ledger['metadata_bytes'] + metadata_bytes
    categories, limits, capacity = _policy(ledger, record, basis, units, metadata)
    if capacity['status'] != 'READY':
        raise AdaptiveBudgetError('TASK_REVIEW_CAPACITY_REQUIRED',
            'New source obligations exceed the adaptive resource ceiling; keep existing evidence and report the named range')
    return dict(ledger, allocations=allocations, basis=basis, category_limits=categories,
                limits=limits, capacity=capacity, unit_count=units, metadata_bytes=metadata)


def allocate_windows(ledger, record, windows, *, new_units=0, metadata_bytes=0):
    """Allocate only previously unbound real ranges; never reset consumption."""
    ledger.update(propose_windows(ledger, record, windows,
                  new_units=new_units, metadata_bytes=metadata_bytes))


def charge(ledger, cost, category, source_bytes, batch_id):
    if cost > ledger['limits']['response_bytes']:
        raise AdaptiveBudgetError('TASK_CONTEXT_RESPONSE_BUDGET', 'Task response byte budget exceeded; request a smaller page')
    source = cost if category == 'source' and not source_bytes else source_bytes
    other = cost-source
    additions = dict(source=source, navigation=other if category == 'navigation' else 0,
                     control=other if category != 'navigation' else 0)
    if category == 'source' and ledger['capacity']['status'] != 'READY':
        raise AdaptiveBudgetError('TASK_REVIEW_CAPACITY_REQUIRED', 'The complete review exceeds the declared resource ceiling')
    for key, amount in additions.items():
        if ledger[key+'_bytes']+amount > ledger['category_limits'][key]:
            raise AdaptiveBudgetError('TASK_CONTEXT_'+key.upper()+'_BUDGET',
                                      f'Task {key} delivery allowance exhausted; existing evidence is retained')
    if ledger['total_bytes']+cost > ledger['limits']['total_bytes']:
        raise AdaptiveBudgetError('TASK_CONTEXT_BYTE_BUDGET', 'Task delivery byte budget exceeded')
    for key, amount in additions.items():
        ledger[key+'_bytes'] += amount
    ledger['total_bytes'] += cost
    ledger['batches'][batch_id] = ledger['batches'].get(batch_id, 0)+cost
    return cost


def renew(ledger, *, now, resume=False):
    """Caller has checked snapshot and owner. Active resume is idempotent."""
    if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
        raise ValueError('Invalid adaptive activity clock')
    lease = ledger['activity_lease']
    if now < lease['last_progress_at']:
        raise ValueError('Adaptive activity clock cannot go backwards')
    if resume:
        if now <= lease['expires_at']:
            return dict(lease)
        lease['resumes'] += 1
    elif now > lease['expires_at']:
        raise AdaptiveBudgetError('REVIEW_PLAN_IDLE', 'Review activity lease is idle; resume the same snapshot and ledger')
    lease.update(last_progress_at=now, expires_at=now+lease['seconds'])
    ledger['deadline'] = lease['expires_at']
    return dict(lease)


def record_capacity(record):
    """Preflight signed metadata plus finite evidence growth, never source."""
    from .closeout_state import encode
    from .task_security_state import MAX_RECORD_BYTES, persistent_record
    value = dict(record)
    for name in ('baseline', 'end'):
        if isinstance(record.get(name), dict):
            value[name] = dict(record[name], texts={})
            value[name].pop('semantic_proofs', None)
    current = len(encode(persistent_record(value)))+512
    ledger = record.get('review_ledger', {})
    frames = min(ledger.get('limits', {}).get('reads', 0),
                 ledger.get('basis', {}).get('source_frames', 0)*2)
    # Historical deliveries are already represented in signed revision history.
    # Reserve only genuinely outstanding lifetime frames, not those archived
    # when a new revision starts with an empty current evidence collection.
    delivered = ledger.get('reads', len(record.get('evidence', {})))
    outstanding = max(0, frames-delivered)
    # Evidence is repeated in the task, plan and lifetime binding ledger.
    # Per-frame headroom covers refs/ranges, not newly returned source bodies.
    projected = current+outstanding*1_000+100_000
    return dict(status='CAPACITY_REQUIRED' if projected > MAX_RECORD_BYTES else 'READY',
        record_bytes=current, projected_record_bytes=projected,
        maximum_record_bytes=MAX_RECORD_BYTES, expected_evidence_frames=frames,
        estimate='SIGNED_METADATA_PLUS_VERSIONED_EVIDENCE_REFERENCE_HEADROOM')
