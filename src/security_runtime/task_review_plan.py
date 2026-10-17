"""Task-wide, version-bound review units and cumulative delivery budgets.

This module neither reads source nor runs scanners. Its caller owns the signed
task record, source guards and transaction. A batch is a view of one fixed plan;
it never creates another snapshot, static attempt or budget.
"""
from __future__ import annotations

import difflib
import copy
import hashlib
import json
import math
import time


CONTRACT = 'task-review-plan-v2'
ADAPTIVE_CONTRACT = 'task-review-plan-v3'
DEFAULT_LIMITS = dict(total_bytes=256_000, response_bytes=16_000,
                      batch_bytes=64_000, reads=160, changed_files=100,
                      related_files=20)
BATCH_UNITS = 10
MAX_DIFF_INPUT_LINES = 10_000
_VERSIONS = {'CURRENT_TASK_END': 'end', 'BEFORE_TASK': 'baseline',
             'BEFORE_DELETION': 'baseline'}


class ReviewPlanError(ValueError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason_code = reason


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def _now(value):
    return time.time() if value is None else value


def _snapshot(record):
    return _digest(dict(task_ref=record['task_ref'],
                        before=record['baseline']['hashes'],
                        after=record['end']['hashes'], changes=record['changes'],
                        hook_revision=record.get('finished_hook_revision'),
                        unverified_paths=record.get('unverified_paths', [])))


def _plan(record):
    plan = record.get('review_plan')
    if not plan or plan.get('contract') not in {CONTRACT, ADAPTIVE_CONTRACT}:
        raise ReviewPlanError('REVIEW_PLAN_UNAVAILABLE', 'Prepare a review plan first')
    if plan['snapshot_id'] != _snapshot(record):
        raise ReviewPlanError('REVIEW_PLAN_STALE', 'Task snapshot changed; old evidence is historical')
    # JSON persistence does not retain Python object aliases. The independent
    # lifetime ledger remains authoritative after every signed-record reload.
    if record.get('review_ledger'):
        plan['budget'] = record['review_ledger']
        plan['related_files'] = record['review_ledger']['related_files']
        if (plan['contract'] == ADAPTIVE_CONTRACT) != (plan['budget'].get('protocol_version') == 3):
            raise ReviewPlanError('REVIEW_PLAN_PROTOCOL_FIXED', 'Plan and lifetime ledger protocols must agree')
    return plan


def _live(plan, now):
    if _now(now) > plan['deadline']:
        if plan['contract'] == ADAPTIVE_CONTRACT:
            raise ReviewPlanError('REVIEW_PLAN_IDLE', 'Review activity lease is idle; resume the same snapshot and ledger')
        raise ReviewPlanError('REVIEW_PLAN_EXPIRED', 'Task review deadline exceeded; budgets are retained')


def _budget_view(ledger, batch_id=None):
    """Delivery metadata must not repeat the entire private accounting ledger."""
    view = {key: ledger[key] for key in ('control_bytes', 'navigation_bytes',
                                        'source_bytes', 'total_bytes', 'reads')}
    view.update(limits=dict(ledger['limits']), deadline=ledger['deadline'],
                remaining_bytes=max(0, ledger['limits']['total_bytes'] - ledger['total_bytes']),
                remaining_reads=max(0, ledger['limits']['reads'] - ledger['reads']))
    if ledger.get('protocol_version') == 3:
        view.update(category_limits=dict(ledger['category_limits']),
            category_remaining={key: max(0, maximum-ledger[key+'_bytes'])
                                for key, maximum in ledger['category_limits'].items()},
            activity_lease=dict(ledger['activity_lease']), capacity=copy.deepcopy(ledger['capacity']))
        if batch_id is not None:
            view.update(batch_id=batch_id, batch_bytes=ledger['batches'].get(batch_id, 0),
                        target_batch_bytes=ledger['limits']['batch_bytes'], batch_is_scheduling_only=True)
        return view
    if batch_id is not None:
        view.update(batch_id=batch_id, batch_bytes=ledger['batches'].get(batch_id, 0),
                    remaining_batch_bytes=max(0, ledger['limits']['batch_bytes']
                                              - ledger['batches'].get(batch_id, 0)))
    return view


def _merge(spans):
    merged = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(high, merged[-1][1])
        else:
            merged.append([low, high])
    return merged


def _line_count(snapshot, path):
    if path in snapshot.get('texts', {}):
        return len(snapshot['texts'][path])
    count = snapshot.get('line_counts', {}).get(path)
    return count if type(count) is int and count >= 0 else None


def _requirement(path, file_hash, version, low=1, high=None):
    return dict(path=path, file_sha256=file_hash, location_version=version,
                start_line=low, end_line=high)


def _windows(record, change):
    path, kind = change['path'], change['change']
    before, after = record['baseline'], record['end']
    old, new = before.get('texts', {}).get(path), after.get('texts', {}).get(path)
    versions = ([('BEFORE_DELETION', before)] if kind == 'DELETED' else
                [('CURRENT_TASK_END', after)] if kind == 'ADDED' else
                [('BEFORE_TASK', before), ('CURRENT_TASK_END', after)])
    spans = {}
    if (kind == 'MODIFIED' and old is not None and new is not None
            and len(old) + len(new) <= MAX_DIFF_INPUT_LINES):
        changed = [op for op in difflib.SequenceMatcher(None, old, new,
                                                       autojunk=True).get_opcodes()
                   if op[0] != 'equal']
        for version, lines, first, last in [('BEFORE_TASK', old, 1, 2),
                                             ('CURRENT_TASK_END', new, 3, 4)]:
            if changed and lines:
                spans[version] = _merge([[max(1, op[first] - 2),
                                          min(len(lines), max(op[first] + 1, op[last]) + 3)]
                                         for op in changed])
    windows, gaps = [], []
    for version, snapshot in versions:
        file_hash = snapshot['hashes'].get(path)
        if not file_hash:
            gaps.append(dict(reason='SOURCE_VERSION_UNAVAILABLE', path=path,
                             location_version=version))
            continue
        count = _line_count(snapshot, path)
        # An empty, hashed file requires no source lines. Literal-only edits
        # whose sanitized diff is empty still require both real versions.
        if count == 0:
            continue
        selected = spans.get(version, [[1, count]])
        # Keep disjoint hunks disjoint. An enclosing range turns scattered
        # one-line edits into hundreds of unrelated required lines and can
        # exhaust a fixed batch before the actual changes are reviewed.
        # Metadata and source deliveries still share the original hard limits;
        # a genuinely oversized plan remains an explicit budget limitation.
        for low, high in selected:
            windows.append(_requirement(path, file_hash, version, low, high))
    return windows, gaps


def build_plan(record, *, now=None, deadline=None, limits=None, protocol_version=None):
    """Create once, from all changes; repeated preparation never resets state."""
    if record.get('review_plan'):
        plan = _plan(record)
        version = 3 if plan['contract'] == ADAPTIVE_CONTRACT else 2
        if protocol_version is not None and (type(protocol_version) is not int or protocol_version != version):
            raise ReviewPlanError('REVIEW_PLAN_PROTOCOL_FIXED', 'An existing task keeps its original review protocol and ledger')
        if limits is not None and dict(DEFAULT_LIMITS, **limits) != plan['budget']['limits']:
            raise ReviewPlanError('REVIEW_PLAN_LIMITS_FIXED', 'A prepared task keeps its original limits')
        if deadline is not None and deadline != plan['deadline']:
            raise ReviewPlanError('REVIEW_PLAN_DEADLINE_FIXED', 'A prepared task keeps its original deadline')
        return plan
    if protocol_version is not None and (type(protocol_version) is not int or protocol_version not in {2, 3}):
        raise ValueError('Invalid task review protocol')
    ledger_version = (record.get('review_ledger') or {}).get('protocol_version', 2)
    if record.get('review_ledger') and protocol_version is not None and protocol_version != ledger_version:
        raise ReviewPlanError('REVIEW_PLAN_PROTOCOL_FIXED', 'An existing task keeps its original review protocol and ledger')
    version = protocol_version if protocol_version is not None else ledger_version
    if version == 3:
        return _build_adaptive(record, now=_now(now), deadline=deadline, limits=limits)
    selected = dict(DEFAULT_LIMITS, **(limits or {}))
    if set(selected) != set(DEFAULT_LIMITS) or any(type(v) is not int or v < 1 for v in selected.values()):
        raise ValueError('Invalid task review limits')
    created = _now(now)
    deadline = created + 900 if deadline is None else deadline
    if (not isinstance(deadline, (int, float)) or isinstance(deadline, bool)
            or not math.isfinite(deadline) or deadline < created):
        raise ValueError('Invalid task review deadline')
    ledger = record.get('review_ledger')
    if ledger is not None:
        if limits is not None and selected != ledger['limits']:
            raise ReviewPlanError('REVIEW_PLAN_LIMITS_FIXED', 'A prepared task keeps its original limits')
        selected, deadline = ledger['limits'], ledger['deadline']
    else:
        previous_bytes = max(0, record.get('context_bytes', 0), record.get('lifetime_context_bytes', 0))
        previous_reads = len(record.get('evidence', {})) + record.get('lifetime_context_reads', 0)
        old_deadline = record.get('review_deadline')
        if isinstance(old_deadline, (int, float)) and not isinstance(old_deadline, bool) and math.isfinite(old_deadline):
            deadline = min(deadline, old_deadline)
        ledger = dict(limits=selected, deadline=deadline, created_at=created,
                      control_bytes=previous_bytes, navigation_bytes=0,
                      source_bytes=0, total_bytes=previous_bytes,
                      reads=previous_reads, evidence_ids=list(record.get('evidence', {})),
                      evidence_bindings={},
                      batches={}, related_files=[], migrated_legacy_bytes=previous_bytes,
                      migrated_legacy_reads=previous_reads)
        record['review_ledger'] = ledger
    snapshot = _snapshot(record)
    units = []
    seen = set()
    for index, change in enumerate(record['changes']):
        if change.get('change') not in {'ADDED', 'MODIFIED', 'DELETED'} or not isinstance(change.get('path'), str):
            raise ValueError('Invalid task change')
        if change['path'] in seen:
            raise ValueError('Duplicate task change path')
        seen.add(change['path'])
        windows, gaps = _windows(record, change)
        if index >= selected['changed_files']:
            gaps.append(dict(reason='TASK_CONTEXT_UNIT_BUDGET', path=change['path']))
        batch_id = 'tb1-' + _digest([record['task_ref'], index // BATCH_UNITS])[:24]
        ledger['batches'].setdefault(batch_id, 0)
        units.append(dict(unit_id='tu1-' + _digest([snapshot, change])[:32],
                          path=change['path'], change=change['change'],
                          batch_id=batch_id, status='PENDING', required_windows=windows,
                          evidence_gaps=gaps, limitations=[], submitted_at=None))
    plan = dict(contract=CONTRACT, snapshot_id=snapshot,
                plan_id='tp1-' + _digest([record['task_ref'], snapshot])[:32],
                created_at=created, deadline=deadline, units=units, evidence={},
                related_files=ledger['related_files'], unverified_paths=list(record.get('unverified_paths', [])),
                static_attempts_at_plan=record.get('static_attempts', 0),
                budget=ledger)
    record['review_plan'] = plan
    return plan


def _build_adaptive(record, *, now, deadline, limits):
    from . import task_review_budget as adaptive
    from .task_review_windows import adaptive_windows
    if limits is not None:
        raise ReviewPlanError('REVIEW_PLAN_LIMITS_FIXED', 'Adaptive allowances derive from actual obligations, not legacy overrides')
    if record.get('review_session') and record.get('review_protocol', 2) != 3:
        raise ReviewPlanError('REVIEW_PLAN_PROTOCOL_FIXED', 'A prepared legacy task cannot switch protocols')
    if record.get('review_ledger'):
        raise ReviewPlanError('REVIEW_PLAN_SNAPSHOT_FIXED', 'An adaptive ledger retains its original plan; do not rebuild a snapshot')
    if deadline is not None and deadline != now+adaptive.ACTIVITY_SECONDS:
        raise ReviewPlanError('REVIEW_PLAN_DEADLINE_FIXED', 'Adaptive review starts with its fixed activity lease')
    snapshot = _snapshot(record)
    units, seen = [], set()
    for change in record['changes']:
        if change.get('change') not in {'ADDED', 'MODIFIED', 'DELETED'} or not isinstance(change.get('path'), str):
            raise ValueError('Invalid task change')
        if change['path'] in seen:
            raise ValueError('Duplicate task change path')
        seen.add(change['path'])
        windows, gaps = adaptive_windows(record, change)
        units.append(dict(unit_id='tu1-'+_digest([snapshot, change])[:32], path=change['path'],
            change=change['change'], batch_id='', status='PENDING', required_windows=windows,
            evidence_gaps=gaps, limitations=[], submitted_at=None))
    try:
        ledger = adaptive.create_ledger(record, units, now=now)
    except adaptive.AdaptiveBudgetError as exc:
        raise ReviewPlanError(exc.reason_code, str(exc)) from None
    batch_index, batch_cost = 0, 0
    for unit in units:
        cost = 0
        for window in unit['required_windows']:
            if window['end_line'] is not None:
                size, frames, _ = adaptive._range_estimate(record, window, window['start_line'], window['end_line'])
                cost += size+frames*2_000
        cost += len(json.dumps(unit, ensure_ascii=False).encode())
        if batch_cost and batch_cost+cost > adaptive.BATCH_TARGET_BYTES:
            batch_index += 1
            batch_cost = 0
        unit['batch_id'] = 'tb3-'+_digest([record['task_ref'], snapshot, batch_index])[:24]
        ledger['batches'].setdefault(unit['batch_id'], 0)
        batch_cost += cost
    plan = dict(contract=ADAPTIVE_CONTRACT, protocol_version=3, semantic_coverage_version=1, snapshot_id=snapshot,
        plan_id='tp3-'+_digest([record['task_ref'], snapshot])[:32], created_at=now,
        deadline=ledger['deadline'], units=units, evidence={}, sources={},
        related_files=ledger['related_files'], unverified_paths=list(record.get('unverified_paths', [])),
        static_attempts_at_plan=record.get('static_attempts', 0), budget=ledger,
        capacity=ledger['capacity'], batching='ESTIMATED_CAPACITY_SCHEDULING_ONLY')
    record['review_plan'], record['review_ledger'] = plan, ledger
    record['review_protocol'] = 3
    record['review_deadline'] = ledger['deadline']
    seen_sources = set()
    for unit in units:
        for window in unit['required_windows']:
            key = tuple(window[name] for name in ('path', 'file_sha256', 'location_version'))
            if key in seen_sources:
                continue
            seen_sources.add(key)
            source = record[_VERSIONS[window['location_version']]]
            _source_binding(record, plan, window['path'], window['file_sha256'],
                            window['location_version'], _line_count(source, window['path']))
    metadata_capacity = record_capacity(record)
    plan['metadata_capacity'] = metadata_capacity
    if metadata_capacity['status'] != 'READY':
        ledger['capacity']['status'] = 'CAPACITY_REQUIRED'
        ledger['capacity']['reasons'].append(dict(category='signed_record', **metadata_capacity))
    return plan


def record_capacity(record):
    from .task_review_budget import record_capacity as capacity
    return capacity(record)


def source_binding(record, path, file_sha256, location_version, total_lines=None):
    """Register immutable source identity, without delivery or coverage credit."""
    plan = _plan(record)
    return _source_binding(record, plan, path, file_sha256, location_version, total_lines)


def _source_binding(record, plan, path, file_sha256, location_version, total_lines=None):
    if plan['contract'] != ADAPTIVE_CONTRACT:
        raise ValueError('Compact source bindings require protocol three')
    if (not isinstance(path, str) or not path or location_version not in _VERSIONS or
            record[_VERSIONS[location_version]]['hashes'].get(path) != file_sha256):
        raise ValueError('Source binding must match the immutable task snapshot')
    if total_lines is not None and (type(total_lines) is not int or not 0 <= total_lines <= 2_147_483_647):
        raise ValueError('Invalid source binding line count')
    ref = 'sr1-'+_digest([plan['snapshot_id'], path, file_sha256, location_version])[:32]
    sources = plan.setdefault('sources', {})
    binding = sources.setdefault(ref, dict(source_ref=ref, path=path,
        file_sha256=file_sha256, location_version=location_version))
    if total_lines is not None:
        if 'total_lines' in binding and binding['total_lines'] != total_lines:
            raise ValueError('Source binding line count cannot change')
        binding['total_lines'] = total_lines
    return dict(binding)


def renew_activity(record, *, now=None, resume=False):
    """Only after caller checks owner and source freshness; never resets budget."""
    from . import task_review_budget as adaptive
    plan = _plan(record)
    if plan['contract'] != ADAPTIVE_CONTRACT:
        return dict(protocol_version=2, deadline=plan['deadline'], renewable=False)
    if type(resume) is not bool:
        raise ValueError('Invalid review resume mode')
    try:
        lease = adaptive.renew(plan['budget'], now=_now(now), resume=resume)
    except adaptive.AdaptiveBudgetError as exc:
        raise ReviewPlanError(exc.reason_code, str(exc)) from None
    plan['deadline'] = record['review_deadline'] = plan['budget']['deadline']
    return dict(protocol_version=3, **lease)


def _adaptive_page(record, plan, cursor, limit):
    # One source file can contain thousands of disjoint hunks. A navigation
    # cursor addresses bounded fragments, never drops windows or changes the
    # underlying unit obligations used for completion.
    navigation = plan.get('navigation')
    if navigation is None:
        navigation = []
        for index, unit in enumerate(plan['units']):
            count = max(1, math.ceil(len(unit['required_windows'])/32))
            for fragment in range(count):
                navigation.append(dict(unit_index=index, fragment=fragment, fragments=count,
                                       start=fragment*32, end=(fragment+1)*32))
        plan['navigation'] = navigation
    high = min(cursor+limit, len(navigation))
    if cursor < len(navigation):
        batch = plan['units'][navigation[cursor]['unit_index']]['batch_id']
        high = next((index for index in range(cursor+1, high)
                     if plan['units'][navigation[index]['unit_index']]['batch_id'] != batch), high)
    units, sources = [], {}
    for item in navigation[cursor:high]:
        unit = plan['units'][item['unit_index']]
        public = {key: copy.deepcopy(unit[key]) for key in
                  ('unit_id', 'path', 'change', 'batch_id', 'status', 'submitted_at')}
        public.update(required_windows=[], required_window_count=len(unit['required_windows']),
            window_fragment=dict(index=item['fragment'], count=item['fragments']),
            evidence_gaps=copy.deepcopy(unit['evidence_gaps'][:3]),
            evidence_gap_count=len(unit['evidence_gaps']), limitations=unit['limitations'][:3],
            limitation_count=len(unit['limitations']))
        for window in unit['required_windows'][item['start']:item['end']]:
            binding = _source_binding(record, plan, window['path'], window['file_sha256'], window['location_version'])
            sources[binding['source_ref']] = binding
            public['required_windows'].append(dict(source_ref=binding['source_ref'],
                start_line=window['start_line'], end_line=window['end_line']))
        units.append(public)
    return dict(protocol_version=3, plan_id=plan['plan_id'], snapshot_id=plan['snapshot_id'],
        unit_count=len(plan['units']), navigation_count=len(navigation), cursor=cursor,
        units=units, next_cursor=high if high < len(navigation) else None,
        batch_id=units[0]['batch_id'] if units else None, sources=list(sources.values()),
        deadline=plan['deadline'], budget=_budget_view(plan['budget'], units[0]['batch_id'] if units else None),
        capacity=copy.deepcopy(plan['budget']['capacity']), batching='ESTIMATED_CAPACITY_SCHEDULING_ONLY',
        trust='NAVIGATION_ONLY_NOT_REVIEW_PROOF')


def plan_page(record, cursor=0, limit=10):
    """Navigation only; a page or an unrequested unit is never review proof."""
    plan = _plan(record)
    if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 30:
        raise ValueError('Invalid review plan page')
    if plan['contract'] == ADAPTIVE_CONTRACT:
        return _adaptive_page(record, plan, cursor, limit)
    # Batches are immutable scheduling views, never a new task allowance.
    high = min(cursor+limit, len(plan['units']))
    if plan['contract'] == CONTRACT:
        high = min(high, (cursor // BATCH_UNITS + 1)*BATCH_UNITS)
    elif cursor < len(plan['units']):
        first_batch = plan['units'][cursor]['batch_id']
        high = next((index for index in range(cursor+1, high)
                     if plan['units'][index]['batch_id'] != first_batch), high)
    units = plan['units'][cursor:high]
    packet = dict(plan_id=plan['plan_id'], snapshot_id=plan['snapshot_id'],
                unit_count=len(plan['units']), cursor=cursor,
                units=units, next_cursor=cursor + len(units) if cursor + len(units) < len(plan['units']) else None,
                batch_id=units[0]['batch_id'] if units else None,
                deadline=plan['deadline'], budget=_budget_view(plan['budget'], units[0]['batch_id'] if units else None),
                trust='NAVIGATION_ONLY_NOT_REVIEW_PROOF')
    if plan['contract'] == ADAPTIVE_CONTRACT:
        compact, sources = [], {}
        for unit in units:
            public = copy.deepcopy(unit)
            public['required_windows'] = []
            for window in unit['required_windows']:
                binding = source_binding(record, window['path'], window['file_sha256'], window['location_version'])
                sources[binding['source_ref']] = binding
                public['required_windows'].append(dict(source_ref=binding['source_ref'],
                    start_line=window['start_line'], end_line=window['end_line']))
            compact.append(public)
        packet.update(protocol_version=3, units=compact, sources=list(sources.values()),
                      capacity=copy.deepcopy(plan['budget']['capacity']),
                      batching='ESTIMATED_CAPACITY_SCHEDULING_ONLY')
    return packet


def charge_packet(record, packet, category='control', source_bytes=0, *, now=None, batch_id=None):
    """Charge every actual delivery, including duplicate/control responses.

    Source bytes are a breakdown within the serialized payload, never a free
    allowance. Caller should pass the exact serialized bytes when already known.
    """
    plan = _plan(record)
    _live(plan, now)
    if category not in {'control', 'navigation', 'source'}:
        raise ValueError('Invalid context byte category')
    raw = packet if isinstance(packet, bytes) else json.dumps(packet, ensure_ascii=False).encode('utf-8')
    cost = len(raw)
    if type(source_bytes) is not int or not 0 <= source_bytes <= cost:
        raise ValueError('Invalid source byte breakdown')
    budget = plan['budget']
    if plan['contract'] == ADAPTIVE_CONTRACT:
        from . import task_review_budget as adaptive
        if batch_id is None and isinstance(packet, dict):
            binding = plan.get('sources', {}).get(packet.get('source_ref'), {})
            path = packet.get('path', binding.get('path'))
            version = packet.get('location_version', binding.get('location_version'))
            matching = next((unit for unit in plan['units'] if any(
                window['path'] == path and (version is None or window['location_version'] == version)
                for window in unit['required_windows'])), None)
            batch_id = matching['batch_id'] if matching else None
        if batch_id is not None and batch_id not in budget['batches']:
            raise ValueError('Unknown task review batch')
        try:
            return adaptive.charge(budget, cost, category, source_bytes, batch_id or 'control')
        except adaptive.AdaptiveBudgetError as exc:
            raise ReviewPlanError(exc.reason_code, str(exc)) from None
    if cost > budget['limits']['response_bytes']:
        raise ReviewPlanError('TASK_CONTEXT_RESPONSE_BUDGET', 'Task response byte budget exceeded; request a smaller page')
    if budget['total_bytes'] + cost > budget['limits']['total_bytes']:
        raise ReviewPlanError('TASK_CONTEXT_BYTE_BUDGET', 'Task delivery byte budget exceeded')
    if batch_id is None and isinstance(packet, dict) and packet.get('path'):
        version = packet.get('location_version')
        matching = next((unit for unit in plan['units']
                         if any(window['path'] == packet['path'] and
                                (version is None or window['location_version'] == version)
                                for window in unit['required_windows'])), None)
        batch_id = matching['batch_id'] if matching else None
    if batch_id is None:
        batch_id = 'control'
    elif batch_id not in budget['batches']:
        raise ValueError('Unknown task review batch')
    used = budget['batches'].get(batch_id, 0)
    if used + cost > budget['limits']['batch_bytes']:
        raise ReviewPlanError('TASK_CONTEXT_BATCH_BUDGET', 'Task batch byte budget exceeded; existing batch evidence is retained')
    source = cost if category == 'source' and not source_bytes else source_bytes
    other = cost - source
    budget['source_bytes'] += source
    budget[('control' if category == 'source' else category) + '_bytes'] += other
    budget['total_bytes'] += cost
    budget['batches'][batch_id] = used + cost
    return cost


def _unit(plan, unit_id):
    unit = next((item for item in plan['units'] if item['unit_id'] == unit_id), None)
    if unit is None:
        raise ValueError('Unknown review unit')
    return unit


def register_related(record, unit_id, path, file_sha256, start_line, end_line,
                     location_version='CURRENT_TASK_END', *, now=None, source_lines=None):
    """Attach a dependency, or create a discoverable RELATED unit with None.

    Repeated reads of the same related path extend its existing unit, rather
    than creating new completion claims or another file/batch allowance.
    """
    plan = _plan(record)
    _live(plan, now)
    if location_version not in _VERSIONS or record[_VERSIONS[location_version]]['hashes'].get(path) != file_sha256:
        raise ValueError('Related source must match the task snapshot')
    if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line:
        raise ValueError('Invalid related source range')
    adaptive_mode = plan['contract'] == ADAPTIVE_CONTRACT
    if adaptive_mode:
        return _register_related_adaptive(record, plan, unit_id, path, file_sha256,
                                          start_line, end_line, location_version, source_lines)
    if unit_id is None:
        related_id = 'tu1-' + _digest([plan['snapshot_id'], 'RELATED', path, location_version])[:32]
        unit = next((item for item in plan['units'] if item['unit_id'] == related_id), None)
    else:
        unit = _unit(plan, unit_id)
    new_related = path not in plan['related_files']
    if new_related:
        if len(plan['related_files']) >= plan['budget']['limits']['related_files']:
            raise ReviewPlanError('TASK_CONTEXT_RELATED_FILE_BUDGET', 'Task related source file budget exceeded')
    if unit is None:
        batch_id = 'tb1-' + _digest([record['task_ref'], len(plan['units']) // BATCH_UNITS])[:24]
        unit = dict(unit_id=related_id, path=path, change='RELATED',
                    status='PENDING', batch_id=batch_id, required_windows=[],
                    evidence_gaps=[], limitations=[], submitted_at=None)
    is_new_unit = unit not in plan['units']
    required = _requirement(path, file_sha256, location_version, start_line, end_line)
    matching = [window for window in unit['required_windows']
                if all(window[key] == required[key] for key in ('path', 'file_sha256', 'location_version'))]
    if not any(window['end_line'] is not None and window['start_line'] <= start_line
               and window['end_line'] >= end_line for window in matching):
        if any(window['end_line'] is None for window in matching):
            return unit  # An unresolved full-file requirement already includes it.
        spans = _merge([[window['start_line'], window['end_line']] for window in matching]
                       + [[start_line, end_line]])
        unit['required_windows'] = [window for window in unit['required_windows'] if window not in matching]
        unit['required_windows'].extend(_requirement(path, file_sha256, location_version, low, high)
                                        for low, high in spans)
        unit.update(status='PENDING', submitted_at=None, limitations=[])
    if new_related:
        plan['related_files'].append(path)
    if is_new_unit:
        plan['budget']['batches'].setdefault(unit['batch_id'], 0)
        plan['units'].append(unit)
    return unit


def _register_related_adaptive(record, plan, unit_id, path, file_hash, low, high, version, source_lines):
    from . import task_review_budget as adaptive
    # Stage only changed containers. Existing evidence, source bindings, spans,
    # consumption and activity state remain untouched if either preflight fails.
    proposed_plan = dict(plan, sources=dict(plan.get('sources', {})))
    binding = _source_binding(record, proposed_plan, path, file_hash, version)
    if binding.get('total_lines') is not None and high > binding['total_lines']:
        raise ValueError('Related obligation exceeds the verified source range')
    if source_lines is not None:
        if (not isinstance(source_lines, list) or any(not isinstance(line, str) for line in source_lines)
                or high > len(source_lines)
                or binding.get('total_lines', len(source_lines)) != len(source_lines)):
            raise ValueError('Invalid verified related source estimate')
        if 'total_lines' not in binding:
            proposed_plan['sources'][binding['source_ref']] = dict(binding, total_lines=len(source_lines))
    related_id = 'tu1-'+_digest([plan['snapshot_id'], 'RELATED', path, version])[:32]
    unit = (next((item for item in plan['units'] if item['unit_id'] == related_id), None)
            if unit_id is None else _unit(plan, unit_id))
    new_related = path not in plan['related_files']
    if new_related and len(plan['related_files']) >= plan['budget']['limits']['related_files']:
        raise ReviewPlanError('TASK_CONTEXT_RELATED_FILE_BUDGET', 'Task related source file budget exceeded')
    is_new = unit is None
    if is_new:
        unit = dict(unit_id=related_id, path=path, change='RELATED', status='PENDING',
            batch_id='tb3-'+_digest([record['task_ref'], plan['snapshot_id'], 'RELATED', related_id])[:24],
            required_windows=[], evidence_gaps=[], limitations=[], submitted_at=None)
    required = _requirement(path, file_hash, version, low, high)
    matching = [window for window in unit['required_windows']
                if all(window[key] == required[key] for key in ('path', 'file_sha256', 'location_version'))]
    if any(window['end_line'] is None or window['start_line'] <= low <= high <= window['end_line']
           for window in matching):
        return unit
    spans = _merge([[window['start_line'], window['end_line']] for window in matching]+[[low, high]])
    windows = [window for window in unit['required_windows'] if window not in matching]
    windows.extend(_requirement(path, file_hash, version, start, end) for start, end in spans)
    proposed_unit = dict(unit, required_windows=windows, status='PENDING',
                         submitted_at=None, limitations=[])
    estimate_record = record
    if source_lines is not None:
        snapshot = _VERSIONS[version]
        estimate_record = dict(record)
        estimate_record[snapshot] = dict(record[snapshot],
            texts=dict(record[snapshot].get('texts', {}), **{path: source_lines}))
    try:
        proposed_ledger = adaptive.propose_windows(plan['budget'], estimate_record, [required],
            new_units=int(is_new), metadata_bytes=len(json.dumps(required, ensure_ascii=False).encode()))
    except adaptive.AdaptiveBudgetError as exc:
        raise ReviewPlanError(exc.reason_code, str(exc)) from None
    related = [*plan['related_files'], path] if new_related else plan['related_files']
    proposed_ledger['related_files'] = related
    proposed_ledger['batches'] = dict(plan['budget']['batches'])
    proposed_ledger['batches'].setdefault(unit['batch_id'], 0)
    units = list(plan['units'])
    if is_new:
        units.append(proposed_unit)
    else:
        units[units.index(unit)] = proposed_unit
    proposed_plan.update(units=units, related_files=related, budget=proposed_ledger,
                         capacity=proposed_ledger['capacity'])
    proposed_plan.pop('navigation', None)
    proposed_record = dict(record, review_plan=proposed_plan, review_ledger=proposed_ledger)
    metadata_capacity = record_capacity(proposed_record)
    if metadata_capacity['status'] != 'READY':
        raise ReviewPlanError('TASK_REVIEW_CAPACITY_REQUIRED',
            'New related obligations exceed signed metadata capacity after future evidence growth; keep existing progress')
    proposed_plan['metadata_capacity'] = metadata_capacity
    # Commit only after source and future signed-record capacity both fit.
    ledger = plan['budget']
    ledger.update(proposed_ledger)
    if not is_new:
        unit.update(proposed_unit)
        units[units.index(proposed_unit)] = unit
    else:
        unit = proposed_unit
    proposed_plan.update(budget=ledger, units=units, related_files=ledger['related_files'])
    plan.update(proposed_plan)
    plan.pop('navigation', None)
    return unit


def record_read(record, evidence, *, now=None):
    """Record a Runtime-issued window; merely reading does not submit a unit."""
    plan = _plan(record)
    _live(plan, now)
    fields = ('path', 'file_sha256', 'location_version', 'start_line', 'end_line')
    if not isinstance(evidence, dict) or any(k not in evidence for k in ('evidence_id', *fields)):
        raise ValueError('Invalid source evidence')
    version = evidence['location_version']
    if version not in _VERSIONS or record[_VERSIONS[version]]['hashes'].get(evidence['path']) != evidence['file_sha256']:
        raise ValueError('Evidence source version does not match the task')
    low, high = evidence['start_line'], evidence['end_line']
    if type(low) is not int or type(high) is not int or not 1 <= low <= high:
        raise ValueError('Invalid evidence range')
    count = evidence.get('total_lines')
    if count is not None and (type(count) is not int or count < high):
        raise ValueError('Invalid source line count')
    identifier = evidence['evidence_id']
    if not isinstance(identifier, str) or not identifier:
        raise ValueError('Invalid evidence identifier')
    item = {key: evidence[key] for key in fields}
    binding = _digest(item)
    historical = plan['budget']['evidence_bindings'].get(identifier)
    if historical is not None and historical != binding:
        raise ValueError('An evidence identifier cannot change its source version or range')
    prior = plan['evidence'].get(identifier)
    if prior is not None and prior != item:
        raise ValueError('An evidence identifier cannot change its range')
    adaptive_mode = plan['contract'] == ADAPTIVE_CONTRACT
    adds_coverage = True
    if adaptive_mode:
        from . import task_review_budget as adaptive
        covered = _merge([[old['start_line'], old['end_line']] for old in plan['evidence'].values()
                          if all(old[key] == item[key] for key in ('path', 'file_sha256', 'location_version'))])
        adds_coverage = bool(adaptive._uncovered(low, high, covered))
        _source_binding(record, plan, item['path'], item['file_sha256'], version, count)
        unresolved = [dict(requirement, end_line=count) for unit in plan['units']
            for requirement in unit['required_windows'] if count is not None and requirement['end_line'] is None
            and all(requirement[key] == item[key] for key in ('path', 'file_sha256', 'location_version'))]
        if unresolved:
            try:
                adaptive.allocate_windows(plan['budget'], record, unresolved)
            except adaptive.AdaptiveBudgetError as exc:
                raise ReviewPlanError(exc.reason_code, str(exc)) from None
            plan['capacity'] = plan['budget']['capacity']
    if prior is None:
        known = identifier in plan['budget']['evidence_ids']
        if not known and plan['budget']['reads'] >= plan['budget']['limits']['reads']:
            raise ReviewPlanError('TASK_CONTEXT_READ_BUDGET', 'Task source read budget exceeded')
        plan['evidence'][identifier] = item
        if not known:
            plan['budget']['reads'] += 1
            plan['budget']['evidence_ids'].append(identifier)
        plan['budget']['evidence_bindings'][identifier] = binding
    if count is not None:
        for unit in plan['units']:
            for requirement in unit['required_windows']:
                if all(requirement[key] == item[key] for key in ('path', 'file_sha256', 'location_version')) and requirement['end_line'] is None:
                    requirement['end_line'] = count
    if adaptive_mode and adds_coverage:
        renew_activity(record, now=now)
    return item


def _unit_gaps(plan, unit):
    gaps = [dict(gap) for gap in unit['evidence_gaps']]
    for requirement in unit['required_windows']:
        if requirement['end_line'] is None:
            gaps.append(dict(reason='SOURCE_RANGE_UNKNOWN', **requirement))
            continue
        covered = _merge([[e['start_line'], e['end_line']] for e in plan['evidence'].values()
                          if all(e[key] == requirement[key] for key in ('path', 'file_sha256', 'location_version'))])
        cursor, high = requirement['start_line'], requirement['end_line']
        for low, end in covered:
            if end < cursor or low > high:
                continue
            if low > cursor:
                gaps.append(dict(requirement, reason='SOURCE_RANGE_UNREAD', start_line=cursor, end_line=min(high, low - 1)))
            cursor = max(cursor, end + 1)
            if cursor > high:
                break
        if cursor <= high:
            gaps.append(dict(requirement, reason='SOURCE_RANGE_UNREAD', start_line=cursor))
    return gaps


def submit_units(record, unit_ids, coverage, limitations, *, now=None):
    """Submit an actual batch; coverage derives from its fixed obligations."""
    plan = _plan(record)
    _live(plan, now)
    if (not isinstance(unit_ids, list) or not unit_ids or len(set(unit_ids)) != len(unit_ids)
            or coverage not in {'REVIEWED', 'PARTIAL'} or not isinstance(limitations, list)
            or any(not isinstance(value, str) or not value or len(value) > 500 for value in limitations)
            or len(limitations) > 30 or (coverage == 'PARTIAL' and not limitations)):
        raise ValueError('Invalid review unit submission')
    units = [_unit(plan, identifier) for identifier in unit_ids]
    submitted = _now(now)
    progressed = False
    for unit in units:
        incomplete = bool(_unit_gaps(plan, unit))
        new_status = 'PARTIAL' if incomplete or coverage == 'PARTIAL' or limitations else 'REVIEWED'
        progressed = progressed or unit['submitted_at'] is None or (unit['status'] != 'REVIEWED' and new_status == 'REVIEWED')
        unit.update(status=new_status,
                    submitted_at=submitted, limitations=list(limitations))
    if plan['contract'] == ADAPTIVE_CONTRACT and progressed:
        renew_activity(record, now=now)
    return dict(unit_ids=list(unit_ids), coverage='PARTIAL' if any(unit['status'] != 'REVIEWED' for unit in units) else 'REVIEWED')


def plan_gaps(record):
    """Current material gaps; navigation pagination is deliberately absent."""
    plan = _plan(record)
    gaps = [dict(reason='TASK_CHANGE_COMPARISON_UNAVAILABLE', path=path)
            for path in plan['unverified_paths']]
    if plan['contract'] == ADAPTIVE_CONTRACT and plan['budget']['capacity']['status'] != 'READY':
        gaps.append(dict(reason='TASK_REVIEW_CAPACITY_REQUIRED',
                         details=copy.deepcopy(plan['budget']['capacity']['reasons'])))
    if plan['contract'] == ADAPTIVE_CONTRACT and plan.get('semantic_coverage_version') != 1:
        gaps.append(dict(reason='SEMANTIC_PLANNING_VERSION_UNAVAILABLE',
                         detail='Existing plan predates hidden semantic change tracking; evidence and quotas are retained'))
    for unit in plan['units']:
        gaps.extend(dict(gap, unit_id=unit['unit_id']) for gap in _unit_gaps(plan, unit))
        if unit['submitted_at'] is None:
            gaps.append(dict(reason='UNIT_NOT_SUBMITTED', unit_id=unit['unit_id'], path=unit['path']))
        elif unit['status'] != 'REVIEWED':
            gaps.append(dict(reason='UNIT_PARTIAL', unit_id=unit['unit_id'], path=unit['path'],
                             limitations=list(unit['limitations'])))
    return gaps


def finalize_plan(record, *, now=None):
    """Aggregate every unit, retaining static result/attempts independently."""
    plan = _plan(record)
    gaps = plan_gaps(record)
    complete = not gaps
    expired = _now(now) > plan['deadline']
    return dict(plan_id=plan['plan_id'], snapshot_id=plan['snapshot_id'],
                status='COMPLETE' if complete else ('IDLE' if plan['contract'] == ADAPTIVE_CONTRACT else 'EXPIRED') if expired else 'PARTIAL',
                coverage='REVIEWED' if complete else 'PARTIAL',
                unit_count=len(plan['units']),
                reviewed_unit_count=sum(unit['status'] == 'REVIEWED' for unit in plan['units']),
                gaps=gaps, deadline=plan['deadline'], budget=_budget_view(plan['budget']))
