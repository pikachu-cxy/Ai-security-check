"""Task-wide, version-bound review units and cumulative delivery budgets.

This module neither reads source nor runs scanners. Its caller owns the signed
task record, source guards and transaction. A batch is a view of one fixed plan;
it never creates another snapshot, static attempt or budget.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import time


from .protocol import PROTOCOL_VERSION, validate_protocol, require_record_protocol
from .coverage import adds_read_coverage, complete_spans, evidence_fields

CONTRACT = 'task-review-plan-v3'
DEFAULT_LIMITS = dict(response_bytes=16_000)
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
    identity = dict(task_ref=record['task_ref'],
                        before=record['baseline']['hashes'],
                        after=record['end']['hashes'], changes=record['changes'],
                        hook_revision=record.get('finished_hook_revision'),
                        unverified_paths=record.get('unverified_paths', []))
    # Keep existing snapshot identities stable. Later revisions are distinct
    # even if a caller edits a file back to an earlier reviewed version.
    if record.get('review_revision', 1) > 1:
        identity['review_revision'] = record['review_revision']
    if record['end'].get('version_ref'):
        identity['end_version_ref'] = record['end']['version_ref']
    if record['baseline'].get('redaction_version', 1) >= 3:
        identity['source_representation_version'] = record['baseline']['redaction_version']
    return _digest(identity)


def _plan(record):
    require_record_protocol(record)
    plan = record.get('review_plan')
    if not plan or plan.get('contract') != CONTRACT:
        raise ReviewPlanError('REVIEW_PLAN_UNAVAILABLE', 'Prepare a review plan first')
    if plan['snapshot_id'] != _snapshot(record):
        raise ReviewPlanError('REVIEW_PLAN_STALE', 'Task snapshot changed; old evidence is historical')
    # JSON persistence does not retain Python object aliases. The independent
    # lifetime ledger remains authoritative after every signed-record reload.
    ledger = record.get('review_ledger')
    if not isinstance(ledger, dict) or not ledger:
        raise ReviewPlanError('REVIEW_PLAN_REVISION_INVALID',
                              'A v3 plan requires its original cumulative ledger')
    if type(ledger.get('protocol_version')) is not int or ledger['protocol_version'] != PROTOCOL_VERSION:
        raise ReviewPlanError('REVIEW_PLAN_PROTOCOL_FIXED', 'Plan and lifetime ledger protocols must agree')
    plan['budget'] = ledger
    plan['related_files'] = ledger['related_files']
    return plan


def _live(plan, now):
    if _now(now) > plan['deadline']:
        raise ReviewPlanError('REVIEW_PLAN_IDLE',
                              'Review activity lease is idle; resume the same snapshot and ledger')


def _budget_view(ledger, batch_id=None):
    """Bounded metadata for the v3 lifetime ledger."""
    view = {key: ledger[key] for key in
            ('control_bytes', 'navigation_bytes', 'source_bytes', 'total_bytes', 'reads')}
    view.update(limits=dict(ledger['limits']), deadline=ledger['deadline'],
                remaining_bytes=max(0, ledger['limits']['total_bytes'] - ledger['total_bytes']),
                remaining_reads=max(0, ledger['limits']['reads'] - ledger['reads']),
                category_limits=dict(ledger['category_limits']),
                category_remaining={key: max(0, maximum-ledger[key+'_bytes'])
                                    for key, maximum in ledger['category_limits'].items()},
                activity_lease=dict(ledger['activity_lease']),
                capacity=copy.deepcopy(ledger['capacity']))
    if batch_id is not None:
        view.update(batch_id=batch_id, batch_bytes=ledger['batches'].get(batch_id, 0),
                    target_batch_bytes=ledger['limits']['batch_bytes'], batch_is_scheduling_only=True)
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


def build_plan(record, *, now=None, deadline=None, limits=None, protocol_version=PROTOCOL_VERSION):
    """Create the sole executable plan without migrating an older task."""
    validate_protocol(protocol_version)
    require_record_protocol(record)
    if limits is not None:
        raise ReviewPlanError('REVIEW_PLAN_LIMITS_FIXED',
                              'Allowances derive from required ranges, not caller overrides')
    if record.get('review_plan'):
        plan = _plan(record)
        if deadline is not None and deadline != plan['deadline']:
            raise ReviewPlanError('REVIEW_PLAN_DEADLINE_FIXED', 'A prepared task keeps its activity lease')
        return plan
    if record.get('review_ledger'):
        validate_protocol(record['review_ledger'].get('protocol_version'))
    return _build_adaptive(record, now=_now(now), deadline=deadline, limits=None)


def _build_adaptive(record, *, now, deadline, limits):
    from . import budget as adaptive
    from .windows import adaptive_windows
    if limits is not None:
        raise ReviewPlanError('REVIEW_PLAN_LIMITS_FIXED', 'Adaptive allowances derive from actual obligations, not legacy overrides')
    if (record.get('pending_review_revision') or record.get('review_history')) and not record.get('review_ledger'):
        raise ReviewPlanError('REVIEW_PLAN_REVISION_INVALID', 'Revision history requires its original cumulative ledger')
    if record.get('review_ledger') and not record.get('pending_review_revision'):
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
        if record.get('review_ledger'):
            from .revisions import revision_ledger, ReviewRevisionError
            try:
                ledger = revision_ledger(record, units, now=now)
            except ReviewRevisionError as exc:
                raise ReviewPlanError(exc.reason_code, str(exc)) from None
        else:
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
    plan = dict(contract=CONTRACT, protocol_version=3, semantic_coverage_version=1, snapshot_id=snapshot,
        plan_id='tp3-'+_digest([record['task_ref'], snapshot])[:32], created_at=now,
        review_revision=record.get('review_revision', 1),
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
    record.pop('pending_review_revision', None)
    return plan


def record_capacity(record):
    from .budget import record_capacity as capacity
    return capacity(record)


def source_binding(record, path, file_sha256, location_version, total_lines=None):
    """Register immutable source identity, without delivery or coverage credit."""
    plan = _plan(record)
    return _source_binding(record, plan, path, file_sha256, location_version, total_lines)


def _source_binding(record, plan, path, file_sha256, location_version, total_lines=None):
    if plan['contract'] != CONTRACT:
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
    from . import budget as adaptive
    plan = _plan(record)
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
        review_revision=plan.get('review_revision', 1),
        unit_count=len(plan['units']), navigation_count=len(navigation), cursor=cursor,
        units=units, next_cursor=high if high < len(navigation) else None,
        batch_id=units[0]['batch_id'] if units else None, sources=list(sources.values()),
        deadline=plan['deadline'], budget=_budget_view(plan['budget'], units[0]['batch_id'] if units else None),
        capacity=copy.deepcopy(plan['budget']['capacity']), batching='ESTIMATED_CAPACITY_SCHEDULING_ONLY',
        trust='NAVIGATION_ONLY_NOT_REVIEW_PROOF')


def plan_page(record, cursor=0, limit=10):
    """Navigation fragments never drop underlying v3 review obligations."""
    plan = _plan(record)
    if type(cursor) is not int or cursor < 0 or type(limit) is not int or not 1 <= limit <= 30:
        raise ValueError('Invalid review plan page')
    return _adaptive_page(record, plan, cursor, limit)


def charge_packet(record, packet, category='control', source_bytes=0, *, now=None, batch_id=None):
    """Charge every delivery to the original v3 category allowances."""
    from . import budget as adaptive
    plan = _plan(record)
    _live(plan, now)
    if category not in {'control', 'navigation', 'source', 'method'}:
        raise ValueError('Invalid context byte category')
    if category == 'method':
        # This exception is only for the complete fixed method already bound
        # to the task. Arbitrary control/source packets retain the 16KB limit.
        expected = record.get('packet', {}).get('quick_skill', {})
        guide = packet.get('quick_skill') if isinstance(packet, dict) else None
        if (not isinstance(packet, dict) or set(packet) != {'quick_skill'}
                or not isinstance(guide, dict) or set(guide) != {'version', 'sha256', 'content'}
                or not isinstance(guide['content'], str) or not guide['content']
                or source_bytes != 0 or batch_id is not None
                or any(guide[key] != expected.get(key) for key in ('version', 'sha256'))
                or len(guide['content'].encode('utf-8')) > adaptive.METHOD_CONTENT_BYTES
                or hashlib.sha256(guide['content'].encode('utf-8')).hexdigest() != guide['sha256']):
            raise ValueError('Method delivery must match the fixed task-bound version and digest')
    raw = packet if isinstance(packet, bytes) else json.dumps(packet, ensure_ascii=False).encode('utf-8')
    cost = len(raw)
    if type(source_bytes) is not int or not 0 <= source_bytes <= cost:
        raise ValueError('Invalid source byte breakdown')
    budget = plan['budget']
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


def _unit(plan, unit_id):
    unit = next((item for item in plan['units'] if item['unit_id'] == unit_id), None)
    if unit is None:
        raise ValueError('Unknown review unit')
    return unit


def register_related(record, unit_id, path, file_sha256, start_line, end_line,
                     location_version='CURRENT_TASK_END', *, now=None, source_lines=None):
    """Register only new, verified v3 obligations without resetting consumption."""
    plan = _plan(record)
    _live(plan, now)
    if location_version not in _VERSIONS or record[_VERSIONS[location_version]]['hashes'].get(path) != file_sha256:
        raise ValueError('Related source must match the task snapshot')
    if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line:
        raise ValueError('Invalid related source range')
    return _register_related_adaptive(record, plan, unit_id, path, file_sha256,
                                      start_line, end_line, location_version, source_lines)


def _register_related_adaptive(record, plan, unit_id, path, file_hash, low, high, version, source_lines):
    from . import budget as adaptive
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
    if not isinstance(evidence, dict) or 'evidence_id' not in evidence:
        raise ValueError('Invalid source evidence')
    item = evidence_fields(evidence)
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
    binding = _digest(item)
    historical = plan['budget']['evidence_bindings'].get(identifier)
    if historical is not None and historical != binding:
        raise ValueError('An evidence identifier cannot change its source version or range')
    prior = plan['evidence'].get(identifier)
    if prior is not None and prior != item:
        raise ValueError('An evidence identifier cannot change its range')
    from . import budget as adaptive
    adds_coverage = adds_read_coverage(plan['evidence'].values(), item)
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
    if adds_coverage:
        renew_activity(record, now=now)
    return item


def _unit_gaps(plan, unit):
    gaps = [dict(gap) for gap in unit['evidence_gaps']]
    for requirement in unit['required_windows']:
        if requirement['end_line'] is None:
            gaps.append(dict(reason='SOURCE_RANGE_UNKNOWN', **requirement))
            continue
        covered = complete_spans(e for e in plan['evidence'].values()
                                 if all(e[key] == requirement[key] for key in ('path', 'file_sha256', 'location_version')))
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
    if progressed:
        renew_activity(record, now=now)
    return dict(unit_ids=list(unit_ids), coverage='PARTIAL' if any(unit['status'] != 'REVIEWED' for unit in units) else 'REVIEWED')


def plan_gaps(record):
    """Current material gaps; navigation pagination is deliberately absent."""
    plan = _plan(record)
    gaps = [dict(reason='TASK_CHANGE_COMPARISON_UNAVAILABLE', path=path)
            for path in plan['unverified_paths']]
    if plan['budget']['capacity']['status'] != 'READY':
        gaps.append(dict(reason='TASK_REVIEW_CAPACITY_REQUIRED',
                         details=copy.deepcopy(plan['budget']['capacity']['reasons'])))
    if plan.get('semantic_coverage_version') != 1:
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
                status='COMPLETE' if complete else 'IDLE' if expired else 'PARTIAL',
                coverage='REVIEWED' if complete else 'PARTIAL',
                unit_count=len(plan['units']),
                reviewed_unit_count=sum(unit['status'] == 'REVIEWED' for unit in plan['units']),
                gaps=gaps, deadline=plan['deadline'], budget=_budget_view(plan['budget']))
