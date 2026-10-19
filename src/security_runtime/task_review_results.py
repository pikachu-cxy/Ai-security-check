"""Bounded, read-only history pages; never another source-review allowance.

The combined order is all static findings followed by all host candidates.
Navigation metadata is sampled with counts; finding explanations themselves
are never silently shortened or presented as complete when unavailable.
"""
from __future__ import annotations

import copy
import json
from pathlib import PurePosixPath

from .redactor import SecretRedactor


MAX_RESULT_BYTES = 64_000
ROOT_METADATA_RESERVE = 512
MAX_FINDINGS = 3
_PUBLIC_FINDING_FIELDS = frozenset({
    'id', 'title', 'plain_title', 'category', 'severity', 'file_path',
    'line_start', 'line_end', 'location_version', 'impact', 'fix_advice',
    'preconditions', 'unknowns', 'counterevidence', 'current_protections',
    'evidence_locations', 'evidence_refs', 'risk_scope', 'task_evidence',
    'source', 'validation', 'verdict', 'scanner_sources',
})
_EXPLANATION_FIELDS = frozenset({
    'title', 'plain_title', 'impact', 'fix_advice', 'preconditions',
    'unknowns', 'counterevidence', 'current_protections',
})


def semantic_gap_notes(gaps, limit=5):
    """Explain unavailable redacted changes using safe locations, never proofs."""
    labels = {
        'SANITIZED_CHANGE_UNOBSERVABLE': '此处变化的内容已脱敏，具体值和含义无法核实。',
        'SEMANTIC_LINE_PROOF_UNAVAILABLE': '修改前记录缺少脱敏行的定位依据，无法排除这些位置还含有未定位的变化。',
        'SEMANTIC_COVERAGE_PLAN_LEGACY': '旧计划没有脱敏变化的覆盖记录，不能把原阅读范围认定为完整复核。',
        'SEMANTIC_PLANNING_VERSION_UNAVAILABLE': '旧计划没有脱敏变化的覆盖记录，不能把原阅读范围认定为完整复核。',
    }
    notes = []
    for gap in gaps:
        label = labels.get(gap.get('reason'))
        if label is None:
            continue
        path = gap.get('path') or '本次改动范围'
        low, high = gap.get('start_line'), gap.get('end_line')
        location = path
        if type(low) is int:
            location += ':'+str(low)
            if type(high) is int and high != low:
                location += '-'+str(high)
        note = location+'：'+label
        if note not in notes:
            notes.append(note)
        if len(notes) >= limit:
            break
    return notes


def _bytes(value):
    return len(json.dumps(value, ensure_ascii=False).encode('utf-8'))


def _redact(value):
    if isinstance(value, str):
        return SecretRedactor().redact(value)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


def _finding(finding):
    result = {key: copy.deepcopy(value) for key, value in finding.items()
              if key in _PUBLIC_FINDING_FIELDS}
    for key in _EXPLANATION_FIELDS & result.keys():
        result[key] = _redact(result[key])
    return result


def _sample(values, maximum=8, byte_limit=1600):
    """Navigation samples may omit entries, but never hide their total count."""
    values = list(values or [])
    selected = []
    for value in values:
        if len(selected) >= maximum:
            break
        if _bytes(value) > 512 or _bytes(selected + [value]) > byte_limit:
            continue
        selected.append(copy.deepcopy(value))
    return dict(items=selected, total_count=len(values),
                omitted_count=len(values)-len(selected))


def _limit_notes(values):
    """Keep diagnostics separate from complete risk explanations."""
    notes = []
    for value in values or []:
        if isinstance(value, str):
            text = _redact(value)
            notes.append(text if _bytes(text) <= 400 else
                         dict(message=text[:100], display_truncated=True,
                              original_char_count=len(text)))
        elif isinstance(value, dict):
            note = {key: copy.deepcopy(value[key]) for key in
                    ('reason', 'path', 'count', 'location_version', 'start_line',
                     'end_line', 'unit_id') if key in value}
            if 'paths' in value:
                note['paths'] = _sample(value['paths'], 3, 512)
            if 'lines' in value:
                note['lines'] = _sample(value['lines'], 8, 256)
            notes.append(note)
    return _sample(notes, 8, 2200)


def history_freshness(record, current, *, hook_revision=None):
    """Describe present applicability without rewriting a saved verdict.

    An unrelated later edit changes the project snapshot, not the bytes or the
    historical completion of already reviewed files. Related evidence and
    project configuration are reported separately; unchanged file hashes alone
    never attest unchanged runtime behavior or a new whole-project review.
    """
    end = record.get('end')
    if not end:
        return dict(workspace_matches_snapshot=None, reviewed_sources='UNKNOWN',
                    reason_codes=['TASK_END_SNAPSHOT_UNAVAILABLE'],
                    source_scope='SAVED_SOURCE_SNAPSHOT_AND_FILE_HOOK_SCOPE_ONLY')
    previous_hashes, hashes = end['hashes'], current['hashes']
    previous_names = set(end.get('inventory', previous_hashes))
    names = set(current.get('inventory', hashes))
    previous_complete = end.get('inventory_complete', not end.get('limitations'))
    complete = current.get('inventory_complete', not current.get('limitations'))
    changed, unknown = [], []
    for path in sorted(previous_names | names):
        if path in previous_hashes and path in hashes:
            if previous_hashes[path] != hashes[path]:
                changed.append(path)
        elif path not in names and complete:
            changed.append(path)
        elif path not in previous_names and previous_complete and path in hashes:
            changed.append(path)
        else:
            unknown.append(path)
    task_paths = {item['path'] for item in record.get('changes') or []}
    checked = set(task_paths)
    for key in ('scope_files', 'actual_files'):
        checked.update((record.get('static') or {}).get(key) or [])
    related = set(record.get('related_files') or [])
    related.update(item['path'] for item in (record.get('evidence') or {}).values()
                   if item.get('path') and item['path'] not in task_paths)
    plan = record.get('review_plan') or {}
    related.update(window['path'] for unit in plan.get('units') or []
                   for window in unit.get('required_windows') or []
                   if window['path'] not in task_paths)
    configuration = [path for path in changed if
                     PurePosixPath(path).suffix.lower() in
                     {'.yml', '.yaml', '.json', '.toml', '.xml', '.properties'}
                     or PurePosixPath(path).name in {'.env', '.gitignore'}
                     or PurePosixPath(path).name.startswith('.env.')]
    checked_changed = [path for path in changed if path in checked]
    related_changed = [path for path in changed if path in related]
    other_changed = [path for path in changed if path not in checked | related]
    scope_unknown = [path for path in unknown if path in checked | related]
    hook_changed = bool(record.get('finished_hook_revision') and
                        hook_revision != record['finished_hook_revision'])
    same = (hashes == previous_hashes and names == previous_names
            and complete == previous_complete
            and current.get('limitations', []) == end.get('limitations', [])
            and not hook_changed)
    reasons = []
    for condition, reason in (
        (bool(checked_changed), 'REVIEWED_SOURCE_CHANGED'),
        (bool(related_changed), 'RELATED_SOURCE_CHANGED'),
        (bool(configuration), 'PROJECT_CONFIGURATION_CHANGED'),
        (bool(other_changed), 'OTHER_PROJECT_SOURCE_CHANGED'),
        (hook_changed, 'FILE_HOOK_SCOPE_CHANGED'),
        (bool(unknown) or not complete or bool(current.get('limitations')),
         'CURRENT_SOURCE_COMPARISON_INCOMPLETE'),
        (complete != previous_complete or current.get('limitations', []) != end.get('limitations', []),
         'SOURCE_COMPARISON_SCOPE_CHANGED')):
        if condition:
            reasons.append(reason)
    if not same and not reasons:
        reasons.append('PROJECT_SNAPSHOT_CHANGED')
    return dict(workspace_matches_snapshot=same,
        reviewed_sources='CHANGED' if checked_changed or related_changed else
                         'UNKNOWN' if scope_unknown else 'UNCHANGED',
        source_scope='SAVED_SOURCE_SNAPSHOT_AND_FILE_HOOK_SCOPE_ONLY',
        reason_codes=reasons,
        reviewed_source_changes=_sample(checked_changed, 4, 800),
        related_source_changes=_sample(related_changed, 4, 800),
        configuration_changes=_sample(configuration, 4, 800),
        other_project_changes=_sample(other_changed, 4, 800),
        unverified_sources=_sample(unknown, 4, 800),
        current_limitations=_limit_notes(current.get('limitations') or []))


def _saved_context(record):
    """Return saved accounting and exact gap samples; absent data is unknown."""
    from .task_security import _unread_context
    ledger = record.get('review_ledger') or {}
    limits = ledger.get('limits') or {}
    unread = _unread_context(record) if 'context_requests' in record else None
    completion = record.get('review_completion') or {}
    gaps = completion.get('gaps')
    from .task_review_protocol import is_v3_record
    if gaps is None and is_v3_record(record) and record.get('review_plan'):
        from .task_review_plan import plan_gaps
        gaps = plan_gaps(copy.deepcopy(record))
    evidence = record.get('evidence')
    return dict(used_bytes=ledger.get('total_bytes', record.get('context_bytes')),
        max_bytes=limits.get('total_bytes'),
        used_reads=ledger.get('reads', len(evidence) if evidence is not None else None),
        max_reads=limits.get('reads'),
        unread_range_count=len(unread) if unread is not None else None,
        unread_ranges=_sample(unread) if unread is not None else None,
        plan_gap_count=len(gaps) if gaps is not None else None,
        plan_gaps=_sample(gaps) if gaps is not None else None,
        gaps=_limit_notes(record['context_gaps']) if 'context_gaps' in record else None,
        record_only=True)


def _suppressed(value):
    return bool(value.get('reminder_suppressed', value.get('folded', False)))


def _compact_feedback(value):
    assessment_fields = ('status', 'folded', 'recorded_status', 'evidence_type', 'recorded_at', 'event_id')
    item = {key: copy.deepcopy(value[key]) for key in (*assessment_fields, 'reminder_suppressed',
            'handling_status', 'handling_label', 'handling_source') if key in value}
    if value.get('technical_feedback'):
        item['technical_feedback'] = {key: copy.deepcopy(value['technical_feedback'][key])
            for key in assessment_fields if key in value['technical_feedback']}
    if value.get('disposition'):
        item['disposition'] = {key: copy.deepcopy(value['disposition'][key]) for key in
            ('disposition', 'active', 'suppressed', 'reassessment_required', 'expired',
             'until', 'recorded_at', 'event_id') if key in value['disposition']}
    return item


def _base(record, freshness=None, feedback=None, static_feedback=None, *, handling_available=True):
    static, review = record.get('static') or {}, record.get('review') or {}
    owner = record.get('task_owner') or {}
    completion = record.get('review_completion') or {}
    changes = record.get('changes') or []
    static_findings, host_findings = static.get('findings') or [], review.get('findings') or []
    result = dict(status=record['phase'], task_ref=record['task_ref'],
        protocol_version=(record.get('review_protocol') if type(record.get('review_protocol')) is int else None),
        history_read_only=True, scanner_run=False,
        repair_authorized=False,
        task_scope=('HOST_SESSION' if owner.get('host') in {'codex', 'cursor'} else
                    'MCP_CONNECTION' if owner else 'LEGACY_UNOWNED'),
        review_required=record['phase'] in {'READY', 'REVIEWING'},
        changed_file_count=len(changes), changes=_sample(changes),
        baseline_file_count=len(record['baseline']['hashes']),
        unverified_file_count=len(record.get('unverified_paths') or []),
        limitations=_limit_notes(record.get('limitations') or []),
        static=dict(status=static.get('status'), coverage=static.get('coverage'),
                    scan_id=static.get('scan_id'), duration_ms=static.get('duration_ms'),
                    finding_count=len(static_findings),
                    scope_files=_sample(static.get('scope_files') or []),
                    actual_files=_sample(static.get('actual_files') or [])),
        host_review=dict(coverage=review.get('coverage'), source=review.get('source'),
                         validation=review.get('validation'), finding_count=len(host_findings),
                         elapsed_wall_ms=review.get('elapsed_wall_ms'),
                         submitted_at=review.get('submitted_at'),
                         limitations=_limit_notes(review.get('limitations') or [])),
        file_hook_checks=dict(check_count=len(record.get('hook_checks') or []),
                              omitted_check_count=record.get('hook_checks_omitted', 0),
                              current_recheck_files=_sample(record.get('hook_final_recheck_files') or [])),
        context_read_coverage=_saved_context(record),
        max_response_bytes=MAX_RESULT_BYTES,
        history_contract='Saved results only; this read does not run checks or extend source-review budgets.')
    from .task_review_protocol import is_v3_record, UnsupportedTaskReviewProtocol
    if not is_v3_record(record):
        result.update(review_required=False,
            historical_review_required=record['phase'] in {'READY', 'REVIEWING'},
            protocol_support=UnsupportedTaskReviewProtocol(record.get('review_protocol')).response())
    if is_v3_record(record):
        result.update(review_revision=record.get('review_revision', 1),
                      previous_review_count=len(record.get('review_history', [])))
    feedback, static_feedback = feedback or {}, static_feedback or {}
    pending_host = sum(not _suppressed(feedback.get(item['id'], {})) for item in host_findings)
    pending_static = sum(not _suppressed(static_feedback.get(item['id'], {})) for item in static_findings)
    result['risk_counts'] = dict(raw_total=len(host_findings)+len(static_findings),
        current_handling='KNOWN' if handling_available else 'UNKNOWN',
        current_pending_total=pending_host+pending_static if handling_available else None,
        current_pending_host=pending_host if handling_available else None,
        current_pending_static=pending_static if handling_available else None)
    if feedback or static_feedback or not handling_available:
        # Current handling is separate from immutable findings and AI evidence.
        # A direct user choice can stop reminders without declaring safety.
        suppressed = [identifier for identifier, value in feedback.items() if _suppressed(value)]
        folded = [identifier for identifier, value in feedback.items()
                  if value.get('technical_feedback', value).get('folded')
                  and (value.get('disposition') or {}).get('disposition') != 'RESTORE']
        result['current_feedback'] = dict(
            folded_host_risk_count=len(folded) if handling_available else None,
            suppressed_host_risk_count=len(suppressed) if handling_available else None,
            excluded_host_risk_count=(sum(value.get('handling_status') == 'EXCLUDED'
                for value in feedback.values()) if handling_available else None),
            deferred_host_risk_count=(sum(value.get('handling_status') == 'DEFERRED'
                for value in feedback.values()) if handling_available else None),
            visible_host_risk_count=pending_host if handling_available else None,
            visible_static_risk_count=pending_static if handling_available else None,
            handling_available=handling_available,
            # Only page-local details are copied below; project-wide counts do
            # not make an unbounded second copy of the disposition ledger.
            by_finding_id={}, static_by_finding_id={},
            detail_tool='get_task_risk_feedback',
            message='按用户处置和当前技术评估展示待处理项；原始发现、AI判断和处理历史完整保留。')
    if freshness is not None:
        result.update(historical_status=record['phase'],
                      current_version=freshness['workspace_matches_snapshot'],
                      version_freshness=freshness)
        if freshness['workspace_matches_snapshot'] is False:
            result['review_required'] = False
            if record['phase'] not in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}:
                result['status'] = 'STALE'
            if freshness['reviewed_sources'] == 'UNCHANGED':
                message = ('已检查文件及已读取关联源码的内容没有变化；项目其他内容或检查范围已变化。'
                           '原检查完成状态保留，这份记录不代表已检查项目后续改动。')
            elif freshness['reviewed_sources'] == 'CHANGED':
                message = ('已检查文件或其关联源码后来发生变化，具体路径见版本明细。'
                           '原检查完成状态保留，历史结论不能直接用于变化后的内容。')
            else:
                message = ('当前部分文件无法完成版本比较，具体路径和原因见版本明细。'
                           '原检查状态保留，无法确认这些内容是否仍适用。')
            result['version_notice'] = message
    if completion:
        result['review_progress'] = {key: completion[key] for key in
                                     ('unit_count', 'reviewed_unit_count', 'coverage', 'status')
                                     if key in completion}
    elif record.get('review_plan'):
        units = record['review_plan'].get('units') or []
        count = sum(unit.get('status') == 'REVIEWED' for unit in units)
        result['review_progress'] = dict(unit_count=len(units), reviewed_unit_count=count,
            coverage='REVIEWED' if count == len(units) and not record.get('unverified_paths') else 'PARTIAL',
            status='IN_PROGRESS')
    if record.get('review_capacity'):
        result['review_capacity'] = copy.deepcopy(record['review_capacity'])
        if record['phase'] not in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'}:
            result.update(status='CAPACITY_REQUIRED', review_required=False)
    if static.get('reason'):
        result['static']['reason'] = static['reason']
    if record.get('skip_reason'):
        result['incomplete_reason'] = _limit_notes([record['skip_reason']])
    return result




def _page(base, record, rows, offset, index, limit, selected, next_offset, *,
          feedback=None, static_feedback=None, handling_available=True, delivery=False):
    result = copy.deepcopy(base)
    result['findings'] = selected
    feedback, static_feedback = feedback or {}, static_feedback or {}
    for item in selected:
        identifier = item.get('detail', {}).get('id')
        source_feedback = feedback if item['source'] == 'HOST_TASK_REVIEW' else static_feedback
        if identifier in source_feedback:
            compact = _compact_feedback(source_feedback[identifier])
            item['detail']['feedback'] = compact
            key = 'by_finding_id' if item['source'] == 'HOST_TASK_REVIEW' else 'static_by_finding_id'
            result['current_feedback'][key][identifier] = copy.deepcopy(compact)
    result['finding_page'] = dict(finding_offset=offset, logical_offset=index,
        requested_limit=limit, returned_count=len(selected), total_count=len(rows),
        static_count=len((record.get('static') or {}).get('findings') or []),
        host_count=len((record.get('review') or {}).get('findings') or []),
        has_more=next_offset is not None, next_offset=next_offset,
        ordering='STATIC_THEN_HOST', max_findings_per_page=MAX_FINDINGS)
    from .reply_adapters import history_facts
    from .reply_plan import plan_reply
    from .reply_render import choice_labels, render_reply
    facts = history_facts(record, selected,
        current=result.get('current_version', True), feedback=feedback,
        static_feedback=static_feedback, handling_available=handling_available,
        delivery=delivery)
    # Scope/diagnostic notices can contain arbitrarily long historical paths.
    # Bound their display separately from complete finding explanations, while
    # retaining the original record and honest sampled scope counts above.
    from dataclasses import replace
    from .reply_plan import Notice
    omitted = 0
    notices = []
    for notice in facts.notices:
        if len(notices) >= 8:
            omitted += 1
        elif _bytes(notice.text) > 2_000:
            omitted += 1
            notices.append(Notice(notice.kind,
                '一项历史范围说明超过单页长度；原记录完整保留，覆盖缺口及省略数量见本页明细。'))
        else:
            notices.append(notice)
    if omitted:
        result['notice_display'] = dict(complete=False, omitted_count=omitted,
                                       original_count=len(facts.notices))
        facts = replace(facts, notices=tuple(notices))
    plan = plan_reply(facts)
    result['reply_plan'] = plan.to_dict()
    result['risk_choices'] = []
    for risk in plan.risks:
        if risk.identifier not in plan.action_ids:
            continue
        identifier = risk.identifier
        source = 'HOST_TASK_REVIEW' if risk.source == 'HOST_REVIEW' else 'STATIC_SCAN'
        choice = dict(finding_id=identifier, source=source, options=choice_labels(),
            deferred_keeps_risk=True, repair_authorized=False,
            handling_tool='set_task_risk_disposition' if source == 'HOST_TASK_REVIEW' else 'set_finding_disposition',
            repair_workflow='HOST_TASK_RISK' if source == 'HOST_TASK_REVIEW' else 'SCANNER_TASK_GROUP')
        if source == 'HOST_TASK_REVIEW':
            choice['task_ref'] = record['task_ref']
        else:
            choice['scan_id'] = record['static']['scan_id']
        result['risk_choices'].append(choice)
    result['risk_counts']['page_visible'] = plan.total_risk_count if handling_available else None
    result['development_summary'] = render_reply(plan, include_risks=delivery)
    if delivery and (offset or next_offset is not None):
        result['development_summary'] += ('\n\n本页返回 '+str(len(selected))+' 项原始风险记录，'
            '当前可提醒 '+str(plan.total_risk_count if handling_available else '未知')+' 项；'
            '全部原始记录共 '+str(len(rows))+' 项，后续详情按页返回。')
    if result.get('protocol_support'):
        result['development_summary'] += '\n旧开发任务协议已停止执行，此处仅保留历史查询。未完成旧任务不能继续或转为 v3；只能在后续新工作实际编辑前显式建立新任务，不能为旧改动补建基线。'
    if next_offset is not None:
        result['next_action'] = dict(tool='get_task_security_review', task_ref=record['task_ref'],
                                     finding_offset=next_offset, finding_limit=min(limit, MAX_FINDINGS))
        if delivery:
            result['next_action']['completion_revision'] = record.get('review_revision', 1)
    result['response_bytes'] = 0
    return result


def seal_history_result(packet):
    """Recount after bounded service metadata, keeping the hard wire limit."""
    packet.setdefault('response_bytes', 0)
    for _ in range(8):
        cost = _bytes(packet)
        if packet['response_bytes'] == cost:
            if cost > MAX_RESULT_BYTES:
                raise ValueError('History response exceeds its independent byte limit')
            return packet
        packet['response_bytes'] = cost
    raise ValueError('History response size did not stabilize')


def bounded_history_result(record, offset=0, limit=3, *, now=None, freshness=None, feedback=None,
                           static_feedback=None, handling_available=True, delivery=False):
    """Return at most three complete risks, or an explicit detail-limit notice.

    ``now`` is accepted for the service's clock-compatible interface; history
    reads do not change deadline, ownership, ledger or stored review state.
    Only presentation fields are public; raw scanner payload/source is excluded.
    """
    if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 30:
        raise ValueError('Invalid history result page')
    static, review = record.get('static') or {}, record.get('review') or {}
    rows = [('STATIC_SCAN', finding) for finding in static.get('findings') or []]
    rows.extend(('HOST_TASK_REVIEW', finding) for finding in review.get('findings') or [])
    index = offset
    base = _base(record, freshness, feedback, static_feedback, handling_available=handling_available)
    if delivery:
        base.update(history_read_only=False, delivery_read_only=True,
                    delivery_contract='CURRENT_TASK_COMPLETION',
                    completion_revision=record.get('review_revision', 1))
    options = dict(feedback=feedback, static_feedback=static_feedback,
                   handling_available=handling_available, delivery=delivery)
    count = min(limit, MAX_FINDINGS)
    if index >= len(rows):
        return seal_history_result(_page(base, record, rows, offset, index, limit, [], None, **options))
    for size in range(min(count, len(rows)-index), 0, -1):
        selected = [dict(finding_index=position, source=rows[position][0],
                         details_complete=True, detail=_finding(rows[position][1]))
                    for position in range(index, index+size)]
        next_offset = index+size if index+size < len(rows) else None
        packet = _page(base, record, rows, offset, index, limit, selected, next_offset, **options)
        if _bytes(packet) + 8 <= MAX_RESULT_BYTES - ROOT_METADATA_RESERVE:
            return seal_history_result(packet)
    source, finding = rows[index]
    next_offset = index+1 if index+1 < len(rows) else None
    selected = [dict(finding_index=index, source=source, details_complete=False,
                     reason_code='RESULT_DETAIL_LIMIT', finding_id=finding.get('id'),
                     message='This finding alone exceeds the history response limit. Its original local record is retained; inspect that record for the full explanation. No complete risk details were returned.')]
    packet = _page(base, record, rows, offset, index, limit, selected, next_offset, **options)
    packet['details_complete'] = False
    packet['reason_code'] = 'RESULT_DETAIL_LIMIT'
    return seal_history_result(packet)
