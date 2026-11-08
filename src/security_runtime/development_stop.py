"""Native Stop fallback for the explicitly focused observed-edit check only."""
from __future__ import annotations

import json
import hashlib
import time

from .development_check import DevelopmentCheckService, DevelopmentCheckStore, owner_key, legacy_guard
from .host_lifecycle import COMPACT_DEVELOPMENT_HOSTS
from .user_config import analysis_requirements, batch_config
from .development_reporting import INSTRUCTIONS, reporting


def fallback(hooks, root, owner, *, stopped_normally=True, stop_hook_active=False,
             service=None, offered=(), turn_id=None, automatic=False, session_id=None, child_turn_resolver=None):
    try:
        return _fallback(hooks, root, owner, stopped_normally=stopped_normally,
            stop_hook_active=stop_hook_active, service=service, offered=offered,
            turn_id=turn_id, automatic=automatic, session_id=session_id, child_turn_resolver=child_turn_resolver)
    except Exception:
        if not automatic or not stopped_normally:
            raise
        # An exception after consuming eligibility must not silently lose the
        # handoff. Read the same signed owner/turn; never restart the scanner.
        notice = interrupted_notice(hooks, root, owner, turn_id=turn_id,
                                    reason='STOP_CLOSEOUT_FAILED', service=service)
        if notice is None:
            raise
        return notice


def interrupted_notice(hooks, root, owner, *, turn_id=None,
                       reason='STOP_HANDOFF_INTERRUPTED', service=None):
    if owner.get('host') not in COMPACT_DEVELOPMENT_HOSTS:
        return None
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return None
    focus = store.read('focus:' + owner_key(owner))
    if not focus:
        return None
    row = store.load(focus['check_ref'], owner)
    if not row.get('effective_config') or not batch_config(row)['development']['stop_fallback']['enabled']:
        return None
    turn = hashlib.sha256(turn_id.encode()).hexdigest() if turn_id else None
    activities = [row.get('stop_activity', {}), *row.get('stop_activity_previous', ())]
    if not any((a.get('turn') == turn if turn is not None else a.get('pending') and a.get('turn'))
               and row['dirty_seq'] > a.get('base_seq', row['dirty_seq']) for a in activities):
        return None
    if row['scanned_seq'] == row['dirty_seq'] and reason != 'STOP_CLOSEOUT_FAILED':
        return None
    # A saved handoff for this input already exists. Reopening a chat is not
    # permission to repeat its report or claim the user has read it.
    if (row.get('stop_closeout_notice') or {}).get('seq') == row['dirty_seq']:
        return None
    service = service or DevelopmentCheckService(None, hooks, owner=owner,
                                                 scan_path_provider=row['scan_path'])
    return incomplete_notice(service, root, row['check_ref'], row['dirty_seq'], row, reason=reason)


def _fallback(hooks, root, owner, *, stopped_normally=True, stop_hook_active=False,
              service=None, offered=(), turn_id=None, automatic=False, session_id=None, child_turn_resolver=None):
    if not stopped_normally or owner.get('host') not in {'codex', 'cursor', 'workbuddy'}:
        return None
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return None
    focus = store.read('focus:' + owner_key(owner))
    if not focus:
        return None
    row = store.load(focus['check_ref'], owner)
    if automatic:
        # A completed background batch is eligible independently of the edit
        # turn consumed by the first Stop. No polling, finish or scan here.
        previous, seen = row, set()
        while previous and len(seen) < 8 and previous['check_ref'] not in seen:
            seen.add(previous['check_ref'])
            notice = saved_handoff(hooks, root, owner, previous, service=service)
            if notice:
                return notice
            predecessor = previous.get('previous_closeout_ref')
            previous = store.load(predecessor, owner) if predecessor else None
    activity = row.get('stop_activity', {})
    turn = hashlib.sha256(turn_id.encode()).hexdigest() if turn_id else None
    prior_activity = False
    if activity.get('turn') is not None and activity['turn'] != turn:
        activity = next((a for a in row.get('stop_activity_previous', ())
                         if turn is not None and a.get('turn') == turn), None)
        if activity is None and automatic and turn is not None and child_turn_resolver is not None:
            pending = [a for a in [row.get('stop_activity', {}), *row.get('stop_activity_previous', ())]
                       if a.get('pending') and a.get('turn') and row['dirty_seq'] > a.get('base_seq', row['dirty_seq'])]
            if pending:
                linked = child_turn_resolver(root, session_id, turn_id, {a['turn'] for a in pending})
                selected = [a for a in pending if a['turn'] in linked]
                if selected and len(selected) == len(pending):
                    # Bind only host-proven executor turns. The existing signed
                    # batch, immutable results and normal scan path remain intact.
                    with store.transaction() as db:
                        current = store._get(db, row['check_ref'])
                        if (current.get('dirty_seq') != row['dirty_seq'] or current.get('stop_activity') != row.get('stop_activity')
                                or current.get('stop_activity_previous', ()) != row.get('stop_activity_previous', ())):
                            return None
                        activities = [current.get('stop_activity', {}), *current.get('stop_activity_previous', ())]
                        activity = dict(turn=turn, base_seq=min(a['base_seq'] for a in selected), pending=True,
                                        executor_turns=sorted({a['turn'] for a in selected}))
                        current['stop_activity_previous'] = [a for a in activities if a and a not in selected][-8:]
                        current['stop_activity'] = activity
                        store._put(db, row['check_ref'], current)
                        row = current
        if activity is None:
            return None
        prior_activity = activity in row.get('stop_activity_previous', ())
    progress = row.get('stop_fallback') or {}
    if stop_hook_active and not automatic:
        # A historical pending check is not authority to interrupt a new turn.
        # Missing turn identity permits one initial fallback, never continuation.
        if turn is None or progress.get('turn') != turn:
            return None
    elif not activity.get('pending'):
        # Only the same development turn may receive a newly saved audit result.
        # No worker, polling or filesystem traversal is needed for this check.
        if not (automatic and turn is not None and activity.get('turn') == turn and audit_report_changed(row)):
            return None
    # Consume this round's eligibility even when Stop is disabled or already done.
    if activity.get('pending'):
        with store.transaction() as db:
            current = store._get(db, row['check_ref'])
            if prior_activity:
                prior = list(current.get('stop_activity_previous', ()))
                if activity not in prior:
                    return None
                current['stop_activity_previous'] = [a for a in prior if a != activity]
            else:
                if current.get('stop_activity') != activity:
                    return None
                current['stop_activity'] = dict(activity, pending=False)
            store._put(db, row['check_ref'], current)
    # Do not turn old abandoned records into new work on a later read-only chat.
    if not row.get('effective_config'):
        return None
    options = batch_config(row)['development']['stop_fallback']
    if not options['enabled'] or legacy_guard(hooks, root, owner) is not None:
        return None
    from .development_file_watch import stop_window
    deadline = None
    if automatic:
        from .development_check import native_wait_seconds
        deadline = time.monotonic() + native_wait_seconds(row)
    draining = row.get('file_watch', {}).get('status') == 'ACTIVE'
    stop_window(store, row['check_ref'], owner, deadline=deadline)
    row = store.load(row['check_ref'], owner)
    if (automatic or not stop_hook_active) and row['dirty_seq'] <= activity.get('base_seq', row['dirty_seq']):
        if (automatic and draining and row.get('file_watch', {}).get('status') == 'FAILED'
                and 'FILE_WATCH_SETTLEMENT_TIMEOUT' in row.get('file_watch_gaps', ())):
            if owner['host'] in COMPACT_DEVELOPMENT_HOSTS:
                service = service or DevelopmentCheckService(None, hooks, owner=owner,
                                                             scan_path_provider=row['scan_path'])
                return incomplete_notice(service, root, row['check_ref'], row['dirty_seq'], row)
            return dict(status='STOP_FALLBACK_INCOMPLETE', check_ref=row['check_ref'],
                        systemMessage='监听未在本轮预算内收完，尚未确认全部文件变更。')
        return None
    if not row['dirty_seq']:
        return None
    ref, seq = row['check_ref'], row['dirty_seq']
    service = service or DevelopmentCheckService(None, hooks, owner=owner,
                                                 scan_path_provider=row['scan_path'])
    if automatic:
        return native_closeout(service, root, row, deadline, offered, session_id)
    saved = service.get(root, ref)
    # Suppress only unchanged waiting already returned by closeout in this connection.
    # This is not acknowledgement of a report or of the user's reading it.
    if (saved['status'] in {'QUEUED', 'RUNNING'} and row['finish_requested']
            and (ref, seq, 'WAITING') in offered):
        return None
    # Terminal coverage limits remain reportable facts, not unfinished work.
    # Suppressing Stop neither clears those gaps nor acknowledges user delivery.
    if (saved['status'] in {'RESULTS_READY', 'PARTIAL'} and saved.get('result_available')
            and saved['scanned_seq'] == saved['dirty_seq'] == seq
            and (saved.get('host_review_completed') or not any(batch_config(row)['agent'].values()))):
        return None
    if saved['status'] == 'FAILED':
        # Failure is terminal, not work that another Stop can complete.
        # Persist one non-blocking notice per input version, across reconnects.
        with store.transaction() as db:
            current = store._get(db, ref)
            if current['dirty_seq'] != seq or current.get('stop_failure_notice_seq') == seq:
                return None
            store._put(db, ref, dict(current, stop_failure_notice_seq=seq))
        return dict(status='STOP_FALLBACK_INCOMPLETE', scanner_run=False,
                    reason_code=saved.get('reason_code'),
                    systemMessage='本次安全检查失败，失败记录已保留；不会通过 Stop 自动重试。')
    terminal_result = ([seq, saved.get('scan_id'), saved['status']]
        if saved.get('result_available') and row['scanned_seq'] == seq
        and saved['status'] in {'RESULTS_READY', 'PARTIAL'} else None)
    with store.transaction() as db:
        current = store._get(db, ref)
        if current['dirty_seq'] != seq:
            return None
        progress = current.get('stop_fallback')
        # One continuation per saved terminal result, not a report acknowledgement.
        # Keep coverage gaps and inconclusive reviews pending without repeating Stop.
        if (terminal_result is not None and progress
                and progress.get('terminal_result') == terminal_result):
            return None
        # Some hosts omit/reset stop_hook_active on continuation. Bind the
        # overall budget to the verified turn, not that advisory flag or seq.
        # Without a turn identity retain the existing conservative budget.
        new_turn = (turn is not None and progress is not None
                    and progress.get('turn') != turn)
        if progress is None or (new_turn and not stop_hook_active):
            if stop_hook_active:
                return None
            progress = dict(seq=seq, turn=turn, count=0, deadline=store.now()+options['wait_timeout_seconds'])
        if progress.get('incomplete_reason') == 'STOP_FALLBACK_BUDGET_EXHAUSTED':
            return None
        if progress['count'] >= options['max_continuations'] or progress['deadline'] <= store.now():
            store._put(db, ref, dict(current, stop_fallback=dict(progress,
                incomplete_reason='STOP_FALLBACK_BUDGET_EXHAUSTED')))
            return dict(status='STOP_FALLBACK_INCOMPLETE', scanner_run=False,
                        review_progress=saved.get('review_progress'),
                        reason_code='STOP_FALLBACK_BUDGET_EXHAUSTED',
                        systemMessage='安全检查或结果报告尚未确认完成；已提交的检查和结果已保留。')
        progress = dict(progress, seq=seq, count=progress['count']+1)
        if terminal_result is not None:
            progress['terminal_result'] = terminal_result
        store._put(db, ref, dict(current, stop_fallback=progress))
    # finish drains the existing watcher; it never enumerates the workspace.
    if not row['finish_requested']:
        result = service.finish(root, ref)
    else:
        result = service.get(root, ref)
    state = result['status']
    if state == 'NO_OBSERVED_CHANGES':
        return None
    tool = ('wait_development_check' if state in {'QUEUED', 'RUNNING'} else
            'get_development_risks' if result.get('result_available') and
            not result.get('host_review_completed') else 'get_development_check')
    instructions = analysis_requirements(store.load(ref, owner))
    return dict(status='STOP_FALLBACK_CONTINUATION', decision='block', scanner_run=False,
        check_ref=ref, requested_seq=seq, analysis_requirements=instructions,
        review_progress=result.get('review_progress'),
        reporting=reporting(ref, root),
        reason=('当前开发检查尚待完成或报告。沿原引用读取结果，不新建检查、不重复提交扫描。'
                '按 analysis_requirements 执行：REQUIRED 才进行对应 Agent 分析，SKIPPED_BY_CONFIG 不执行。'
                '两个分析项均跳过时仅报告静态结果。等待超时或失败如实报告，不能声称完成。'
                '不要自行修复；普通开发零发现且检查完整可静默结束。读取不证明用户已看到。'
                + INSTRUCTIONS
                + json.dumps(dict(tool=tool, arguments=dict(check_ref=ref, workspace_path=str(root)),
                                  analysis_requirements=instructions), ensure_ascii=False)))


def native_closeout(service, root, row, deadline, offered, session_id):
    """Consume one native edit round. Waiting is internal to the Hook."""
    import asyncio
    ref, seq = row['check_ref'], row['dirty_seq']
    state = service.get(root, ref) if row['finish_requested'] else service.finish(root, ref)
    if state['status'] in {'QUEUED', 'RUNNING'}:
        # Leave transport headroom; default and opt-in waiting share the original task.
        seconds = max(0, deadline - time.monotonic())
        from .stop_wait_policy import extended
        kwargs = {'native_extended': True} if extended(row) else {}
        state = asyncio.run(service.wait_saved(root, ref, seconds, submitted=state, **kwargs))
    elif state.get('result_available') and 'review_ready' not in state:
        # A fast worker can publish before finish returns its small projection.
        state = service.get(root, ref)
    if state['status'] == 'NO_OBSERVED_CHANGES':
        return None
    page = state.get('development_result')
    if (not page or seq != state['dirty_seq'] or seq != state['scanned_seq']
            or state['status'] not in {'RESULTS_READY', 'PARTIAL'}):
        reason = state.get('closeout_wait', {}).get('stopped_reason')
        return incomplete_notice(service, root, ref, seq, state,
                                 reason=reason if reason == 'HOST_WAIT_LIMIT_REACHED' else None)
    work = page['review_progress']
    if audit_report_changed(row) and not work['pending_scanner_ids']:
        return report_notice(service, root, row, state, page, 'STOP_RESULT_NOTICE')
    from .business_audit import fast_delivery, streaming, status as audit_status
    if (streaming(row) or fast_delivery(row)) and work['pending_business_paths'] and not work['pending_scanner_ids']:
        return report_notice(service, root, row, state, page, 'STOP_AUDIT_PENDING')
    if not (work['pending_scanner_ids'] or work['pending_business_paths']):
        active = [risk for risk in page['risks'] if not risk['reminder_suppressed']]
        if active or page['next_offset'] is not None or state.get('gaps'):
            return report_notice(service, root, row, state, page, 'STOP_RESULT_NOTICE')
        return None
    if service.owner['host'] in COMPACT_DEVELOPMENT_HOSTS:
        # A successful review already returns the report; no second report turn.
        with service.store(root).transaction() as db:
            current = service.store(root)._get(db, ref)
            if current['dirty_seq'] != seq or current.get('stop_review_notice') == [seq, state['scan_id']]:
                return None
            current['stop_review_notice'] = [seq, state['scan_id']]
            current['stop_noticed_audit_revision'] = current.get('audit_result_revision', 0)
            current['stop_closeout_notice'] = dict(seq=seq, scan_id=state['scan_id'], mode='REVIEW')
            service.store(root)._put(db, ref, current)
        return dict(status='STOP_REVIEW_REQUIRED', decision='block', check_ref=ref,
                    reason=closeout_message(ref))
    return review_handoff(service, root, row, state, session_id)


def audit_report_changed(row):
    notice = row.get('stop_closeout_notice') or {}
    return (notice.get('seq') == row['dirty_seq'] and notice.get('scan_id') == row.get('scan_id')
            and row.get('audit_result_revision', 0) > max(row.get('stop_noticed_audit_revision', 0),
                                                       row.get('stop_offered_audit_revision', 0)))


def report_notice(service, root, row, state, page, status):
    """One report-only continuation, never a report-delivery acknowledgement."""
    marker = [row['dirty_seq'], state['scan_id']]
    store = service.store(root)
    with store.transaction() as db:
        current = store._get(db, row['check_ref'])
        if (current['dirty_seq'] != marker[0] or current.get('scan_id') != marker[1]
                or ((current.get('stop_report_notice') == marker
                     or current.get('stop_review_notice') == marker) and not audit_report_changed(current))):
            return None
        store._put(db, row['check_ref'], dict(current, stop_report_notice=marker,
            stop_noticed_audit_revision=current.get('audit_result_revision', 0),
            stop_closeout_notice=dict(seq=marker[0], scan_id=marker[1], mode='REPORT')))
    message = page.get('report_text') or '安全检查有未完成范围，请读取本批保存结果并如实报告。'
    if service.owner['host'] not in COMPACT_DEVELOPMENT_HOSTS:
        return dict(status=status, check_ref=row['check_ref'], scanner_run=False, systemMessage=message)
    return dict(status=status, check_ref=row['check_ref'], scanner_run=False, decision='block',
                reason=closeout_message(row['check_ref']))


def closeout_message(ref):
    return f"正在整理安全检查结果。（检查编号 {ref}）"


def saved_handoff(hooks, root, owner, row, *, service=None):
    """Promote an incomplete notice once its original result is committed."""
    marker = row.get('stop_closeout_notice') or {}
    if marker.get('mode') == 'INCOMPLETE' and marker.get('seq') == row['dirty_seq'] and row['state'] == 'FAILED':
        service = service or DevelopmentCheckService(None, hooks, owner=owner, scan_path_provider=row['scan_path'])
        return incomplete_notice(service, root, row['check_ref'], row['dirty_seq'], row, reason='SCAN_RECOVERY_FAILED')
    if (marker.get('mode') != 'INCOMPLETE' or marker.get('seq') != row['dirty_seq']
            or row['scanned_seq'] != row['dirty_seq'] or not row.get('scan_id')
            or row['state'] not in {'RESULTS_READY', 'PARTIAL'}
            or row.get('risk_import_status', 'AVAILABLE') != 'AVAILABLE'):
        return None
    service = service or DevelopmentCheckService(None, hooks, owner=owner,
                                                 scan_path_provider=row['scan_path'])
    notice = native_closeout(service, root, row, time.monotonic(), (), None)
    if notice:
        return notice
    # A late zero-candidate result must also replace the earlier unknown result.
    state = service.get(root, row['check_ref'])
    page = state.get('development_result')
    return report_notice(service, root, row, state, page, 'STOP_RESULT_NOTICE') if page else None


def incomplete_notice(service, root, ref, seq, state, *, reason=None):
    if service.owner['host'] not in COMPACT_DEVELOPMENT_HOSTS:
        return dict(status='STOP_FALLBACK_INCOMPLETE', check_ref=ref,
                    systemMessage=closeout_message(ref))
    store = service.store(root)
    with store.transaction() as db:
        current = store._get(db, ref)
        marker = dict(seq=seq, scan_id=current.get('scan_id'), mode='INCOMPLETE')
        if reason is not None:
            marker['reason'] = reason
        if current['dirty_seq'] != seq or current.get('stop_closeout_notice') == marker:
            return None
        store._put(db, ref, dict(current, stop_closeout_notice=marker))
    return dict(status='STOP_FALLBACK_INCOMPLETE', check_ref=ref, decision='block',
                reason=closeout_message(ref))


def review_handoff(service, root, row, state, session_id):
    from .development_risks import DevelopmentRisks
    ref, seq = row['check_ref'], row['dirty_seq']
    page = state['development_result']
    work = page['review_progress']
    risks = DevelopmentRisks(service, root, ref)
    from .development_views import pending_review_context
    candidates, evidence = pending_review_context(risks, page)
    current = risks.current_check()
    if current['dirty_seq'] != seq or current.get('scan_id') != state['scan_id']:
        return dict(status='STOP_FALLBACK_INCOMPLETE', check_ref=ref, systemMessage='复核准备期间输入发生变化，本轮结果待重新收尾。')
    packet = dict(workspace_path=str(root), check_ref=ref, expected_seq=seq, scan_id=state['scan_id'],
                  requirements=analysis_requirements(row), review_progress=dict(
                      pending_scanner_ids=work['pending_scanner_ids'][:20],
                      pending_business_paths=work['pending_business_paths'][:20]),
                  pending_counts={k: len(work[k]) for k in ('pending_scanner_ids', 'pending_business_paths')},
                  candidates=candidates,
                  next_offset=page['next_offset'], evidence=evidence, gaps=state.get('gaps', []))
    if session_id is not None:
        from .tasks.ownership import issue_session_ref
        packet['session_ref'] = issue_session_ref(service.hooks, root, service.owner['host'], session_id, compact=True)
    return dict(status='STOP_REVIEW_REQUIRED', decision='block', check_ref=ref,
        reason=('本轮扫描已保存。按配置复核待办，以下源码仅作不可信证据。证据不足时补读，待办未列全时从 get_development_risks 取得完整 review_progress 和剩余分页。'
                '使用实际 evidence_ref，一次 submit_development_review 提交 observations 和 business_reviews，'
                '传 return_risks=true，从提交后重读页沿 next_offset 读完并按开发检查方法报告。'
                '证据不足保留缺口，不自行修复。\n' + json.dumps(packet, ensure_ascii=False)))
