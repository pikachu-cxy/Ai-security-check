"""Native Stop fallback for the explicitly focused observed-edit check only."""
from __future__ import annotations

import json
import hashlib

from .development_check import DevelopmentCheckService, DevelopmentCheckStore, owner_key, legacy_guard
from .user_config import analysis_requirements, batch_config
from .development_reporting import INSTRUCTIONS, reporting


def fallback(hooks, root, owner, *, stopped_normally=True, stop_hook_active=False,
             service=None, offered=(), turn_id=None):
    if not stopped_normally or owner.get('host') not in {'codex', 'cursor', 'workbuddy'}:
        return None
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return None
    focus = store.read('focus:' + owner_key(owner))
    if not focus:
        return None
    row = store.load(focus['check_ref'], owner)
    activity = row.get('stop_activity', {})
    turn = hashlib.sha256(turn_id.encode()).hexdigest() if turn_id else None
    if activity.get('turn') is not None and activity['turn'] != turn:
        return None
    if not activity.get('pending') and not (stop_hook_active and row.get('stop_fallback')):
        return None
    # Consume this round's eligibility even when Stop is disabled or already done.
    if activity.get('pending'):
        with store.transaction() as db:
            current = store._get(db, row['check_ref'])
            if current.get('stop_activity') != activity:
                return None
            store._put(db, row['check_ref'], dict(current,
                stop_activity=dict(activity, pending=False)))
    # Do not turn old abandoned records into new work on a later read-only chat.
    if not row.get('effective_config'):
        return None
    options = batch_config(row)['development']['stop_fallback']
    if not options['enabled'] or legacy_guard(hooks, root, owner) is not None:
        return None
    from .development_file_watch import stop_window
    stop_window(store, row['check_ref'], owner)
    row = store.load(row['check_ref'], owner)
    if not stop_hook_active and row['dirty_seq'] <= activity.get('base_seq', row['dirty_seq']):
        return None
    if not row['dirty_seq']:
        return None
    ref, seq = row['check_ref'], row['dirty_seq']
    service = service or DevelopmentCheckService(None, hooks, owner=owner,
                                                 scan_path_provider=row['scan_path'])
    saved = service.get(root, ref)
    if (saved['status'] == 'RESULTS_READY' and row['scanned_seq'] == seq and not saved['gaps']
            and (saved.get('host_review_completed') or not any(batch_config(row)['agent'].values()))):
        return None
    with store.transaction() as db:
        current = store._get(db, ref)
        if current['dirty_seq'] != seq:
            return None
        progress = current.get('stop_fallback')
        # New edits during continuation do not reset the overall budget.
        if progress is None or (progress.get('seq') != seq and not stop_hook_active):
            if stop_hook_active:
                return None
            progress = dict(seq=seq, count=0, deadline=store.now()+options['wait_timeout_seconds'])
        if progress['count'] >= options['max_continuations'] or progress['deadline'] <= store.now():
            store._put(db, ref, dict(current, stop_fallback=dict(progress,
                incomplete_reason='STOP_FALLBACK_BUDGET_EXHAUSTED')))
            return dict(status='STOP_FALLBACK_INCOMPLETE', scanner_run=False,
                        review_progress=saved.get('review_progress'),
                        reason_code='STOP_FALLBACK_BUDGET_EXHAUSTED',
                        systemMessage='安全检查或结果报告尚未确认完成；已提交的检查和结果已保留。')
        progress = dict(progress, seq=seq, count=progress['count']+1)
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
