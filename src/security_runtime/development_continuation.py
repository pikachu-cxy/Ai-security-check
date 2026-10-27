"""Bounded owner-bound delivery hints; no scan or authenticated display claim."""
from __future__ import annotations

import json
import hashlib

from .development_check import DevelopmentCheckStore, root_identity, owner_key
from .development_delivery import pending

MAX_CONTINUATIONS = 2
CONTINUATION_SECONDS = 120


def notice_key(delivery):
    signature = (dict(status=delivery['status'], reason=delivery.get('reason_code'),
                      diagnostic=delivery.get('failure_diagnostic'))
                 if delivery['status'] == 'FAILED' else dict(version=delivery['result_version']))
    return 'notice:' + delivery['check_ref'] + ':' + hashlib.sha256(
        json.dumps(signature, sort_keys=True).encode()).hexdigest()


def candidates(store, owner, offered=()):
    identity = root_identity(store.root)
    rows = store.rows()
    ready = [(r['check_ref'], r['scanned_seq'], 'get_development_result')
             for r in pending(store, owner, rows=rows) if (r['check_ref'], r['scanned_seq']) not in offered
             and not store.read(notice_key(r))]
    queued = [(r['check_ref'], r['dirty_seq'], 'wait_development_check') for r in rows
              if r.get('kind') == 'check' and r.get('owner') == owner
              and r.get('root_identity') == identity and r.get('finish_requested')
              and r['state'] in {'QUEUED', 'RUNNING'}]
    return list(dict.fromkeys([*ready, *queued]))


def context(hooks, root, owner):
    # Saved results remain explicitly readable. Opening a chat must not inject
    # historical check instructions into an unrelated conversation.
    return ''


def pending_context(hooks, root, owner):
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return ''
    items = candidates(store, owner)
    if not items:
        return ''
    return ('本会话有已提交检查或保存结果尚待交付。使用当前会话凭据读取 '
            'get_development_deliveries；未完成的原检查继续 wait_development_check，'
            '不重发收尾、不新建检查。先分析原版本的风险和覆盖缺口再向用户报告；'
            '返回给模型不证明用户已看到，不能自行确认交付。原引用：'
            + json.dumps([r[0] for r in items[:10]], ensure_ascii=True))


def stop(hooks, root, owner, *, stop_hook_active=False, offered=(), turn_id=None,
         allow_continuation=False):
    # Ordinary development delivers via complete/get, not a forced extra turn.
    # Only a trusted host with an active task can opt into continuation.
    if not allow_continuation:
        return None
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return None
    items = candidates(store, owner, offered)
    if not items:
        return None
    ref, seq, tool = items[0]
    # A persistent budget per original generation, not per model/tool request.
    budget_key = f'continuation:{ref}:{seq}'
    window_key = ('continuation-window:' + owner_key(owner) + ':'
                  + hashlib.sha256(str(turn_id or ref).encode()).hexdigest())
    with store.transaction() as db:
        from .development_delivery import key
        delivery = store._get(db, key(ref, seq))
        reminder_key = None
        if delivery:
            reminder_key = notice_key(delivery)
            if store._get(db, reminder_key):
                return None
        budget = store._get(db, budget_key)
        window = store._get(db, window_key)
        if budget is None:
            if stop_hook_active:
                return None  # Do not join another guard's continuation loop.
            budget = dict(kind='continuation', check_ref=ref, owner=owner,
                          count=0, expires_at=store.now()+CONTINUATION_SECONDS)
        if budget['owner'] != owner or budget['count'] >= MAX_CONTINUATIONS or budget['expires_at'] <= store.now():
            return None
        window = window or dict(kind='continuation', check_ref=ref, owner=owner,
                                count=0, expires_at=store.now()+CONTINUATION_SECONDS)
        if window['count'] >= MAX_CONTINUATIONS or window['expires_at'] <= store.now():
            return None
        store._put(db, budget_key, dict(budget, count=budget['count']+1))
        store._put(db, window_key, dict(window, count=window['count']+1))
        if reminder_key:
            store._put(db, reminder_key, dict(kind='continuation', check_ref=ref,
                owner=owner, reminder_offered=True))
    arguments = dict(check_ref=ref, workspace_path=str(store.root))
    if tool == 'get_development_result':
        arguments['scanned_seq'] = seq
    return dict(status='DEVELOPMENT_DELIVERY_CONTINUATION', decision='block', scanner_run=False,
        baseline_created=False, repair_authorized=False,
        reason=('本会话已提交检查的结果尚待读取分析。沿当前会话凭据和以下原引用继续，'
                '不要重新提交扫描。结果可读后分析风险及覆盖缺口并向用户报告；'
                '仍未完成则如实说明阶段，不声称无风险。' + json.dumps(dict(tool=tool, arguments=arguments))))
