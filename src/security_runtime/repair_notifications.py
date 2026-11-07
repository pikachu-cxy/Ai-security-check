"""Deliver Web repair selections only to their original, verified host owner."""
import time
import json
from .tasks.durable import SignedRecords


def enqueue(hooks, root, row, risk_id):
    job = row['risks'][risk_id].get('management', {}).get('repair_request')
    if not job:
        return
    store = SignedRecords(hooks, root, 'repair-notifications.db')
    with store.transaction() as db:
        if not store._get(db, job['id']):
            store._put(db, job['id'], dict(owner=row['owner'], target_host=job['target_host'],
                check_ref=row['key'], risk_id=risk_id, last_offered_at=0))


def offer(hooks, root, owner):
    store = SignedRecords(hooks, root, 'repair-notifications.db')
    if not store.path.exists():
        return None
    from .development_check import DevelopmentCheckStore
    checks = DevelopmentCheckStore(hooks, root)
    messages = []
    with store.transaction() as db:
        for notice in store._all(db):
            if notice['owner'] != owner or notice['target_host'] != owner['host']:
                continue
            check = checks.read(notice['check_ref'])
            risk = (check or {}).get('security_result', {}).get('risks', {}).get(notice['risk_id'], {})
            job = risk.get('management', {}).get('repair_request', {})
            if job.get('id') != notice['key'] or job.get('status') != 'AWAITING_HOST':
                db.execute('DELETE FROM records WHERE key=?', (notice['key'],))
                continue
            if time.time()-notice['last_offered_at'] < 300:
                continue
            notice['last_offered_at'] = time.time()
            store._put(db, notice['key'], notice)
            finding = risk['finding']
            start = max(1, finding['line_start'] - 5)
            window = dict(file_path=finding['file_path'], start_line=start,
                          end_line=min(start + 79, finding['line_end'] + 5))
            action = dict(operation='read_development_risk_context', arguments=dict(
                workspace_path=str(root), check_ref=notice['check_ref'], **window))
            messages.append('用户已在本机风险页选择修复：check_ref='+notice['check_ref']+
                '，risk_id='+notice['risk_id']+'。任务绑定当前原项目和原会话，网页只授权此风险。'
                '使用当前 session_ref，通过 development_review 先调用 '+json.dumps(action, ensure_ascii=False)+
                '；必要时沿用 workspace_path/session_ref/check_ref 调用 get_development_risks(view="full") 核对原风险，'
                'final_report 仅是提交回执视图，不是读取视图。'
                '准备接口 prepare_development_risk_fix 沿用 workspace_path/session_ref/check_ref/risk_id，'
                '必填 proposal、preserve（字符串数组）、impact_summary、critical_unknowns（无关键未知才为空数组）、'
                'repair_paths（已取证路径数组）、evidence_refs、user_requested=true。'
                '准备成功才修改；只改允许路径并验证，再以 start_line/end_line 读取修后证据。'
                'submit_development_risk_resolution 沿用上述身份及 prepare 返回的 repair_ref，'
                '必填 outcome（CODE_REVIEWED_RESOLVED/STILL_PRESENT/INCONCLUSIVE）、rationale、修后 evidence_refs。'
                '代码复查不等于扫描验证。版本或影响不符时保留待处理；无需再次查全量工具及宽泛指导。')
            if len(messages) == 3:
                break
    return '\n'.join(messages) or None
