"""Host-scheduled, version-bound read-only audit handoffs during development.

The Runtime never launches an independent model. Only the actual host can
dispatch its subagent, and must acknowledge that dispatch or report unsupported.
"""
import time
import secrets
from .user_config import batch_config
from .development_risks import require


def status(check):
    job = dict(check.get('parallel_audit') or {})
    if not batch_config(check)['agent']['audit_business_logic']:
        return dict(status='DISABLED')
    if check.get('audit_delegate'):
        from .incremental_audit import progress
        grant = check.get('audit_delegate') or {}
        result = progress(check)
        if grant.get('round_id') != result.get('round_id'):
            if result['pending_paths']:
                result['status'] = 'READY'
        elif grant.get('revoked'):
            result['status'] = 'CANCELLED'
        elif grant.get('failure') and result['pending_paths']:
            result.update(status='FAILED', reason_code=grant['failure'])
        elif result['pending_paths'] and not grant.get('agent_ref'):
            result['status'] = 'READY'
        return dict(result, streaming=True)
    if not job:
        return dict(status='NOT_STARTED', pending_paths=check['observed_paths'])
    if job['dirty_seq'] != check['dirty_seq']:
        job['status'] = 'NEEDS_REVIEW'
    elif job['status'] in {'READY', 'RUNNING'} and job['lease_until'] < time.time():
        job['status'] = 'INTERRUPTED'
    return job


def fast_delivery(check):
    config = batch_config(check)
    return (config['agent']['audit_business_logic'] and
            not streaming(check) and
            config['development']['business_audit_delivery'] == 'fast')


def streaming(check):
    """Legacy explicitly prepared jobs retain their original delivery contract."""
    return bool(check.get('audit_stream') and
                (check.get('audit_delegate') or not check.get('parallel_audit')))


def continuation(check):
    if not streaming(check) or not batch_config(check)['agent']['audit_business_logic']:
        return None
    from .incremental_audit import progress
    state = progress(check)
    if not state['pending_paths']:
        return None
    grant = check.get('audit_delegate') or {}
    bound = (bool(grant.get('agent_ref')) and not grant.get('revoked') and not grant.get('closed')
             and grant.get('round_id') == state.get('round_id'))
    return dict(contract='incremental-business-audit-v1', **state,
        agent_ref=grant.get('agent_ref') if bound else None,
        executor_failure=grant.get('failure') if bound else None,
        next_action=None if bound else dict(tool='manage_development_audit', arguments=dict(
            workspace_path=check['workspace'], check_ref=check['check_ref'], action='stream_prepare')),
        instructions='继续开发期已登记的审计任务，不启动新的扫描或另建审计。'
        '主 Agent 只在本轮按 agent_ref 续接原子 Agent，无需先调用 stream_status；尚未派发则为本轮创建新子 Agent。'
        '子 Agent 通过 process_development_audit 直接领取和保存，主 Agent 不转交结果。'
        '若执行者不可恢复，明确保留中断状态；重新授权须撤销原凭据后 stream_rotate。'
        '不要在 Hook 中等待模型或循环查状态；保存后读取同批最终报告。')


def revalidate(risks, check, row):
    """Recheck only the audit's actual evidence when publishing a new scan."""
    if check.get('audit_stream'):
        from .audit_stream_service import revalidate as revalidate_stream
        revalidate_stream(risks, check, row)
    job = check.get('parallel_audit') or {}
    if job.get('status') not in {'COMPLETE', 'PARTIAL'} or job.get('dirty_seq') != check['dirty_seq']:
        return
    refs = {ref for review in row['reviews'] if review.get('audit_id') == job['audit_id']
            for item in review.get('business_reviews', []) for ref in item['evidence_refs']}
    refs.update(ref for risk in row['risks'].values() for assessment in risk.get('assessments', [])
                if assessment.get('audit_id') == job['audit_id'] for ref in assessment.get('evidence_refs', []))
    try:
        for ref in refs:
            risks.evidence(row, [ref])
    except (ValueError, OSError):
        check['parallel_audit'] = dict(job, status='NEEDS_REVIEW', reason_code='AUDIT_EVIDENCE_CHANGED')


def operate(risks, action, audit_id=None, agent_ref=None):
    check = risks.current_check()
    require(batch_config(check)['agent']['audit_business_logic'], 'BUSINESS_AUDIT_DISABLED')
    if action == 'status':
        return status(check)
    if action == 'prepare':
        existing = status(check)
        if existing['status'] in {'READY', 'RUNNING', 'COMPLETE', 'PARTIAL'}:
            return existing
        paths = list(check['observed_paths'])
        require(bool(paths), 'BUSINESS_AUDIT_NO_OBSERVED_PATHS')
        # One in-flight task per check; bounded initial evidence with explicit continuation.
        contexts, errors = [], []
        for name in paths[:8]:
            try:
                contexts.append(risks.read(name, 1, 80))
            except (ValueError, OSError):
                errors.append(name)
        with risks.checks.transaction() as db:
            row = risks.checks._get(db, risks.ref)
            require(row['dirty_seq'] == check['dirty_seq'], 'BUSINESS_AUDIT_VERSION_STALE')
            latest = status(row)
            if latest['status'] in {'READY', 'RUNNING', 'COMPLETE', 'PARTIAL'}:
                return latest
            job = dict(audit_id='audit-'+secrets.token_hex(16), status='READY',
                dirty_seq=row['dirty_seq'], paths=paths, config_revision=row.get('effective_config', {}).get('revision'),
                created_at=time.time(), lease_until=time.time()+300,
                evidence_refs=[v['evidence_ref'] for v in contexts], unread_paths=errors+paths[8:])
            from .audit_leases import reserve
            reserve(risks.root, risks.development.owner, job['audit_id'])
            row['parallel_audit'] = job
            risks.checks._put(db, risks.ref, row)
        from .dashboard_service import session_url
        return dict(job, session_url=session_url(str(risks.root), check['owner']), evidence=contexts, instructions=(
            '由当前宿主创建一个只读 subagent 并行审计本任务业务逻辑；主开发继续。'
            'started 仅沿用 workspace_path/session_ref/check_ref，另传 action、audit_id、实际 agent_ref，不传 expected_seq 或 scan_id；版本已绑定 audit_id。'
            '将本次固定 dirty_seq、证据和需求交给子 Agent。补读使用原检查的 read_development_risk_context，'
            '开发期只用 prepare 证据和补读接口，扫描尚未发布时不要请求 view=review。'
            '补读不传 expected_seq 或 scan_id；行号参数为 start_line/end_line（不是 line_start/line_end），路径外依赖标 related=true。'
            'business_reviews 用 coverage=COMPLETE/PARTIAL 标记覆盖，PARTIAL 必须在 uncovered 列出具体未审范围，背景说明放 limitations。子 Agent 不编辑、不扫描、不提交；'
            '完成后由主 Agent 以本次 dirty_seq 和 audit_id 调用 submit_development_review，保留完整报告和 business_reviews。'
            '确认项优先传 report_content 的中文 title/problem/impact/advice 及具体 unknowns/function_name，由产品固定排版；旧 report_text 兼容保留。'
            '保存回执若为 WAITING_FOR_STATIC_SCAN，先只交付开发结果和验证，说明安全报告待收尾，不提前展开漏洞；正常结束触发 Stop 后统一报告，不主动扫描或轮询。'
            '新编辑使输入失效时取消旧子 Agent，重新 prepare；旧版本不能保存。'
            '参数失败只修报错字段，保留 observations、证据和报告，不以空发现替代；修正后重试一次。同错再次失败用 failed 结束原审计并释放租约，完整说明已发现但未保存的漏洞，附 session_url；不得声称已入库。实际创建成功后用 started 回传真实 agent_ref。没有子 Agent 能力时用 unsupported，不可声称已派发。'))
    require(action in {'started','cancel','unsupported','failed'}, 'BUSINESS_AUDIT_ACTION_INVALID')
    with risks.checks.transaction() as db:
        row = risks.checks._get(db, risks.ref)
        job = row.get('parallel_audit')
        require(job and job['audit_id'] == audit_id, 'BUSINESS_AUDIT_ID_MISMATCH')
        if action == 'started':
            require(job['dirty_seq'] == row['dirty_seq'] and job['lease_until'] >= time.time(), 'BUSINESS_AUDIT_VERSION_STALE')
            require(isinstance(agent_ref, str) and 1 <= len(agent_ref) <= 200, 'BUSINESS_AUDIT_AGENT_REQUIRED')
            require(job['status'] in {'READY', 'RUNNING'}, 'BUSINESS_AUDIT_STATE_INVALID')
            require(not job.get('agent_ref') or job['agent_ref'] == agent_ref, 'BUSINESS_AUDIT_ALREADY_CLAIMED')
            job.update(status='RUNNING', agent_ref=agent_ref, started_at=job.get('started_at', time.time()))
        else:
            if action == 'failed':
                job['reason_code'] = 'HOST_AUDIT_FAILED'
            job.update(status={'cancel':'CANCELLED','unsupported':'UNSUPPORTED','failed':'FAILED'}[action], ended_at=time.time())
            from .audit_leases import release
            release(audit_id)
        risks.checks._put(db, risks.ref, row)
    return job


def offer(hooks, root, owner, ref):
    from .development_check import DevelopmentCheckStore
    store = DevelopmentCheckStore(hooks, root)
    with store.transaction() as db:
        check = store._get(db, ref)
        if (not check or check['owner'] != owner or not batch_config(check)['agent']['audit_business_logic']
                or not check['observed_paths'] or check.get('audit_offered_seq') == check['dirty_seq']
                or time.time()-check.get('audit_offered_at', 0) < 15):
            return None
        check.update(audit_offered_seq=check['dirty_seq'], audit_offered_at=time.time())
        store._put(db, ref, check)
    return ('已启用持续增量业务审计：首批修改后通过 development_review 的 manage_development_audit '
            'action=stream_prepare 准备原任务，check_ref='+ref+'，沿用当前 workspace_path 和 session_ref，不必先查状态。'
            '每轮开发收到 registration 后立即新建只读子 Agent（名称附 round_id 后缀，先等待完整交接包），主开发继续；'
            '将 registration 加真实 agent_ref 和父会话 session_ref 调用 stream_started。'
            '把返回的完整 child_call 原样交给子 Agent，不转交父会话凭据。'
            '子 Agent 直接执行 child_call 领取证据，再直接保存；提交同时取得下一批待审修改。'
            '主开发继续，新修改合并入队，不取消整个任务。本轮内复用原子 Agent；下一轮新建，不跨轮续接。'
            '主 Agent 不转抄结果；收到子 Agent 完成消息后核对保存回执。Stop 只封口，不在 Hook 内等待模型。'
            '宿主不能派发时明确保留待办，不能把这条提示当成已经启动审计。')
