"""Command-host delivery adaptation; no model, scan, polling or new scheduler."""
import json


def session_context(token, root):
    request = dict(operation='get_development_risks', arguments=dict(
        workspace_path=str(root), session_ref=token, check_ref='<检查编号>', view='closeout'))
    return ('安全任务会话路由（内部使用）：' + json.dumps(dict(session_ref=token)) +
        '。普通开发由编辑 Hook 记录路径，Stop 自动收尾；无待办无需主动调用安全 MCP，零候选正常静默结束。'
        '收到“正在整理安全检查结果”时，替换下面的检查编号，通过 development_review 读取原批次：' +
        json.dumps(request, ensure_ascii=False) +
        '。按 closeout_mode 分流：REVIEW 才取证和提交复核；REPORT/INCOMPLETE 只交付 report_text 和 session_url。'
        '复用 evidence_refs，缺失证据按 windows 批量补读。复核依据当前源码的可利用路径，检查输入控制、校验和权限；'
        '不能仅凭危险写法、规则命中或假设未来改动确认漏洞，完整防护已阻断路径则 DISMISSED，证据不足则 INCONCLUSIVE。'
        '提交仍用 development_review，operation=submit_development_review；arguments 必须完整沿用读取时的 '
        'workspace_path、session_ref、check_ref，expected_seq=dirty_seq，顶层只传一次 scan_id。'
        'observations 逐项含非空 same_issue_as、decision、rationale、evidence_refs；确认项用 report_content '
        '填写 title、problem、impact、advice、unknowns、function_name（中文具体说明，问题专业解释，影响通俗解释）。'
        'return_risks=true、response_view=final_report。沿 next_action 读完同批分页，'
        '先一句话保留开发结果，再原样附完整 report_text；不得改成摘要、同上或省略漏洞段落。'
        'report_text 末尾已含本批次唯一的风险管理链接；link_in_report 为 true 时不要再用 session_url 追加第二遍。'
        'session_url 只有 link_in_report 为 false 且非空时才作为 Markdown 链接补充展示；'
        '为空时保留报告中的链接不可用说明，不要输出 session_url: null、空链接或自行猜测网址。'
        '同一检查编号可能有新输入或报告版本，每次明确通知都读取，不凭编号相同忽略；只沿 next_action 续页，不轮询。'
        '工作日志等文件编辑应在开发期完成，Stop 交付阶段不要为了记录安全结果再写文件。'
        '未收到交付通知时仅回复开发结果，不把没有通知推断为零候选或扫描完成。不要重新扫描或在 Stop 新开业务审计。'
        '业务审计仅在开发期派发，每轮新建子 Agent，轮内增量复用；子 Agent 用完整 child_call 直接保存。'
        'stream_prepare 只传当前 workspace_path、session_ref、check_ref、action，已记录文件自动纳入，不另传 related_paths；'
        '确需授权额外证据时 related_paths 必须是工作区相对路径。请求参数错误不等于宿主不支持；按返回原因修正一次。'
        '只有实际子任务能力或调用结果证明无法使用所需工具时才报告不支持，不凭工具列表未展开推断；不改为主 Agent 代审。')


def audit_context(core, root, owner, result):
    if (not result.get('development_check_ref') or
            result.get('analysis_requirements', {}).get('audit_business_logic') != 'REQUIRED'):
        return ''
    from .business_audit import offer
    return offer(core.store, root, owner, result['development_check_ref'], prefer_active_executor=True) or ''


def reconnect_context(core, root, owner):
    """Only SessionStart recovers this owner's interrupted task; never edit/Stop."""
    if not getattr(core, 'task_audit_mode', False):
        return ''
    from .development_continuation import context
    return context(core.store, root, owner)
