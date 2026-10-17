"""Canonical host interaction policy, independent of evidence and persistence.

The host performs bounded code assessment; Runtime never invokes its model.
User handling choices control reminders, not technical truth or repair authority.
"""

RISK_DECISION_CONTRACT = 'risk-decisions-v2'
PRIMARY_CHOICES = ['修复', '稍后处理']
SECONDARY_CHOICES = ['请复核', '不再提醒此项']
HANDLING_UNAVAILABLE_MESSAGE = ('风险处置记录暂时无法读取，原告警和处理记录保留；'
                               '本次不重复要求选择，尚未确认风险已消除。')

RISK_DECISION_GUIDANCE = '''风险交互与用户处置（risk-decisions-v2）：
产品承担调查工作，用户决定是否处理。技术评估、用户处置、提醒状态和修复证明分别保存。
普通开发检查或授权扫描中，先由当前宿主 Agent 在原范围与预算内读取代码、防护和反证并复核，
再给出建议；Runtime 不自调模型，不凭原始规则命中认定真实漏洞。用户明确只要原始扫描或只记录意见时遵从。
扫描器候选通过 prepare_finding_feedback/submit_finding_feedback 完成有证据的复核；
任务代码复核发现沿用已完成的任务评估，不重复分析同版本材料；需要重新核查原风险时使用对应任务反馈工具。
充分且当前的具体反证可以登记 AI 复核认为不成立，保留来源与依据；证据不足保持尚待确认。
不能因模型自报高置信度、测试目录、内部部署或用户坚持直接判定安全。只有确有业务事实缺口时，
问一项会改变建议的具体事实，不要求用户证明漏洞真假，也不循环索取安全分析。
默认主要选择是“修复／稍后处理”，给出具体改法和已知行为影响后才能取得对应修复授权。
“稍后处理”（兼容“暂不处理”和原明确暂缓语义的“忽略”）以 DEFER 保存；风险仍保留，本次不再追问。
用户明确说“这是误报”“标为误报”“不再提醒这一项”是处置决定：对选定扫描器告警调用
set_finding_disposition(disposition="EXCLUDE", user_requested=true)，对任务代码复核风险调用
set_task_risk_disposition；不需要 Agent 同意，不强制补写理由，不授予修改代码或关闭原风险的权限。
“是不是误报／可能误报／请复核”只请求复核，不自动排除；用户明确只记录意见时才使用旧 mark 工具。
多个问题未选定时只澄清具体哪一项；不得扩大成全项目、全规则或整类忽略。沉默和“先不要修复”不代表排除。
人工排除后，即使 AI 仍认为存在风险，也只说明一次“已按你的决定停止重复提醒，AI 判断保留在详情”。
保存成功后才说已记住；保存失败保留本轮用户决定并如实说明未持久保存，不要求用户重新作安全判断。
用户要求恢复提醒时以 RESTORE 保存，允许撤销人工排除或 AI 自动排除，历史保留。
相同问题和相同依据跨扫描、跨聊天沿用决定；行号移动、注释或无关代码变化不直接恢复提醒。
相关入口、防护或依赖等有实质变化时先自动复核，有新的风险依据才恢复提醒并说明变化。
读取失败、模型换意见或版本号变化本身不推翻用户决定；缺材料保留待复核，不冒充新风险。
用户侧使用“待处理／已暂缓／已排除／已修复”，已排除注明 AI 复核或用户决定；不用“折叠”要求用户理解内部机制。
原始命中、待处理、暂缓、排除与复查结果分别统计，人工排除不得算 AI 确认误报、已修复或经验证安全。
'''


def handling_counts(feedback):
    """Count independent handling buckets without changing raw scan records."""
    counts = dict(pending=0, deferred=0, excluded_by_user=0, excluded_by_agent=0, resolved=0)
    for item in feedback.values():
        disposition = item.get('disposition') or {}
        action = disposition.get('disposition') if isinstance(disposition, dict) else disposition
        active = disposition.get('active', True) if isinstance(disposition, dict) else True
        suppressed = item.get('reminder_suppressed', item.get('folded', False))
        if item.get('handling_status') in {'RESOLVED', 'FIXED'}:
            counts['resolved'] += 1
        elif suppressed and active and action == 'DEFER':
            counts['deferred'] += 1
        elif suppressed and active and action == 'EXCLUDE':
            counts['excluded_by_user'] += 1
        elif suppressed:
            counts['excluded_by_agent'] += 1
        else:
            counts['pending'] += 1
    return counts
