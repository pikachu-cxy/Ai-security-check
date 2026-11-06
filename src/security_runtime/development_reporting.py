"""Shared reporting instructions, not a receipt that the host reported a result."""


EVIDENCE_RECOVERY = (
    '复核尚未保存，本批没有部分保存。先按 next_action 核对当前版本、候选或补读源码，'
    '使用实际 scan_id、告警 ID 和返回的 evidence_ref 重试同一项复核；'
    '文件路径、行号和扫描发现编号都不能代替证据引用，不得猜编号或删除证据绕过校验。'
    '按要求补读重试后仍失败，就报告具体障碍并结束，不再反复提交。'
    '后续 Stop 续接也不能重新开始同一失败的重试循环；保留未完成记录，不声称复核成功。'
)


INSTRUCTIONS = (
    '若配置要求复核，提交前使用原生 Stop 随包给出的实际 evidence_ref，或用 read_development_risk_context 补读证据。若提交返回可恢复错误：'
    + EVIDENCE_RECOVERY +
    '报告前读取 get_development_risks 的当前风险及处置；若调用 submit_development_review，'
    '提交成功后必须从 offset=0 重新读取，优先传 return_risks=true。post_commit_read=true 即本批保存后重读的第一页，按本批 next_action 续读 next_offset；只有回执则按其 next_action 另读第一页。'
    '沿 next_offset 读取完全部相关分页，再组织最终回复；读取失败如实说明，不能声称报告流程完成。'
    '误报仅统计本批已保存为 DISMISSED 且没有 duplicate_of 的候选，重复命中单列；有误报时只用一句话概述数量。'
    '混合结果只展开仍需提醒的真实风险。仅当本轮全部候选均已判为误报、要求的检查完整且无待提醒风险时，'
    '可以说“本次扫描命中的 N 项均经复核判为误报，无需处理”。'
    '暂缓、用户排除、已修复及证据不足均不计为误报；有缺口须说明。'
    '仅呈现未排除、未暂缓、未解决且需要提醒的风险。'
    '每项风险先写标题、级别和来源（区分 Agent 判断与扫描器原始评级）、文件行链接和已知函数名；'
    '随后分别使用“问题”“可能影响”“建议修复”“尚未确认”四个独立标签，不合并成普通段落。'
    '问题包含依据及已有防护，影响说明触发条件，未知不得编造；标签随用户语言翻译。'
    '按 analysis_requirements 决定是否复核；两项均跳过时只报告静态候选，不能冒充 Agent 确认。'
    '提交保存不代表整体完成；按 review_progress 补齐待复核告警与业务审计路径。'
    '批次顶层传一次 scan_id；已有告警各自提交 same_issue_as、decision、rationale、evidence_refs，原始位置由系统取得。'
    '业务审计使用独立的 business_reviews 字段提交 file_path、rationale、evidence_refs、limitations；'
    '读齐证据后，优先将候选复核和业务审计合并在一次 submit_development_review 中，随后统一读取最终风险；'
    '无需仅为观察中间进度拆分提交和读取。'
    '空 observations 不证明候选或业务审计完成；证据不足保留 INCONCLUSIVE 和实际缺口。'
    '合并说明实际范围、扫描和复核状态及缺口；无待提醒风险且检查完整的普通开发无需风险模板。'
    '对仍需用户决定的风险，在报告末尾统一给一次“修复／暂不处理”选择；已有授权不重复确认，'
    '已暂缓、排除、解决的风险不重复询问。用户未选择不保存处置，不把报告请求当作暂缓决定。'
    '不要自行修复。读取和格式要求都不证明已发送报告或用户已阅读。'
)


def reporting(check_ref, root, *, offset=None, after_review=False):
    result = dict(
        contract='development-reporting-v1', instructions=INSTRUCTIONS,
        required_sections=['problem', 'conditional_impact', 'suggested_fix', 'unknowns'],
        reread_after_review=after_review, host_report_submitted=False,
    )
    if after_review or offset is not None:
        result['next_action'] = dict(tool='get_development_risks', arguments=dict(
            check_ref=check_ref, workspace_path=str(root), offset=0 if after_review else offset))
    return result
