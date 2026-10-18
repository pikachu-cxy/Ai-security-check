"""One host classification policy; structural checks never certify its reasoning."""

UNKNOWN_CLASSIFICATION_CONTRACT = 'repair-impact-unknowns-v1'
UNKNOWN_CLASSIFICATIONS = frozenset({'BLOCKING_CONTEXT', 'SCOPE_LIMITATION'})

UNKNOWN_CLASSIFICATION_GUIDANCE = '''
未知分级判据（repair-impact-unknowns-v1）：
先固定当前选定方案、用户已经说明的业务规则及必须保留的正常操作，再判断缺失事实是否改变本次实施决定。
BLOCKING_CONTEXT（关键阻断未知，critical=true）必须指出：具体角色与正常操作、已读依据、缺失的必要事实、
该事实的不同答案为何会改变当前方案，以及编辑前最小核对步骤。不能以“未提供全项目代码”代替这条决策依赖。
例如：已读仓储明确向合法读取返回不含权限字段的投影，但拟复用的权限函数要求这些字段；补齐方式尚未确定；
或者本方案要改变身份来源，而新来源及其可信绑定尚不能核实。这些直接决定正常访问或安全目标，仍须阻断。
SCOPE_LIMITATION（仅限制结论范围的未知，critical=false）表示已读依据足以决定当前局部改法，缺失材料只限制
结论能否推广到外部调用、仓储实现、部署或界面。decision_basis 要解释为何不改变本次具体方案；仍保存未知，
不能因此宣称所有数据满足契约、上游身份已经可信、全局兼容或生产安全。
仅未提供仓储、外层身份或拒绝异常的最终呈现，且当前方案不改变这些接口或来源、没有具体冲突证据时，
不得自动升级为关键阻断，也不要求用户再次批准同一修复。若可得代码显示真实冲突，先核对，再按事实分级。
A2 类局部例：用户已明确所有者和 member_ids 成员可读，can_read 已实现该规则，四文件调用链已读；
本次仅在 read_document 返回前复用 can_read，下载继续转交，成功返回结构不变。拒绝其他用户是预期安全限制，
已读路径中所有者和共享成员沿用同一规则；未提供的外部身份绑定、仓储和错误展示保留为范围限制。
不要假设存在旧数据缺字段或特殊服务角色来阻断，也不要假设这些外部情况已经全部排除。
UNDETERMINED 只用于当前方案范围内某项具体正常操作的结果无法判定、且缺失事实会改变实施决定，仍独立阻断。
新提交应为它提供 decision_basis，写明正常路径、缺失事实、决策依赖和最小核对步骤。范围限制只写 unknowns，
不能把同一个一般性外部未知再写成 UNDETERMINED，否则仍会阻断。已确认会损失合法共享权限则是
BUSINESS_BEHAVIOR_CHANGE，保留业务选择门槛，不能写成范围限制。
新能力可用时，unknowns 每项使用 classification 和非空 decision_basis（最多800字符）：
BLOCKING_CONTEXT 必须 critical=true 且至少引用一个本评估实际签发的 evidence_ref；
SCOPE_LIMITATION 必须 critical=false。未读必需代码、版本失效和材料缺失仍通过原覆盖/版本门槛阻断，
没有已读依据时保存 PARTIAL 和具体缺口，不虚构证据。未知分级是宿主分析，Runtime 只校验结构、引用与版本。
旧连接未声明该能力时不发送新字段；旧记录没有新字段时仍沿用原 critical 和 UNDETERMINED 门槛。
历史查询不改写、不降级旧阻断。修正分级须由原归属会话沿同一评估，根据实际证据重新提交，保留原风险、
修改前基线与既有授权；来源或材料过期时沿原恢复流程处理，不新建任务绕过。不能只删掉阻断字段来获得放行。
'''


def valid_unknown_classification(classification, critical, decision_basis, evidence_refs):
    """Validate explicit host labels without guessing a classification from prose.

    Omitted additive fields retain the legacy gate; they never mean nonblocking.
    """
    if classification is None:
        return decision_basis is None
    if not isinstance(classification, str) or classification not in UNKNOWN_CLASSIFICATIONS:
        return False
    if not isinstance(decision_basis, str) or not decision_basis.strip() or len(decision_basis) > 800:
        return False
    blocking = classification == 'BLOCKING_CONTEXT'
    return type(critical) is bool and critical is blocking and (not blocking or bool(evidence_refs))
