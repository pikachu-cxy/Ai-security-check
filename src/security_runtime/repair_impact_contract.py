"""Fixed impact diagnostics shared by local and global MCP routing."""
import re

CONTRACT = 'repair-impact-v1'
IMPACT_TOOLS = frozenset({'prepare_repair_impact', 'read_repair_impact_context',
                          'submit_repair_impact', 'get_repair_impact'})


def impact_failure(error='IMPACT_REQUEST_REJECTED'):
    reason = getattr(error, 'reason_code', None) or str(error)
    if not re.fullmatch(r'(?:REPAIR_)?IMPACT_[A-Z_]{1,80}', reason):
        reason = 'IMPACT_REQUEST_REJECTED'
    if any(word in reason for word in ('STALE', 'VERSION', 'REVISION')):
        message = '影响分析所依据的版本已变化或原修订无法核对；旧记录保留，请核对原问题与当前版本。'
    elif any(word in reason for word in ('CAPACITY', 'BUDGET', 'LIMIT')):
        message = '影响分析达到资源边界，已保存材料保留；尚未完成的必要范围不能作为编辑依据。'
    elif any(word in reason for word in ('OWNER', 'WORKSPACE', 'SESSION')):
        message = '当前请求不能续办这份影响分析；原记录保留，请使用对应项目和有效会话。'
    elif any(word in reason for word in ('SOURCE', 'CONTEXT', 'LOCATION')):
        message = '影响分析所需的原问题或关联材料尚不能核对；未执行代码修改，原记录保留。'
    else:
        message = '影响分析请求未被接受，原问题和已保存记录保留；本次没有执行代码修改。'
    return dict(contract=CONTRACT, status='INCONCLUSIVE', reason_code=reason,
                message=message, scanner_run=False, source_modified=False,
                repair_authorized=False, automatic_execution=False, security_proof=False)
