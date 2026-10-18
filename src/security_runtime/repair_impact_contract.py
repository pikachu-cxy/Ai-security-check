"""Fixed impact diagnostics shared by local and global MCP routing."""
import re

from pydantic import ValidationError

from .repair_impact_models import COVERAGES, KINDS, SOURCE_KINDS, validate_impact_request
from .repair_impact_policy import UNKNOWN_CLASSIFICATIONS

CONTRACT = 'repair-impact-v1'
IMPACT_TOOLS = frozenset({'prepare_repair_impact', 'read_repair_impact_context',
                          'submit_repair_impact', 'get_repair_impact'})
_FIELDS = frozenset({'source', 'kind', 'task_ref', 'finding_id', 'origin_review_revision',
    'proposal', 'security_goal', 'summary', 'changes', 'preserve', 'file_path', 'start_line',
    'end_line', 'reason', 'assessment_ref', 'impacts', 'unknowns', 'evidence_refs',
    'affected_roles', 'affected_operations', 'affected_modules', 'interfaces', 'alternatives',
    'counterevidence', 'critical', 'classification', 'decision_basis', 'coverage', 'business_choice', 'user_requested',
    'proposal_revision', 'decision', 'workspace_path', 'session_ref', 'offset', 'limit'})
_MAX_FIELD_ERRORS = 6


def _field_path(location):
    """Locations can contain attacker-chosen extra keys; never echo those keys."""
    path = ''
    for item in location[:8]:
        if type(item) is int:
            path += f'[{item}]' if 0 <= item <= 1024 else '[]'
        elif item in SOURCE_KINDS:
            continue
        else:
            path += ('.' if path else '') + (item if item in _FIELDS else '?')
    return path or '$'


def _field_error(error):
    field = _field_path(error.get('loc', ()))
    kind = error.get('type', '')
    code = 'INVALID_VALUE'
    correction = '按工具参数契约修正此字段，再续办同一份分析。'
    if kind == 'missing':
        code, correction = 'REQUIRED', '补齐工具契约要求的字段。'
    elif kind == 'extra_forbidden':
        code, correction = 'UNSUPPORTED_FIELD', '删除工具契约未声明的字段。'
    elif kind.endswith('_type'):
        code, correction = 'WRONG_TYPE', '使用契约声明的 JSON 类型；整数和布尔值不可互换。'
    elif kind in {'greater_than_equal', 'less_than_equal', 'too_long', 'too_short',
                  'string_too_long', 'string_too_short'}:
        code, correction = 'OUT_OF_RANGE', '缩减到工具契约声明的数量或长度范围。'
    result = dict(field=field, code=code, correction=correction)
    leaf = field.rsplit('.', 1)[-1]
    if field in {'source', 'source.kind'}:
        result.update(allowed_values=sorted(SOURCE_KINDS),
            correction='使用声明的来源类型；扫描分组只传 kind/task_ref，原生风险还需 finding_id。')
    elif field.startswith('impacts[') and leaf == 'kind':
        result.update(allowed_values=sorted(KINDS), correction='使用 allowed_values 中的影响类型，不自行缩写或改名。')
    elif field.startswith('unknowns[') and (leaf == 'classification' or kind == 'value_error'):
        result.update(code='CLASSIFICATION_INVALID', allowed_values=sorted(UNKNOWN_CLASSIFICATIONS),
            correction='显式 classification 须附非空 decision_basis；BLOCKING_CONTEXT 配 critical=true 和已签发证据，SCOPE_LIMITATION 配 critical=false。说明缺失事实如何影响当前方案，不为放行删改阻断依据。')
    elif field.startswith('impacts[') and kind == 'value_error':
        result.update(code='DECISION_BASIS_INVALID',
            correction='decision_basis 仅用于 UNDETERMINED，说明具体正常路径、缺失事实、决策依赖及最小核对步骤；范围限制只写 unknowns。')
    elif field == 'coverage':
        result.update(allowed_values=sorted(COVERAGES), correction='已完成必读范围用 REVIEWED；未完成或有缺口用 PARTIAL。')
    elif field == 'business_choice.decision':
        result.update(allowed_values=['ACCEPT_PROPOSED_CHANGE'],
            correction='仅在用户已明确选择此具体业务变化时报告该值；只问影响时省略 business_choice。')
    elif field == 'business_choice.user_requested':
        result.update(allowed_values=[True],
            correction='必须是用户已有明确业务选择的 JSON true；只问影响时省略 business_choice。')
    elif field == 'business_choice.proposal_revision':
        result['correction'] = '原样使用这份分析返回的 proposal_revision；它是 64 位小写十六进制摘要。'
    elif field == 'assessment_ref':
        result['correction'] = '原样使用 prepare_repair_impact 返回的 assessment_ref。'
    elif leaf == 'evidence_refs' or '.evidence_refs[' in field:
        result['correction'] = '使用此分析 read_repair_impact_context 实际返回的 evidence_ref；不要自造引用。'
    elif field == 'limit':
        result.update(bounds=dict(minimum=1, maximum=10),
            correction='每页使用 1 至 10；读取后跟随 page.next_offset。')
    elif field == 'offset':
        result.update(bounds=dict(minimum=0), correction='使用非负整数；后续页原样使用 page.next_offset。')
    elif leaf in {'start_line', 'end_line'} or kind == 'value_error' and (field == '$' or '.changes[' in field):
        result.update(bounds=dict(minimum=1, maximum=2_147_483_647),
            correction='行号使用正整数且 start_line 不大于 end_line；跟随返回的 next_range 读取剩余窗口。')
    return result


def impact_input_failure(tool_name, arguments, *, require_workspace=False):
    """Return bounded contract hints without input, SDK messages or secret keys."""
    errors = []
    try:
        request = validate_impact_request(tool_name, arguments)
        if require_workspace and not request.workspace_path:
            errors.append(dict(field='workspace_path', code='REQUIRED',
                correction='全局入口需要当前项目的绝对 workspace_path。'))
    except ValidationError as exc:
        errors = [_field_error(row) for row in
                  exc.errors(include_input=False, include_context=False, include_url=False)[:_MAX_FIELD_ERRORS]]
    except (KeyError, TypeError, ValueError):
        pass
    result = impact_failure('REPAIR_IMPACT_INPUT_INVALID')
    result.update(field_errors=errors[:_MAX_FIELD_ERRORS],
        correction='按字段提示和工具 schema 修正参数后，继续原分析；不要绕过影响门槛编辑源码。')
    return result


def impact_failure(error='IMPACT_REQUEST_REJECTED'):
    if isinstance(error, ValidationError):
        # This fallback also avoids SDK error strings containing submitted data.
        result = impact_failure('REPAIR_IMPACT_INPUT_INVALID')
        result['field_errors'] = [_field_error(row) for row in
            error.errors(include_input=False, include_context=False, include_url=False)[:_MAX_FIELD_ERRORS]]
        return result
    reason = getattr(error, 'reason_code', None) or str(error)
    if reason in {'TASK_CONNECTION_SCOPE_MISMATCH', 'TASK_SESSION_SCOPE_MISMATCH',
                  'TASK_SESSION_BINDING_REQUIRED', 'TASK_OWNER_UNAVAILABLE'}:
        reason = 'REPAIR_IMPACT_SESSION_BINDING_REQUIRED'
    if not re.fullmatch(r'(?:(?:REPAIR_)?IMPACT|NATIVE_REPAIR)_[A-Z_]{1,80}', reason):
        reason = 'IMPACT_REQUEST_REJECTED'
    if reason in {'REPAIR_IMPACT_INPUT_INVALID', 'IMPACT_INPUT_INVALID'}:
        message = '影响分析参数不符合契约；请按字段提示和工具 schema 修正，继续原分析。'
    elif reason == 'REPAIR_IMPACT_UNKNOWN_CLASSIFICATION_INVALID':
        message = '未知分级与依据不一致；请核对缺失事实对当前具体方案的影响，沿原评估修正。'
    elif reason == 'REPAIR_IMPACT_DECISION_BASIS_INVALID':
        message = '影响的决策依据不符合契约；仅对当前方案中无法判定的具体正常操作使用该字段。'
    elif reason == 'REPAIR_IMPACT_EVIDENCE_INVALID':
        message = '影响分析引用未被接受；仅使用同一分析实际读取返回的 evidence_ref。'
    elif reason in {'NATIVE_REPAIR_ALREADY_BOUND', 'NATIVE_REPAIR_SELECTION_PENDING'}:
        message = '当前选定修复已有待办或原始修复基线；沿原问题和评估继续。明确暂停或切换工作时只取消该工作流，不替换基线。'
    elif reason in {'NATIVE_REPAIR_BASELINE_MISMATCH', 'REPAIR_IMPACT_NATIVE_BASELINE_MISMATCH'}:
        message = '拟修复材料与编辑前基线不一致或未被保留；尚未满足修复准备条件，不能新建基线掩盖已有改动。'
    elif reason == 'REPAIR_IMPACT_NATIVE_FIX_INTENT_REQUIRED':
        message = '只有用户已明确要求修复这一项原生风险时才进入修复准备；只问影响时保留分析和源码。'
    elif any(word in reason for word in ('STALE', 'VERSION', 'REVISION')):
        message = '影响分析所依据的版本已变化或原修订无法核对；旧记录保留，请核对原问题与当前版本。'
    elif any(word in reason for word in ('CAPACITY', 'BUDGET', 'LIMIT')):
        message = '影响分析达到资源边界，已保存材料保留；尚未完成的必要范围不能作为编辑依据。'
    elif any(word in reason for word in ('OWNER', 'WORKSPACE', 'SESSION')):
        message = '当前请求不能续办这份影响分析；原记录保留，请使用对应项目和有效会话。'
    elif any(word in reason for word in ('SOURCE', 'CONTEXT', 'LOCATION')):
        message = '影响分析所需的原问题或关联材料尚不能核对；未执行代码修改，原记录保留。'
    else:
        message = '影响分析请求未被接受，原问题和已保存记录保留；本次没有执行代码修改。'
    result = dict(contract=CONTRACT, status='INCONCLUSIVE', reason_code=reason,
                message=message, scanner_run=False, source_modified=False,
                repair_authorized=False, automatic_execution=False, security_proof=False)
    if reason == 'REPAIR_IMPACT_EVIDENCE_INVALID':
        result['field_errors'] = [dict(field='evidence_refs', code='EVIDENCE_NOT_ISSUED',
            correction='仅引用同一 assessment_ref 实际读取返回的 evidence_ref；不要自造或跨分析引用。')]
    elif reason == 'REPAIR_IMPACT_UNKNOWN_CLASSIFICATION_INVALID':
        result['field_errors'] = [dict(field='unknowns', code='CLASSIFICATION_INVALID',
            allowed_values=sorted(UNKNOWN_CLASSIFICATIONS),
            correction='显式分级须附 decision_basis；BLOCKING_CONTEXT 配 critical=true 和已签发证据，SCOPE_LIMITATION 配 critical=false。旧阻断不自动降级。')]
    elif reason == 'REPAIR_IMPACT_DECISION_BASIS_INVALID':
        result['field_errors'] = [dict(field='impacts', code='DECISION_BASIS_INVALID',
            correction='decision_basis 仅用于 UNDETERMINED；范围限制记录在 unknowns，不据此宣称全局兼容。')]
    elif reason in {'REPAIR_IMPACT_PATH_REJECTED', 'REPAIR_IMPACT_DOCUMENT_REASON_REQUIRED'}:
        result['field_errors'] = [dict(field='file_path', code='PATH_REJECTED',
            correction='使用项目内受支持的源码相对路径；文档需具体关联 reason，不读取密钥或环境配置。')]
    return result
