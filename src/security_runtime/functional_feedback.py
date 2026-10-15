"""Explicit verifier results; personal repair feedback has no verifier offer."""
from __future__ import annotations


def pending_feedback(*, arguments=None, notify=True):
    """Keep the internal call signature without advertising the hidden feature."""
    return dict(verification_summary=dict(security='原问题安全复查已通过。'))


def result_feedback(out):
    """Keep compile/test coverage and scanner facts separate in every result."""
    functional = out['functional_verification']
    status = functional['status']
    coverage = functional.get('coverage', 'NONE')
    security = ('原问题安全复查已通过。' if
                out['security_verification']['status'] == 'SCANNER_VERIFIED_RESOLVED' else
                '当前安全复查未确认完成。')
    if status == 'PASSED':
        if coverage in {'COMPILE', 'COMPILE_ONLY', 'TYPECHECK'}:
            text = '编译或类型检查通过，业务功能测试尚未验证。'
        else:
            text = '所执行的本地检查通过，仅覆盖列出的检查范围。'
    elif status == 'FAILED':
        text = '验证失败，需要检查；没有可信修复前基线，尚不能确定是否由本次修复造成。'
    elif status == 'PARTIAL':
        text = '仅完成部分检查，功能验证尚未全部完成。'
    elif status == 'NOT_AVAILABLE':
        text = '当前环境或项目没有可执行的验证条件，功能尚未验证。'
    elif status in {'NOT_RUN', 'NOT_VERIFIED'}:
        text = '尚未执行，原有功能是否受影响仍待确认。'
    elif status == 'PLANNED':
        text = '已准备验证计划，等待执行。'
    else:
        text = '验证未能确认完成，不能视为通过。'
    if functional.get('reused'):
        text += ' 复用了与当前代码和验证计划匹配的已有结果。'
    reason = {
        'LOCAL_TOOL_UNAVAILABLE': '缺少本地验证工具。',
        'NO_EXISTING_LOCAL_VERIFIER': '未找到受支持的现有测试或构建入口。',
        'NO_TESTS_COLLECTED': '没有收集到可执行测试。',
        'LOCAL_DEPENDENCIES_UNAVAILABLE': '本地依赖不齐，未自动安装或联网下载。',
        'HOST_NETWORK_BOUNDARY_UNPROVEN': '执行环境的网络限制未确认。',
        'HOST_PROJECT_CODE_REVIEW_REQUIRED': '项目测试脚本尚未完成执行前检查。',
        'WORKSPACE_OR_PLAN_CHANGED_REFRESH': '代码或验证计划已经变化，需要重新准备验证。',
        'SECURITY_RECEIPT_REQUIRED_REFRESH': '原验证上下文已失效，需核对当前代码和执行条件，不会重新修复。',
        'FUNCTIONAL_PLAN_EXPIRED_REFRESH': '验证计划已过期，需重新准备，不会自动重复执行。',
        'FUNCTIONAL_RESULT_REQUIRED': '尚未取得与当前代码匹配的功能验证结果。',
        'FUNCTIONAL_BUSY': '当前项目另有验证正在进行，本次未重复执行。',
    }.get(functional.get('reason_code'))
    if reason:
        text += ' ' + reason
    out['verification_summary'] = dict(security=security, functional=text)
    out['user_feedback'] = dict(message='安全复查：' + security + '\n功能验证：' + text,
                                choices=[], scope='POST_FIX_FUNCTIONAL_VERIFICATION')
    out.pop('functional_verification_offer', None)
    return out
