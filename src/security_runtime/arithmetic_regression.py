"""Prepare a bounded arithmetic regression command for execution by the host.

The Runtime never imports target modules, invokes Node, or accepts a host's
``tests_passed`` boolean as functional or security verification.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from .hook_state import no_links

VERSION = 'arithmetic-regression-v1'
MAX_MODULE_BYTES = 512_000
SCRIPT = Path(__file__).parent / 'assets' / 'arithmetic_regression.mjs'
CHECKS = (
    'NORMAL_ARITHMETIC_EXPECTED_VALUES',
    'BEFORE_AFTER_OBJECT_IS_EQUIVALENCE',
    'HTTP_JSON_PAYLOAD_EQUIVALENCE',
    'INVALID_INPUT_REJECTION',
    'CONTROLLED_PROCESS_LOCAL_MARKER_BLOCKED',
    'UNSUPPORTED_JAVASCRIPT_REJECTED',
    'EXPRESSION_LENGTH_AND_NESTING_BUDGETS_ENFORCED',
    'MODULE_HASHES_UNCHANGED_DURING_EXECUTION',
)


def _module(path):
    if not isinstance(path, (str, Path)) or not str(path) or any(ord(c) < 32 for c in str(path)):
        raise ValueError('ARITHMETIC_MODULE_PATH_REQUIRED')
    source = Path(path)
    if not source.is_absolute() or source.suffix.lower() != '.ts':
        raise ValueError('ARITHMETIC_ABSOLUTE_TYPESCRIPT_MODULE_REQUIRED')
    no_links(source)
    source = source.resolve(strict=True)
    if not source.is_file() or source.stat().st_size > MAX_MODULE_BYTES:
        raise ValueError('ARITHMETIC_MODULE_BUDGET_EXCEEDED')
    raw = source.read_bytes()
    if len(raw) > MAX_MODULE_BYTES:
        raise ValueError('ARITHMETIC_MODULE_BUDGET_EXCEEDED')
    return {'path': str(source), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def build_arithmetic_regression_plan(before_module=None, after_module=None, *,
        export_name='evaluateExpression', arithmetic_contract_confirmed=False):
    """Return requirements, or a fixed local command after business confirmation.

    Before/after copies belong to the host. Merely preparing this optional plan
    neither executes target code nor changes a remediation receipt.
    """
    if type(arithmetic_contract_confirmed) is not bool:
        raise ValueError('ARITHMETIC_CONTRACT_CONFIRMATION_MUST_BE_BOOLEAN')
    base = {
        'version': VERSION,
        'automatic_execution': False,
        'runtime_executes_target_code': False,
        'checks': list(CHECKS),
        'arithmetic_contract': '十进制数字（含尾点和科学记数）、+ - * / %、括号、一元正负号和空白；保持 Number 与 JSON 数值语义；最多 4096 字符、64 层括号或一元运算。',
        'limitations': [
            '仅在确认该算术契约后适用；其他 JavaScript 语法将不兼容。',
            '固定用例检查函数返回值及 HTTP JSON 载荷形状，未启动 Express，不能证明 HTTP 路由或生产业务正确。',
            '宿主应先审阅两个模块及导入依赖，在可信环境或隔离副本执行。',
            'Node 子进程禁止子进程创建及文件写入；Node 24 权限模型未限制网络，宿主需另行控制网络。',
            '宿主结果仍是宿主执行证据；简单 tests_passed 字段不会被 Runtime 自动采信。',
            '功能用例通过与原安全规则复测独立，不改变风险关闭或发布结论。',
        ],
        'security_verification': 'SEPARATE_ORIGINAL_RULE_RESCAN_REQUIRED',
        'evidence_source': 'HOST_EXECUTION_REQUIRED',
        'production_correctness': 'UNKNOWN',
    }
    if not arithmetic_contract_confirmed:
        return {**base, 'status': 'ARITHMETIC_CONTRACT_CONFIRMATION_REQUIRED',
            'message': '请先确认该入口只需支持正常算术，并由宿主保留修复前模块及修复后模块；确认前不生成或执行命令。'}
    if not isinstance(export_name, str) or not re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]{0,79}', export_name):
        raise ValueError('ARITHMETIC_EXPORT_IDENTIFIER_REQUIRED')
    before, after = _module(before_module), _module(after_module)
    if before['path'] == after['path']:
        raise ValueError('ARITHMETIC_DISTINCT_MODULE_COPIES_REQUIRED')
    worker = SCRIPT.with_name('arithmetic_regression_worker.mjs')
    if not SCRIPT.is_file() or not worker.is_file():
        raise ValueError('ARITHMETIC_HOST_TEMPLATE_UNAVAILABLE')
    return {**base, 'status': 'HOST_ARITHMETIC_REGRESSION_READY',
        'message': '算术范围已确认；由宿主执行固定用例，并核对前后模块哈希和实际结果。',
        'node_major_version': 24, 'export_name': export_name,
        'modules': {'before': before, 'after': after},
        'template_sha256': hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        'worker_sha256': hashlib.sha256(worker.read_bytes()).hexdigest(),
        'command': {'argv': ['node', '--experimental-transform-types', str(SCRIPT.resolve()),
                            before['path'], after['path'], export_name],
                    'shell': False, 'timeout_seconds': 30,
                    'worker_timeout_seconds': 10, 'network_access': 'UNKNOWN'},
        'expected_result': 'ARITHMETIC_REGRESSION_PASSED',
    }
