"""Minimal bound MCP lifecycle observation. Readiness is not a scan result."""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from ._version import __version__
from .codex_integration import CodexIntegrationAdapter, CONTRACT, check_capabilities, fingerprint
from .hook_state import atomic_bytes, identity, no_links
from .integration_lifecycle import IntegrationDiagnostic


def readiness_message(status, reason_code=None):
    """Fixed user copy; lifecycle metadata never becomes a security verdict."""
    if status in {'DEGRADED', 'ERROR'}:
        reasons = {
            'BASELINE_BUSY': '项目初始检查暂时被其他检查占用。保留当前会话和已有任务记录，等待资源释放后继续同一个任务；无需新建聊天。',
            'BASELINE_DEADLINE_EXCEEDED': '项目初始检查超时，项目初始比较点未能保存。请查看检查工具准备状态，保留当前会话和已有任务记录。',
            'BASELINE_FILE_BUDGET_EXCEEDED': '项目文件数量超过项目初始检查上限。任务核查按自己的修改前记录和实际改动范围说明结果。',
            'BASELINE_CONTENT_BUDGET_EXCEEDED': '项目文件大小超过项目初始检查上限。任务核查按自己的修改前记录和实际改动范围说明结果。',
            'BASELINE_SOURCE_CHANGED': '准备期间项目文件发生变化，本次项目初始比较点未能保存。任务检查仍沿用其编辑前记录；不能用修改后的文件补作修改前记录。',
            'BASELINE_COVERAGE_INSUFFICIENT': '项目初始代码检查未完成，项目初始比较点未能保存。请查看检查工具的准备状态，保留已有任务记录。',
            'BASELINE_STATE_PERMISSION_DENIED': '无法读取项目文件或读写本地检查记录。请检查当前账户的访问权限，保留当前会话和已有任务记录。',
            'BASELINE_GIT_SNAPSHOT_UNAVAILABLE': '无法读取项目的版本和文件列表。请确认项目目录可访问，保留当前会话和已有任务记录。',
        }
        detail = reasons.get(reason_code, '项目初始检查准备失败，具体原因未能确定。请查看本地诊断记录，保留当前会话和已有任务记录。')
        return '自动安全检查未启动：' + detail
    messages = {
        'INITIALIZING': '正在准备项目检查。请等待准备完成。',
        'READY': '安全检查工具已连接，项目检查已就绪。',
    }
    return messages.get(status, '自动安全检查未启动：尚未确认工具已连接，请查看产品连接状态。')


def handle_readiness(event, workspace_path, session_id, *, binding, tools, adapter=None):
    result = {'status': 'INCONCLUSIVE', 'host': 'codex', 'readiness': 'NOT_OBSERVED',
              'execution': {'scan': False, 'scanner_run': False, 'model': False, 'source_modified': False,
                            'target_build': False, 'network': False, 'remediation': False}}
    try:
        if any(not isinstance(v, str) or not v.strip() or len(v) > limit or '${' in v
               or any(ord(c) < 32 for c in v) for v, limit in zip((event, workspace_path, session_id), (32, 4096, 500))) or event != 'SessionStart':
            raise IntegrationDiagnostic('INVALID_HOST_CLAIMS')
        if binding is None:
            raise IntegrationDiagnostic('WORKSPACE_BINDING_REQUIRED')
        # Validate lexically before any filesystem access outside the binding.
        root = Path(binding.root)
        if workspace_path.startswith(('\\\\', '//')) or not Path(workspace_path).is_absolute():
            raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
        candidate = Path(os.path.abspath(workspace_path))
        if not candidate.is_relative_to(root):
            raise IntegrationDiagnostic('WORKSPACE_BINDING_MISMATCH')
        no_links(candidate)
        no_links(root)
        from .guidance.host_guidance import runtime_info
        info = runtime_info()
        check_capabilities(info, tools)
        manager = adapter or CodexIntegrationAdapter()
        manager._state_path(root, 'readiness.json')
        with manager.store.lock(root, wait_seconds=2) as acquired:
            if not acquired:
                raise IntegrationDiagnostic('INTEGRATION_BUSY')
            manifest = manager._manifest(root)
            desired = manager._desired(root)
            diagnostics, _, _ = manager._inspection(root, manager._config(root), manifest, desired)
            if diagnostics or manifest is None or manifest['phase'] != 'COMMITTED' or manifest['records'] != [desired[-1]]:
                raise IntegrationDiagnostic('INTEGRATION_NOT_CONFIGURED')
            value = {'host': 'codex', 'workspace_hash': identity(os.path.normcase(str(root))),
                     'session_hash': identity(session_id), 'runtime_version': __version__,
                     'capability_contract': CONTRACT, 'config_hash': fingerprint(desired[-1])}
            path = manager._state_path(root, 'readiness.json')
            import json
            try:
                raw = manager._read(path, 4096)
            except IntegrationDiagnostic:
                raw = b''  # bounded owned metadata slot; never read excess bytes
            try:
                previous = json.loads(raw) if raw else {}
            except (ValueError, UnicodeError):
                previous = {}
            # Idempotent within a session while the authenticated observation is fresh.
            valid_previous = manager.readiness_status(root, desired[-1], manifest)['status'] == 'READINESS_OBSERVED'
            if not valid_previous or any(previous.get(k) != v for k, v in value.items()):
                value['observed_at'] = manager.now()
                key = manager.store.key(root)
                value['signature'] = hmac.new(key, manager._encode(value), hashlib.sha256).hexdigest()
                content = manager._encode(value)
                if len(content) > 4096:
                    raise IntegrationDiagnostic('READINESS_BUDGET_EXCEEDED')
                atomic_bytes(path, content)
            result.update(status='READY', readiness='READINESS_OBSERVED', runtime_version=__version__, capability_contract=CONTRACT)
    except IntegrationDiagnostic as exc:
        result['diagnostic'] = exc.code
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        result['diagnostic'] = 'READINESS_INCONCLUSIVE'
    message = readiness_message(result['status'])
    result.update(systemMessage=message, hookSpecificOutput={'hookEventName': 'SessionStart', 'additionalContext': message})
    return result
