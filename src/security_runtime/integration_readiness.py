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


def readiness_message(status):
    """Fixed user copy; lifecycle metadata never becomes a security verdict."""
    messages = {
        'INITIALIZING': '正在准备安全检查，结果尚未就绪。完成前，暂时无法确认本次改动是否安全。',
        'READY': '安全检查工具已连接。连接成功不代表项目已经通过安全检查。',
        'DEGRADED': '安全检查暂时无法完整开展，当前结果不能证明改动安全。建议先检查工具连接和配置。',
        'ERROR': '安全检查准备失败，暂时无法确认本次改动是否安全。建议先检查工具连接和配置。',
    }
    return messages.get(status, '尚未确认安全检查工具已连接，当前结果不能证明改动安全。建议先检查工具连接和配置。')


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
        from .host_guidance import runtime_info
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
