"""Host lifecycle boundary, independent of scanning and remediation policy."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol


class IntegrationDiagnostic(ValueError):
    """Only fixed diagnostics cross this boundary; never config/error contents."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class IntegrationAdapter(Protocol):
    integration_id: str

    def setup(self, root: Path) -> dict: ...
    def status(self, root: Path) -> dict: ...
    def repair(self, root: Path) -> dict: ...
    def remove(self, root: Path) -> dict: ...


class IntegrationManager:
    """Codex only in v0.2; legacy Cursor/WorkBuddy registry stays compatible."""

    def __init__(self, adapter: IntegrationAdapter | None = None):
        if adapter is None:
            from .codex_integration import CodexIntegrationAdapter
            adapter = CodexIntegrationAdapter()
        self.adapter = adapter

    def execute(self, action: str, integration: str, path: str | None = None) -> dict:
        if integration != self.adapter.integration_id or action not in {'setup', 'status', 'repair', 'remove'}:
            raise IntegrationDiagnostic('UNSUPPORTED_INTEGRATION')
        from .codex_integration import validated_workspace
        try:
            root = validated_workspace(path)
            return getattr(self.adapter, action)(root)
        except IntegrationDiagnostic as exc:
            return self._broken(integration, exc.code)
        except (ValueError, OSError, UnicodeError, RecursionError):
            return self._broken(integration, 'CONFIG_INVALID')

    @staticmethod
    def _broken(integration, code):
        return {'integration': integration, 'overall': 'BROKEN', 'installation': 'UNKNOWN',
                'runtime': {'status': code if code in {'RUNTIME_MISSING', 'RUNTIME_STALE', 'CAPABILITY_MISMATCH'} else 'UNKNOWN'},
                'mcp': {'status': code if code in {'MCP_CONFIGURATION_CONFLICT', 'WORKSPACE_BINDING_MISMATCH'} else 'UNKNOWN'},
                'post_tool_hook': {'status': 'UNKNOWN'}, 'readiness': {'status': 'READINESS_NOT_OBSERVED'},
                'legacy_hook': {'status': code if code == 'POTENTIAL_DUPLICATE_HOOK' else 'UNKNOWN'},
                'live_connection': 'UNKNOWN', 'diagnostics': [code]}


def render_integration(value: dict) -> str:
    lines = ['AI Security Runtime / Codex', '']
    for label, key in [('Runtime', 'runtime'), ('MCP', 'mcp'), ('Security Hook', 'post_tool_hook'),
                       ('Startup Ready', 'readiness')]:
        lines.append(f"{label:<15}{value.get(key, {}).get('status', 'UNKNOWN')}")
    lines.extend([f"Mode           {value.get('mode', 'UNKNOWN')}", '', f"Status: {value['overall']}"])
    if value.get('operation'):
        lines.append(value['operation'])
    if value.get('diagnostics'):
        lines.append('Diagnostics: ' + ', '.join(value['diagnostics']))
    lines.append('Readiness is a recent connection observation, not a safety result or a live connection check.')
    if value['overall'] not in {'NOT_INSTALLED', 'READY'}:
        lines.append('Run: security-check integration repair codex --path .')
    if value.get('operation') in {'CONFIGURED', 'REPAIRED'}:
        lines.append('Restart Codex Desktop and open this trusted project. No warm-up prompt is required.')
    return '\n'.join(lines)
