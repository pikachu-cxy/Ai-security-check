"""Optional current-chat entry; verifies existing routing, creates no task."""
from pathlib import Path

from mcp.types import ToolAnnotations


def register(server, registry, *, application):
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def start_risk_dashboard() -> dict:
        """When the user asks to open risk statistics or the risk dashboard, start the local read-only dashboard and open its returned URL in the host. Reads retained local project risk records; never scans, modifies disposition, or starts token/time monitoring. Historical candidates may be duplicated or lack current disposition."""
        from ..risk_dashboard import launch
        try:
            return dict(status='AVAILABLE', url=launch(), scanner_run=False, source_modified=False,
                        message='本机风险统计已启动，请打开返回的本机页面。')
        except (OSError, ValueError):
            return dict(status='UNAVAILABLE', scanner_run=False, source_modified=False,
                        message='风险统计页面暂时无法启动。')

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def start_usage_monitor(workspace_path: str, session_ref: str) -> dict:
        """When the user asks to start consumption monitoring, open the local page for THIS chat. Pass its existing Hook session_ref; never ask the user to find logs or expose that ref. Starts observation automatically; the page ends and exports a private token/time report with one button. No scan, model, development task or repair. Missing/ambiguous chat identity stays unavailable; never choose the latest log. Requires an updated connected Runtime."""
        from ..tasks.ownership import verify_session_ref, current_owner
        from .launch import start_monitor
        try:
            root = Path(application.bound_path(workspace_path)).resolve(strict=True)
            owner = verify_session_ref(application.hooks, root, session_ref)
            existing = current_owner()
            if existing is not None and existing != owner:
                raise ValueError('MONITOR_SESSION_MISMATCH')
            return start_monitor(root, owner)
        except Exception as exc:
            code = str(exc)
            if not code.startswith('MONITOR_') or len(code) > 80:
                code = 'MONITOR_START_UNAVAILABLE'
            return dict(status='UNAVAILABLE', reason_code=code, scanner_run=False,
                model_called=False, message='无法确认本聊天的本机用量来源，未猜测其他聊天。')

    registry.harden(('start_usage_monitor', 'start_risk_dashboard'))
