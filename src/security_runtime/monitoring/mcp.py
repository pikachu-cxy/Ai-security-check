"""Optional current-chat entry; verifies existing routing, creates no task."""
from pathlib import Path

from mcp.types import ToolAnnotations


def register(server, registry, *, application):
    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def start_usage_monitor(workspace_path: str, session_ref: str) -> dict:
        """When the user asks to start consumption monitoring, open the local page for THIS chat. Pass its existing Hook session_ref; never ask the user to find logs or expose that ref. Starts observation automatically; the page ends and exports a private token/time report with one button. No scan, model, development task or repair. Missing/ambiguous chat identity stays unavailable; never choose the latest log. Requires an updated connected Runtime."""
        from ..task_ownership import verify_session_ref, current_owner
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

    registry.harden(('start_usage_monitor',))
