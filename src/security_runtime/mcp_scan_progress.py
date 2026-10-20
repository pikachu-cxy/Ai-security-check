"""Bridge shared scan events to optional MCP notifications and measured timings."""
from __future__ import annotations

import time

import anyio

from .progress import ProgressReporter


_MESSAGES = {
    'SCAN_REQUEST_ACCEPTED': '已确定检查范围，正在准备',
    'SCAN_REUSE_CHECK_STARTED': '正在核验上次结果是否仍适用',
    'WORKSPACE_DISCOVERY_COMPLETED': '正在确认检查文件',
    'TARGET_DISCOVERY_COMPLETED': '检查范围已确认，正在准备检查',
    'SCANNER_STARTED': '安全检查进行中',
    'SCAN_COMPLETED': '扫描完成，接下来核对检查结果',
    'SCAN_RESULT_REUSED': '已验证并复用此前扫描结果，接下来核对检查结果',
}


async def run_mcp_scan(server, operation):
    """Run blocking local scanning off the protocol loop; notifications are optional.

    Static messages never include source, arbitrary paths, scanner logs or secrets.
    A client without a progress token receives the same final scan result.
    """
    context = server.get_context()
    try:
        request = context.request_context
        enabled = request.meta is not None and request.meta.progressToken is not None
    except (ValueError, LookupError, AttributeError):
        enabled = False
    seen = set()
    notifications = 0

    async def report(message):
        nonlocal enabled, notifications
        if not enabled:
            return
        try:
            notifications += 1
            await context.report_progress(float(notifications), message=message)
        except Exception:
            enabled = False  # Presentation failure never changes a scan result.

    def sink(event):
        key = event.event_type
        if key not in _MESSAGES or key in seen:
            return
        seen.add(key)
        if enabled:
            anyio.from_thread.run(report, _MESSAGES[key])

    reporter = ProgressReporter(sink)
    started = time.monotonic()

    def execute():
        reporter.emit('SCAN_REQUEST_ACCEPTED')
        return operation(reporter)

    try:
        result = await anyio.to_thread.run_sync(execute, abandon_on_cancel=True)
    except BaseException:
        reporter.cancel()
        raise
    return result, dict(contract='mcp-scan-timing-v1',
        request_ms=round((time.monotonic()-started)*1000),
        host_analysis_ms=None, conversation_total_ms=None,
        progress_notifications=notifications)


def scan_timing(result, request_timing, *, reused=False):
    """Keep this request's work distinct from historical execution and host time."""
    diagnostics = (result.get('scanner_diagnostics', {}) if isinstance(result, dict)
                   else result.scanner_diagnostics)
    duration = result.get('duration_ms') if isinstance(result, dict) else result.duration_ms
    stages = diagnostics.get('timing_ms', {})
    measured = {key: value for key, value in stages.items()
                if key in {'workspace_discovery', 'target_preparation', 'rule_planning',
                    'reuse_proof_prepare', 'reuse_proof_seal', 'scanner_orchestration',
                    'result_normalization_policy', 'state_persistence', 'total'}
                and type(value) in {int, float} and value >= 0}
    return dict(request_timing, scan_ms=0 if reused else measured.get('total', duration),
        scan_stages_ms={} if reused else measured,
        historical_scan_ms=duration if reused else None,
        reused=reused)
