"""Lightweight observed-edit checks; strict task audits remain a separate API."""
from mcp.types import ToolAnnotations
from pydantic import Field
from typing import Annotated


TOOLS = frozenset({'begin_development_check', 'record_development_changes',
                   'finish_development_check', 'get_development_check',
                   'complete_development_check', 'wait_development_check',
                   'get_development_deliveries', 'get_development_result'})


def register(server, registry, *, application):
    def offered(result):
        # Response preparation is not report submission. This in-memory hint
        # only avoids a redundant Stop continuation in this connection.
        delivery = result.get('delivery', {})
        ref = delivery.get('check_ref', result.get('check_ref'))
        seq = delivery.get('scanned_seq', result.get('scanned_seq'))
        if ref and seq and ('static_result' in result or delivery):
            if len(application.development_result_offers) >= 128:
                application.development_result_offers.pop()
            application.development_result_offers.add((ref, seq))
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def begin_development_check(task_key: str, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Start an actual coding task's lightweight edit record. Metadata only: no project inventory, baseline, source snapshot or scan. Use a short task key, never prompt/source. Ordinary chat needs no check. Retain the returned check_ref."""
        service = application.development_service(session_ref=session_ref, workspace=workspace_path)
        result = service.begin(application.bound_path(workspace_path), task_key)
        application.remember_development_check(result, service.owner)
        return result

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    def record_development_changes(check_ref: str, paths: list[str],
                                   workspace_path: str | None = None, session_ref: str | None = None,
                                   scope_unknown: bool = False, event_id: str | None = None) -> dict:
        """Record paths observed during AI editing when Hooks cannot supply them. Include both old/new rename paths and deleted paths. Paths are bounded workspace-relative hints; set scope_unknown for incomplete observations. Metadata only: never starts a worker, scans the project, or creates a before-image. Finish once after editing to check the combined scope."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return service.record(application.bound_path(workspace_path), check_ref, paths,
                              scope_unknown=scope_unknown, event_id=event_id)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    async def finish_development_check(check_ref: str, workspace_path: str | None = None,
                                       session_ref: str | None = None,
                                       wait_seconds: Annotated[int, Field(ge=0, le=25)] = 0) -> dict:
        """Close the observed-edit batch and schedule scoped background work once. Default wait_seconds=0 dispatches immediately. Opt into 1-25 seconds of asynchronous waiting to receive the normal saved result directly, without client polling code. Waiting only reads the original check/owner/version; new edits, terminal state or the time budget stop it. If still pending, continue get_development_check on the same ref, never refinish to wait. No baseline, scope expansion, host review certification or repair authority."""
        from ..development_check import MAX_FINISH_WAIT_SECONDS
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= MAX_FINISH_WAIT_SECONDS:
            raise ValueError('DEVELOPMENT_WAIT_INVALID')
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.finish_and_wait(application.bound_path(workspace_path), check_ref, wait_seconds))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_check(check_ref: str, workspace_path: str | None = None,
                              session_ref: str | None = None) -> dict:
        """Read this owner's saved lightweight check status, scope, versions, findings and gaps. Never scans, rehashes source, or launches a worker. Saved results cover their observed input version only. Analyze relevant risks before the normal development summary; zero static alerts do not prove all code safe."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(service.get(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False))
    async def complete_development_check(check_ref: str, workspace_path: str | None = None,
                                          session_ref: str | None = None) -> dict:
        """Submit the observed batch once; product chooses its bounded wait. Timeout/cancellation leaves durable work and versioned deliveries intact. Continue wait_development_check on the SAME ref, never resubmit to wait. No project baseline or repair authority."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.complete(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    async def wait_development_check(check_ref: str, workspace_path: str | None = None,
                                      session_ref: str | None = None) -> dict:
        """Await saved progress using the product's communication budget. Read-only: never submits, retries, scans or starts a worker. A timeout is not task completion. Returns original scope/version/findings/gaps; cancellation does not cancel background work."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(await service.wait_saved(application.bound_path(workspace_path), check_ref))

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_deliveries(workspace_path: str | None = None, session_ref: str | None = None,
                                    offset: int = 0, limit: int = 20) -> dict:
        """Page this verified owner's pending result deliveries, including older scan versions. Reads do not acknowledge display, start work or grant repairs. Follow the issued get_development_result arguments; keep original owner/workspace."""
        service = application.development_service(session_ref=session_ref, workspace=workspace_path)
        return service.deliveries(application.bound_path(workspace_path), offset=offset, limit=limit)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False))
    def get_development_result(check_ref: str, scanned_seq: int, workspace_path: str | None = None,
                                session_ref: str | None = None) -> dict:
        """Read an original saved version from this owner's outbox, even after later edits/scans. Never substitutes current content or acknowledges user display. Analyze saved scope, gaps and existing risk handling before reporting."""
        service = application.development_service(check_ref, session_ref, workspace_path)
        return offered(service.saved_result(application.bound_path(workspace_path), check_ref, scanned_seq))

    registry.harden(TOOLS)
