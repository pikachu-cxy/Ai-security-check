"""MCP SDK boundary and shared raw-input contracts, never security policy.

The adapters validate raw JSON before SDK parsing or workspace admission. Domain
services still validate ownership, evidence, versions and authority themselves.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Callable

from .repair_impact_contract import CONTRACT as IMPACT_CONTRACT, IMPACT_TOOLS
from .task_review_contract import CONTRACT as TASK_REVIEW_CONTRACT


@dataclass(frozen=True)
class RawToolContract:
    names: frozenset[str]
    version: str
    validator: Callable[[str, object, bool], dict | None]


def _impact_input(name, arguments, require_workspace):
    from .repair_impact_contract import impact_input_failure
    return impact_input_failure(name, arguments, require_workspace=require_workspace)


def _task_review_input(name, arguments, require_workspace):
    from .task_review_contract import task_review_input_failure
    return task_review_input_failure(arguments, require_workspace=require_workspace)


def _task_protocol_input(name, arguments, require_workspace):
    from .task_review_protocol import PROTOCOL_VERSION, validate_protocol, UnsupportedTaskReviewProtocol
    if not isinstance(arguments, dict):
        return None
    try:
        validate_protocol(arguments.get('protocol_version', PROTOCOL_VERSION))
    except UnsupportedTaskReviewProtocol as exc:
        return exc.response()
    return None


def unsupported_protocol_failure(exc):
    from .task_review_protocol import UnsupportedTaskReviewProtocol
    cause = exc
    for _ in range(8):
        if isinstance(cause, UnsupportedTaskReviewProtocol):
            return cause.response()
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None


def _guidance_input(name, arguments, require_workspace):
    topics = {'core', 'runtime-workflow', 'task-review', 'risk-decisions', 'repair-impact', 'deep-audit'}
    if (not isinstance(arguments, dict) or set(arguments) != {'topic'}
            or not isinstance(arguments['topic'], str) or arguments['topic'] not in topics):
        return dict(status='GUIDANCE_REQUEST_REJECTED', reason_code='GUIDANCE_INPUT_INVALID',
            message='请选择一个已声明的本地方法主题；此入口不接受项目、源码或网址。',
            scanner_run=False, source_modified=False, repair_authorized=False)
    return None


RAW_TOOL_CONTRACTS = (
    RawToolContract(frozenset({'get_runtime_guidance'}), 'runtime-guidance-v1', _guidance_input),
    RawToolContract(frozenset({'prepare_task_security_review'}),
                    'task-review-plan-v3', _task_protocol_input),
    RawToolContract(IMPACT_TOOLS, IMPACT_CONTRACT, _impact_input),
    RawToolContract(frozenset({'submit_task_security_review'}),
                    TASK_REVIEW_CONTRACT, _task_review_input),
)


def raw_input_failure(name, arguments, *, require_workspace=False):
    """Return bounded diagnostics or None; never route, open stores or echo input."""
    for spec in RAW_TOOL_CONTRACTS:
        if name in spec.names:
            result = spec.validator(name, arguments, require_workspace)
            return result if result and (result.get('field_errors') or
                result.get('reason_code') in {'UNSUPPORTED_TASK_REVIEW_PROTOCOL', 'GUIDANCE_INPUT_INVALID'}) else None
    return None


class MCPRegistry:
    """Keep SDK-private access at one compatibility boundary.

    Existing FastMCP public helpers and low-level stdio handlers remain usable;
    this class owns no task, authorization, scanner or delivery state.
    """
    def __init__(self, server):
        self.server = server
        self.manager = server._tool_manager
        self.low_level = server._mcp_server

    def tools(self):
        return self.manager.list_tools()

    def tool(self, name):
        return self.manager.get_tool(name)

    def names(self):
        return {tool.name for tool in self.tools()}

    def schemas(self):
        return {tool.name: tool.parameters for tool in self.tools()}

    def harden(self, names):
        for name in names:
            tool = self.tool(name)
            tool.fn_metadata.arg_model.model_config.update(
                extra='forbid', strict=True, hide_input_in_errors=True)
            tool.fn_metadata.arg_model.model_rebuild(force=True)
            tool.parameters = tool.fn_metadata.arg_model.model_json_schema()

    async def dispatch(self, name, arguments, **kwargs):
        return await self.manager.call_tool(name, arguments, **kwargs)

    def wrap_dispatch(self, wrapper):
        self.manager.call_tool = wrapper(self.manager.call_tool)

    def validate_raw_inputs(self):
        def wrap(original):
            async def validated(name, arguments, *args, **kwargs):
                failure = raw_input_failure(name, arguments)
                if failure is None:
                    try:
                        return await original(name, arguments, *args, **kwargs)
                    except Exception as exc:
                        from .task_diagnostics import capacity_failure
                        failure = unsupported_protocol_failure(exc) or capacity_failure(exc)
                        if failure is None:
                            raise
                convert = kwargs.get('convert_result', args[1] if len(args) > 1 else False)
                return self.tool(name).fn_metadata.convert_result(failure) if convert else failure
            return validated
        self.wrap_dispatch(wrap)

    def add_instructions(self, instructions):
        self.low_level.instructions += instructions

    def install_router(self, listed, call):
        # The router performs strict raw/model validation before admission.
        self.server.list_tools = listed
        self.server.call_tool = call
        self.low_level.list_tools()(listed)
        self.low_level.call_tool(validate_input=False)(call)

    def close_with(self, close):
        original = self.low_level.lifespan

        @asynccontextmanager
        async def lifespan(inner):
            async with original(inner) as context:
                try:
                    yield context
                finally:
                    close()
        self.low_level.lifespan = lifespan

    def observe_project(self, binding):
        from pathlib import Path
        from mcp.types import CallToolRequest
        from .recent_hooks import instrument
        schemas = self.schemas()
        resolver = lambda arguments: Path(binding.root) if binding is not None else None
        self.wrap_dispatch(lambda call: instrument(call, schemas=schemas, resolve_root=resolver))
        original = self.low_level.request_handlers[CallToolRequest]

        async def request_handler(request):
            async def invoke(name, arguments):
                return await original(request)
            return await instrument(invoke, schemas=schemas, resolve_root=resolver)(
                request.params.name, request.params.arguments)
        self.low_level.request_handlers[CallToolRequest] = request_handler

    def observe_context_cost(self, *, workspace=None):
        """Observe each external response once, after SDK normalization."""
        import os
        if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0':
            return
        try:
            from .context_cost_mcp import observe_response
        except Exception:
            return
        from mcp.types import CallToolRequest
        from uuid import uuid4
        original = self.low_level.request_handlers[CallToolRequest]
        connection_id = uuid4().hex

        async def request_handler(request):
            return await observe_response(original, request, connection_id=connection_id,
                                          workspace=workspace)
        self.low_level.request_handlers[CallToolRequest] = request_handler


def schema_specifications(tools):
    """Project registered or routed tools to a common, serializable description."""
    specs = []
    for tool in tools:
        input_schema = getattr(tool, 'inputSchema', None)
        if input_schema is None:
            input_schema = tool.parameters
        output_schema = getattr(tool, 'outputSchema', getattr(tool, 'output_schema', None))
        annotations = getattr(tool, 'annotations', None)
        if annotations is not None and hasattr(annotations, 'model_dump'):
            annotations = annotations.model_dump(mode='json', exclude_none=True)
        from .compatibility import tool_requirements
        specs.append(dict(name=tool.name, input_schema=input_schema,
                          output_schema=output_schema, effects=annotations,
                          **tool_requirements(tool.name)))
    return sorted(specs, key=lambda item: item['name'])
