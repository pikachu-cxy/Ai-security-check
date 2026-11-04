"""Compact global discovery; operations keep their existing handlers and checks."""
from copy import deepcopy


CONTRACT = 'grouped-tool-routing-v1'
GROUPS = {
    'development_check': ('begin_development_check', 'record_development_changes',
        'declare_development_outputs', 'finish_development_check', 'get_development_check',
        'complete_development_check', 'wait_development_check',
        'get_development_deliveries', 'get_development_result'),
    'development_review': ('read_development_risk_context', 'submit_development_review',
        'get_development_risks', 'set_development_risk_disposition',
        'prepare_development_risk_fix', 'submit_development_risk_resolution'),
    'security_task': ('begin_security_task', 'switch_security_task', 'finish_security_task',
        'prepare_task_workspace', 'get_task_closeout_status', 'wait_task_closeout', 'cancel_task_closeout'),
    'task_review': ('prepare_task_security_review', 'get_task_review_plan', 'get_task_review_method',
        'read_task_review_context', 'submit_task_review_batch', 'submit_task_security_review',
        'get_task_security_review'),
    'task_risks': ('get_task_risk_ledger', 'prepare_task_risk_feedback', 'submit_task_risk_feedback',
        'mark_task_risk_false_positive', 'set_task_risk_disposition',
        'revoke_task_risk_feedback', 'get_task_risk_feedback'),
    'finding_feedback': ('prepare_finding_feedback', 'submit_finding_feedback',
        'mark_finding_false_positive', 'set_finding_disposition',
        'revoke_finding_feedback', 'get_finding_feedback'),
    'findings': ('get_findings', 'get_security_summary', 'prepare_triage',
        'submit_triage', 'get_triage', 'prepare_task_triage'),
    'repair_impact': ('prepare_repair_impact', 'read_repair_impact_context',
        'submit_repair_impact', 'get_repair_impact'),
    'repair': ('prepare_task_risk_fix', 'cancel_task_risk_fix', 'prepare_task_fix',
        'confirm_remediation', 'refresh_remediation_confirmation', 'verify_task_fix', 'generate_fix', 'verify'),
    'scan': ('start_scan', 'scan_diff', 'scan_project', 'scan_files',
        'get_scan_status', 'get_scan_result', 'list_scan_jobs'),
    'closeout_check': ('prepare_closeout_check', 'run_closeout_check', 'get_closeout_status'),
    'runtime_status': ('get_development_config', 'get_scan_preparation_status',
        'get_workspace_binding_status', 'get_product_epoch_status', 'get_task_isolation_capabilities',
        'get_professional_guidance'),
}
ROUTES = {operation: group for group, operations in GROUPS.items() for operation in operations}


def describe_groups(info):
    """Advertise public entrypoints separately from their retained operations."""
    info['tool_routing_contract'] = CONTRACT
    info['tool_groups'] = GROUPS
    required = info['required_guidance_tools']
    info['required_guidance_operations'] = required
    info['required_guidance_tools'] = sorted({ROUTES.get(name, name) for name in required})
    return info


def available_operations(info, names):
    """A group satisfies capability discovery only when declared AND listed."""
    available = set(names)
    if info.get('tool_routing_contract') == CONTRACT and isinstance(info.get('tool_groups'), dict):
        for group, operations in GROUPS.items():
            declared = info['tool_groups'].get(group)
            if group in available and isinstance(declared, (list, tuple)):
                available.update(name for name in operations if name in declared)
    return available


def operation_schemas(tools):
    """Inspect actual listed schemas, including group members, for setup probes."""
    schemas = {tool.name: tool.inputSchema for tool in tools}
    for tool in tools:
        if tool.name in GROUPS:
            declared = tool.inputSchema.get('properties', {}).get('operation', {}).get('enum', [])
            definitions = tool.inputSchema.get('$defs', {})
            schemas.update({name: _rewrite_refs(definitions[name], '#/$defs/' + name + '/', '#/') for name in GROUPS[tool.name]
                            if name in declared and name in definitions})
    return schemas


def original_call(name, arguments):
    if isinstance(name, str) and name in GROUPS and isinstance(arguments, dict) and arguments.get('operation') in GROUPS[name]:
        return arguments['operation'], arguments.get('arguments')
    return name, arguments


def _rewrite_refs(value, prefix, replacement):
    if isinstance(value, dict):
        return {key: (replacement + item[len(prefix):]
                     if key == '$ref' and isinstance(item, str) and item.startswith(prefix)
                     else _rewrite_refs(item, prefix, replacement)) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_refs(item, prefix, replacement) for item in value]
    return value


def compact_tools(tools):
    from mcp.types import Tool, ToolAnnotations
    indexed = {tool.name: tool for tool in tools}
    hidden = {name for names in GROUPS.values() for name in names}
    result = [tool for tool in tools if tool.name not in hidden]
    for group, names in GROUPS.items():
        members = [indexed[name] for name in names]
        schema = dict(type='object', properties={
            'operation': {'type': 'string', 'enum': list(names)},
            'arguments': {'type': 'object', 'description': 'Original operation arguments, including workspace_path when required.'}},
            required=['operation', 'arguments'], additionalProperties=False,
            oneOf=[{'properties': {'operation': {'const': name},
                                 'arguments': {'$ref': '#/$defs/' + name}}} for name in names])
        schema['$defs'] = {tool.name: _rewrite_refs(deepcopy(tool.inputSchema), '#/', '#/$defs/' + tool.name + '/') for tool in members}
        result.append(Tool(name=group, inputSchema=schema,
            description='Choose operation and pass its exact arguments. Existing scope, ownership and authorization checks apply.\n' +
                '\n'.join(f'{tool.name}: {tool.description}' for tool in members),
            annotations=ToolAnnotations(
                readOnlyHint=all(tool.annotations and tool.annotations.readOnlyHint for tool in members),
                destructiveHint=any(not tool.annotations or tool.annotations.destructiveHint for tool in members),
                openWorldHint=any(not tool.annotations or tool.annotations.openWorldHint for tool in members))))
    return result


def instructions():
    import json
    return ('\nCompact global tool routing: when guidance or next_action names an operation below, '
        'call its group tool with {operation: ORIGINAL_NAME, arguments: ORIGINAL_ARGUMENTS}. '
        'Keep workspace_path/session_ref and every original argument inside arguments. '
        'Unlisted operations keep their direct tool. Old direct calls remain compatible. '
        'Grouping changes no workflow, evidence or permission requirement. Groups: ' + json.dumps(GROUPS))
