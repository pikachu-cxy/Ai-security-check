"""Public task finding types and safe recovery across callable, SDK and router."""
import asyncio
import copy
import json

import pytest
from pydantic import ValidationError

from security_runtime.global_mcp import create_global_server
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.mcp_server import create_server
from security_runtime.task_ownership import issue_session_ref
from security_runtime.task_review_contract import (
    SubmitTaskSecurityReviewInput, TaskReviewInputError, task_review_input_failure,
    validate_task_review_body,
)
from security_runtime.task_security import TaskSecurityService, digest_value
from test_global_integration import structured
from test_task_security import service  # noqa: F401


TOOL = 'submit_task_security_review'
SECRET = 'synthetic-contract-secret-must-not-be-reflected-8321'


def candidate():
    # Older protocols' evidence strings remain valid at the shape boundary.
    return dict(title='A bounded access-control candidate', category='custom/authorization',
        severity='MEDIUM', primary_evidence='te-legacy-primary',
        evidence_refs=['te-legacy-primary', 'te-legacy-related'],
        impact='A caller without permission may read a private document.',
        preconditions=['A caller can select another document identifier.'],
        unknowns=['Deployment reachability is not established.'],
        counterevidence=[], fix_advice='Apply the existing owner-or-member policy.')


def arguments():
    return dict(task_ref='ts1-' + 'a' * 32, review_session='tr1-fixture',
                findings=[candidate()], coverage='REVIEWED', limitations=[])


def invoke(server, name, **kwargs):
    return server._tool_manager.get_tool(name).fn(**kwargs)


def resolve_schema(schema, value):
    while '$ref' in value:
        reference = value['$ref']
        assert reference.startswith('#/$defs/')
        value = schema['$defs'][reference.rsplit('/', 1)[-1]]
    return value


def assert_safe_failure(result):
    assert result['reason_code'] == 'TASK_REVIEW_INPUT_INVALID', result
    assert result['status'] == 'INCONCLUSIVE'
    assert result['scanner_run'] is result['source_modified'] is False
    assert result['repair_authorized'] is result['security_proof'] is False
    assert result['review_state_changed'] is False
    assert 1 <= len(result['field_errors']) <= 6
    rendered = json.dumps(result, ensure_ascii=False)
    assert len(rendered.encode('utf-8')) < 8_000
    assert SECRET not in rendered
    assert 'task_ref' in result['correction'] and 'review_session' in result['correction']


def test_local_and_global_discovery_publish_closed_candidate_and_evidence_types():
    local = create_server(global_mode=False)
    # Discovery and malformed requests must not need an admitted workspace.
    global_server = create_global_server(workspaces=object())
    global_tool = next(tool for tool in asyncio.run(global_server.list_tools()) if tool.name == TOOL)
    for schema in (local._tool_manager.get_tool(TOOL).parameters, global_tool.inputSchema):
        assert schema['additionalProperties'] is False
        findings = schema['properties']['findings']
        assert findings['type'] == 'array' and findings['maxItems'] == 10
        item = resolve_schema(schema, findings['items'])
        assert item['additionalProperties'] is False
        assert set(item['required']) == set(candidate())
        properties = item['properties']
        assert properties['primary_evidence']['type'] == 'string'
        assert properties['task_evidence']['type'] == 'string'
        assert properties['evidence_refs']['type'] == 'array'
        assert properties['evidence_refs']['items']['type'] == 'string'
        assert properties['evidence_refs']['minItems'] == 1
        assert properties['evidence_refs']['maxItems'] == 10
        assert properties['category']['type'] == 'string' and 'enum' not in properties['category']
        for optional in ('risk_scope', 'task_evidence', 'current_protections'):
            assert optional not in item['required']
            assert 'default' not in properties[optional]
    assert 'workspace_path' in global_tool.inputSchema['required']


def test_omitted_optional_fields_and_legacy_candidate_identity_are_preserved():
    original = candidate()
    original['category'] = ' custom non-enum category '
    body = validate_task_review_body([original], 'REVIEWED', [])
    assert body['findings'] == [original]
    assert set(body['findings'][0]) == set(original)
    assert digest_value(['original-task', body['findings'][0]]) == digest_value(['original-task', original])
    request = SubmitTaskSecurityReviewInput.model_validate(arguments())
    assert request.findings[0] == candidate() and isinstance(request.findings[0], dict)
    related = dict(original, risk_scope='RELATED_EXISTING', task_evidence='te-legacy-primary',
                   current_protections=[])
    assert validate_task_review_body([related], 'REVIEWED', [])['findings'] == [related]


@pytest.mark.parametrize('field', ['risk_scope', 'task_evidence', 'current_protections'])
def test_optional_does_not_mean_explicit_null_is_accepted(field):
    data = arguments()
    data['findings'][0][field] = None
    with pytest.raises(ValidationError):
        SubmitTaskSecurityReviewInput.model_validate(data)
    result = task_review_input_failure(data)
    assert_safe_failure(result)
    assert any(row['field'] == 'findings[0].' + field for row in result['field_errors'])


@pytest.fixture
def reviewing(service):
    legacy, root, runtime = service
    core = HookCoordinator(runtime, legacy.hooks)
    server = create_server(runtime, hook_coordinator=core, global_mode=False)
    token = issue_session_ref(core.store, root, 'codex', 'submission-contract-chat')
    common = dict(workspace_path=str(root), session_ref=token)
    task = invoke(server, 'begin_security_task', task_key='submission-contract', **common)
    (root / 'routes.py').write_text('def get_order(order_id, user):\n    return load_order(order_id)\n')
    invoke(server, 'finish_security_task', task_ref=task['task_ref'], **common)
    packet = invoke(server, 'prepare_task_security_review', task_ref=task['task_ref'],
                    protocol_version=3, **common)
    data = dict(arguments(), task_ref=task['task_ref'], review_session=packet['review_session'], **common)
    return server, legacy, root, runtime, data


@pytest.mark.parametrize('field', ['primary_evidence', 'task_evidence', 'evidence_refs', 'current_protections'])
def test_direct_callable_rejects_evidence_objects_without_mutating_review(reviewing, field):
    server, legacy, root, runtime, data = reviewing
    evidence_object = dict(evidence_id=SECRET, file_path='routes.py', start_line=1, end_line=2)
    data['findings'][0][field] = [evidence_object] if field in {'evidence_refs', 'current_protections'} else evidence_object
    before = copy.deepcopy(legacy.store(root).get(data['task_ref']))
    calls = copy.deepcopy(runtime.calls)
    source_before = {p.name: p.read_bytes() for p in root.glob('*.py')}
    result = invoke(server, TOOL, **data)
    assert_safe_failure(result)
    assert any(row['field'].startswith('findings[0].' + field) for row in result['field_errors'])
    if field != 'current_protections':
        assert any(row.get('expected_type') == 'string' for row in result['field_errors'])
    assert legacy.store(root).get(data['task_ref']) == before
    assert runtime.calls == calls
    assert {p.name: p.read_bytes() for p in root.glob('*.py')} == source_before


@pytest.mark.parametrize('route', ['sdk', 'global'])
def test_sdk_and_global_shape_errors_do_not_enter_service_or_admit_workspace(monkeypatch, route):
    def forbidden(*args, **kwargs):
        raise AssertionError('Malformed raw input must not enter the task service')
    monkeypatch.setattr(TaskSecurityService, 'submit', forbidden)
    server = create_server(global_mode=False) if route == 'sdk' else create_global_server(workspaces=object())
    data = arguments()
    data['workspace_path'] = 'C:/unadmitted-contract-fixture'
    value = dict(evidence_id=SECRET, file='documents.py', start_line=1, end_line=3)
    data['findings'][0].update(primary_evidence=value, task_evidence=value, evidence_refs=[value])
    result = structured(asyncio.run(server.call_tool(TOOL, data)))
    assert_safe_failure(result)
    fields = {row['field'] for row in result['field_errors']}
    assert {'findings[0].primary_evidence', 'findings[0].task_evidence',
            'findings[0].evidence_refs[0]'} <= fields


@pytest.mark.parametrize('route', ['sdk', 'global'])
@pytest.mark.parametrize('field', ['findings', 'limitations'])
def test_json_string_arrays_cannot_bypass_raw_type_contract(monkeypatch, route, field):
    def forbidden(*args, **kwargs):
        raise AssertionError('SDK JSON pre-parsing must not accept malformed raw input')
    monkeypatch.setattr(TaskSecurityService, 'submit', forbidden)
    server = create_server(global_mode=False) if route == 'sdk' else create_global_server(workspaces=object())
    data = arguments()
    data['workspace_path'] = 'C:/unadmitted-contract-fixture'
    data[field] = json.dumps(data[field])
    result = structured(asyncio.run(server.call_tool(TOOL, data)))
    assert_safe_failure(result)
    assert any(row['field'] == field and row['code'] == 'WRONG_TYPE' for row in result['field_errors'])


@pytest.mark.parametrize('route', ['sdk', 'global'])
def test_many_input_errors_are_bounded_and_never_echo_values_or_unknown_keys(route):
    server = create_server(global_mode=False) if route == 'sdk' else create_global_server(workspaces=object())
    data = arguments()
    data['workspace_path'] = 'C:/unadmitted-contract-fixture'
    bad = dict(candidate(), primary_evidence={'evidence_id': SECRET},
        evidence_refs=[dict(file_path=SECRET)], current_protections=[{'claim': SECRET}],
        title=SECRET * 100, **{SECRET: SECRET})
    data['findings'] = [copy.deepcopy(bad) for _ in range(3)]
    result = structured(asyncio.run(server.call_tool(TOOL, data)))
    assert_safe_failure(result)
    assert len(result['field_errors']) == 6
    # An unknown extra key alone still receives a useful, input-free location.
    extra = arguments()
    extra['workspace_path'] = data['workspace_path']
    extra['findings'][0][SECRET] = SECRET
    extra_result = structured(asyncio.run(server.call_tool(TOOL, extra)))
    assert_safe_failure(extra_result)
    assert extra_result['field_errors'][0]['field'] == 'findings[0].?'


def test_missing_global_workspace_is_reported_before_admission():
    server = create_global_server(workspaces=object())
    result = structured(asyncio.run(server.call_tool(TOOL, arguments())))
    assert_safe_failure(result)
    assert result['field_errors'] == [dict(field='workspace_path', code='REQUIRED',
        correction='全局入口需要当前项目的绝对 workspace_path。')]


@pytest.mark.parametrize('route', ['sdk', 'global'])
@pytest.mark.parametrize('field,value,expected', [
    ('title', ' \t\n ', 'findings[0].title'),
    ('counterevidence', [' \t\n '], 'findings[0].counterevidence[0]'),
    ('primary_evidence', ' \t\n ', 'findings[0].primary_evidence'),
    ('task_evidence', ' \t\n ', 'findings[0].task_evidence'),
    ('evidence_refs', [' \t\n '], 'findings[0].evidence_refs[0]'),
])
def test_blank_candidate_values_are_rejected_before_workspace_admission(monkeypatch, route, field, value, expected):
    def forbidden(*args, **kwargs):
        raise AssertionError('Blank host input must be rejected before task service or workspace admission')
    monkeypatch.setattr(TaskSecurityService, 'submit', forbidden)
    # Whitespace passes JSON Schema's minLength; the shared AfterValidator
    # must run before the global router touches this sentinel workspace pool.
    server = create_server(global_mode=False) if route == 'sdk' else create_global_server(workspaces=object())
    data = arguments()
    data['workspace_path'] = 'C:/unadmitted-contract-fixture'
    data['findings'][0][field] = value
    result = structured(asyncio.run(server.call_tool(TOOL, data)))
    assert_safe_failure(result)
    assert any(row['field'] == expected for row in result['field_errors'])


def test_body_domain_error_is_input_free_and_retains_retry_guidance():
    with pytest.raises(TaskReviewInputError) as error:
        validate_task_review_body([dict(candidate(), primary_evidence={'evidence_id': SECRET})], 'REVIEWED', [])
    assert SECRET not in str(error.value)
    assert_safe_failure(error.value.response())
