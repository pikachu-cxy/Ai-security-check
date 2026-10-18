"""Exercise packaging probe helpers without building or starting a subprocess."""
import asyncio
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

from jsonschema import Draft202012Validator
from mcp.types import CallToolResult, TextContent
import pytest

from security_runtime.global_mcp import create_global_server


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def builder(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'scripts'))
    # Import as a module: the executable main guard must never run in this suite.
    return importlib.import_module('rebuild_repair_impact')


@pytest.fixture
def discovered():
    # Any attempted workspace admission fails: inventory and runtime info need
    # no root, task, project source, scanner, build, or installed frozen process.
    server = create_global_server(workspaces=object())
    rows = {tool.name: tool.inputSchema for tool in asyncio.run(server.list_tools())}
    return server, rows


def tool_result(value, *, structured=True, error=False):
    return CallToolResult(isError=error,
        structuredContent=value if structured else None,
        content=[TextContent(type='text', text=json.dumps(value))])


def test_default_decoder_rejects_an_error_receipt(builder):
    error = tool_result(dict(reason_code='TASK_REVIEW_INPUT_INVALID'), error=True)
    with pytest.raises(ValueError, match='unexpected success/error status'):
        builder.decoded_tool(error)


def test_expected_error_decoder_rejects_an_unexpected_success(builder):
    success = tool_result(dict(status='COMPLETE'))
    with pytest.raises(ValueError, match='unexpected success/error status'):
        builder.decoded_tool(success, expected_error=True)


@pytest.mark.parametrize('structured', [False, True], ids=['json-text', 'structured'])
@pytest.mark.parametrize('expected_error', [False, True], ids=['success', 'expected-error'])
def test_decoder_reads_only_dictionary_receipts_with_the_expected_status(
        builder, structured, expected_error):
    value = dict(reason_code='TASK_REVIEW_INPUT_INVALID', field_errors=[])
    result = tool_result(value, structured=structured, error=expected_error)
    assert builder.decoded_tool(result, expected_error=expected_error) == value


@pytest.mark.parametrize('value', [None, [], ['not-an-object'], 'not-an-object', 7, False])
def test_decoder_rejects_non_dictionary_json_text(builder, value):
    with pytest.raises(ValueError, match='structured object'):
        builder.decoded_tool(tool_result(value, structured=False))


@pytest.mark.parametrize('value', [[], 'not-an-object', 7, False])
def test_decoder_rejects_non_dictionary_structured_content(builder, value):
    # Do not let CallToolResult's own validation hide the helper's last guard.
    result = SimpleNamespace(isError=True, structuredContent=value, content=[])
    with pytest.raises(ValueError, match='structured object'):
        builder.decoded_tool(result, expected_error=True)


def test_frozen_schema_probe_accepts_real_discovery_and_rejects_b2_objects(builder, discovered):
    _, rows = discovered
    receipt = builder.frozen_schema_contract(rows)
    assert receipt['status'] == 'PASSED'
    assert receipt['typed_task_review_evidence'] is True
    assert receipt['object_shaped_task_evidence_rejected'] is True
    assert receipt['native_preparation_executed'] is False
    assert receipt['native_baseline_guard_executed'] is False
    assert receipt['explicit_unknown_classification'] is True

    schema = rows['submit_task_security_review']
    candidate = schema['properties']['findings']['items']
    if '$ref' in candidate:
        candidate = schema['$defs'][candidate['$ref'].removeprefix('#/$defs/')]
    fields = candidate['properties']
    assert fields['primary_evidence']['type'] == 'string'
    assert fields['task_evidence']['type'] == 'string'
    assert fields['evidence_refs']['type'] == 'array'
    assert fields['evidence_refs']['items']['type'] == 'string'
    validator = Draft202012Validator(schema)
    validator.validate(builder.task_review_schema_payload())
    assert validator.is_valid(builder.malformed_task_review_payload()) is False


def test_runtime_info_advertises_typed_submission_and_safe_same_task_recovery(builder, discovered):
    server, _ = discovered
    info = builder.decoded_tool(asyncio.run(server.call_tool('get_runtime_info', {})))
    feature = info['features']['task_review_submission']
    assert feature.split(';')[0] == 'task-review-submission-v1'
    assert 'TYPED_ISSUED_EVIDENCE_IDS' in feature
    assert 'SAFE_FIELD_ERRORS' in feature
    assert 'SAME_ACTIVE_REVIEW_RETRY' in feature
    assert builder.has_contract(info, 'task-review-submission-v1') is True


def test_expected_error_decoder_reads_real_pre_admission_rejection(builder, discovered):
    server, _ = discovered
    result = asyncio.run(server.call_tool('submit_task_security_review',
                                         builder.malformed_task_review_payload()))
    rejection = builder.decoded_tool(result, expected_error=True)
    assert rejection['reason_code'] == 'TASK_REVIEW_INPUT_INVALID'
    fields = {item['field'] for item in rejection['field_errors']}
    assert {'findings[0].primary_evidence', 'findings[0].task_evidence',
            'findings[0].evidence_refs[0]'} <= fields
    assert all(rejection[key] is False for key in
               ('scanner_run', 'source_modified', 'repair_authorized', 'review_state_changed'))
    assert 'workspace_readiness' not in rejection


def test_frozen_probe_rejects_unknown_classification_conflict_before_admission(builder, discovered):
    server, rows = discovered
    # The shape is valid JSON Schema; the cross-field model validator is needed.
    payload = builder.malformed_impact_unknown_payload()
    assert Draft202012Validator(rows['submit_repair_impact']).is_valid(payload)
    result = asyncio.run(server.call_tool('submit_repair_impact', payload))
    rejection = builder.decoded_tool(result, expected_error=True)
    assert rejection['reason_code'] == 'REPAIR_IMPACT_INPUT_INVALID'
    assert any(row['field'].startswith('unknowns[') for row in rejection['field_errors'])
    assert all(rejection[key] is False for key in ('scanner_run', 'source_modified', 'repair_authorized'))
    assert 'workspace_readiness' not in rejection
    info = builder.decoded_tool(asyncio.run(server.call_tool('get_runtime_info', {})))
    assert builder.has_contract(info, 'repair-impact-unknowns-v1')
