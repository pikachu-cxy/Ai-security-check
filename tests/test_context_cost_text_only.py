"""Exercise response observations through the real SDK serialization boundary."""
import copy
import json

import pytest
from mcp.server.fastmcp.utilities.func_metadata import func_metadata
from mcp.types import CallToolResult

from security_runtime import context_cost
from security_runtime.context_cost import ContextCostStore


@pytest.fixture
def store(tmp_path, monkeypatch):
    for name in ('SECURITY_RUNTIME_CONTEXT_MODE', 'SECURITY_RUNTIME_CONTEXT_MONITOR',
                 'SECURITY_RUNTIME_CONTEXT_RUN'):
        monkeypatch.delenv(name, raising=False)
    return ContextCostStore(tmp_path / 'metrics.sqlite3')


def text_reply(payload):
    def response() -> dict:
        return payload
    metadata = func_metadata(response)
    assert metadata.output_schema is None
    return CallToolResult(content=metadata.convert_result(response()))


def test_sdk_text_only_source_and_duplicate_receipts_are_observed_without_persisting_bodies(store):
    payload = dict(evidence_id='PRIVATE-EVIDENCE', start_line=1,
                   lines=['PRIVATE SOURCE ONE', 'PRIVATE SOURCE TWO'], scanner_run=False)
    response = text_reply(payload)
    original = response.model_dump()
    for _ in range(2):
        assert store.record_call('read_task_review_context', response)['status'] == 'RECORDED'
    store.record_call('read_task_review_context', text_reply(dict(
        status='ALREADY_DELIVERED', evidence_refs=['PRIVATE-EVIDENCE'], source_lines_delivered=0)))
    summary = store.summary()
    assert summary['source_lines_delivered'] == 4
    assert summary['repeated_evidence_deliveries'] == 1
    assert summary['duplicate_receipts'] == 1
    assert summary['observation_status'] == 'COMPLETE'
    assert summary['observation_incomplete_calls'] == 0
    assert response.model_dump() == original
    persisted = store.path.read_bytes()
    assert b'PRIVATE SOURCE' not in persisted and b'PRIVATE-EVIDENCE' not in persisted


def test_structured_payload_wins_over_its_text_copy_and_unknown_tool_text_is_not_parsed(store):
    payload = dict(evidence_id='test', start_line=1, lines=['one', 'two'])
    response = dict(structuredContent=payload,
                    content=[dict(type='text', text=json.dumps(payload))])
    before = copy.deepcopy(response)
    store.record_call('read_task_review_context', response)
    store.record_call('unregistered_tool', text_reply(payload))
    events = store.snapshot()['events']
    assert events[0]['observation_status'] == 'UNKNOWN'
    assert events[0]['source_lines_delivered'] == 0
    assert events[1]['source_lines_delivered'] == 2
    assert response == before
    assert store.summary()['observation_status'] == 'PARTIAL'
    assert store.summary()['observation_incomplete_calls'] == 1


@pytest.mark.parametrize('content', [
    [dict(type='text', text='not JSON')],
    [dict(type='text', text='"a string"')],
    [dict(type='text', text='{}'), dict(type='text', text='{}')],
    [dict(type='image', data='not-an-image')],
    [dict(type='text', text='[' * 1500)],
])
def test_uninspectable_text_reports_unknown_and_preserves_byte_measurement(store, content):
    assert store.record_call('read_task_review_context', dict(content=content))['status'] == 'RECORDED'
    summary = store.summary()
    assert summary['wire_bytes'] > 0
    assert summary['observation_status'] == 'UNKNOWN'
    assert summary['observation_incomplete_calls'] == 1
    assert summary['limited_measurements'] == 1


def test_text_parser_enforces_utf8_budget_before_decoding(store, monkeypatch):
    monkeypatch.setattr(context_cost, 'MAX_OBSERVATION_TEXT_BYTES', 20)
    store.record_call('read_task_review_context', dict(content=[dict(type='text', text='{"x":"秘密秘密秘密"}')]))
    assert store.summary()['observation_status'] == 'UNKNOWN'


def test_truncated_observation_tree_reports_partial_coverage(store):
    store.record_call('read_task_review_context', dict(structuredContent={'items': [{}] * 2001}, content=[]))
    summary = store.summary()
    assert summary['limited_measurements'] == 1
    assert summary['observation_incomplete_calls'] == 1
    assert store.snapshot()['events'][0]['observation_status'] == 'PARTIAL'
