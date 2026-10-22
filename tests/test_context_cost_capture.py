from mcp.types import CallToolResult, TextContent

from security_runtime import observation
from security_runtime.context_cost import _measure
from security_runtime.context_cost_capture import capture_response, MAX_CAPTURE_BYTES, MAX_CAPTURE_NODES


def test_sdk_result_bytes_match_existing_measurement_without_body_retention():
    response = CallToolResult(content=[TextContent(type='text', text='你好 result')],
                              structuredContent={'value': [1, True, 'hello']})
    sizes, facts = capture_response(response)
    assert sizes == _measure(response)[1]
    assert 'hello' not in repr((sizes, facts))


def test_invalid_keys_also_consume_the_traversal_budget():
    result = {index: None for index in range(MAX_CAPTURE_NODES + 100)}
    result['scanner_run'] = True
    sizes, facts = capture_response(result)
    assert sizes['measurement_limited']
    assert 'scanner_run' not in facts['flags']
    assert facts['observation_status'] == 'PARTIAL'


def test_oversized_response_is_explicitly_unmeasured():
    sizes, facts = capture_response({'content': [{'type': 'text', 'text': 'x' * (MAX_CAPTURE_BYTES + 1)}]})
    assert sizes['measurement_limited']
    assert sizes['wire_bytes'] == 0  # Storage placeholder, not a measured zero.
    assert facts['observation_status'] == 'PARTIAL'


def test_capture_does_not_invoke_arbitrary_serializer():
    class Hostile:
        def model_dump(self, **kwargs):
            raise AssertionError('must not call')
    sizes, _ = capture_response(Hostile())
    assert sizes['measurement_limited']


def test_later_chat_binding_cannot_override_a_different_host_binding():
    capture, token = observation.begin_call()
    observation.bind_host('codex', 'a' * 64, 'c' * 64, 'd' * 64)
    observation.bind_chat({'host': 'codex', 'session': 'b' * 64})
    result = observation.end_call(capture, token)
    assert result['chat_conflict']
    assert result['session_binding'] is None and capture.owner is None


def test_chat_binding_also_exposes_the_same_observed_session():
    capture, token = observation.begin_call()
    observation.bind_chat({'host': 'cursor', 'session': 'a' * 64})
    result = observation.end_call(capture, token)
    assert result['host'] == 'cursor' and result['session_binding'] == 'a' * 64


def test_finishing_while_an_observation_lock_is_busy_never_waits():
    capture, token = observation.begin_call()
    capture.lock.acquire()
    try:
        result = observation.end_call(capture, token)
    finally:
        capture.lock.release()
    assert result['limited'] and result['chat_conflict'] and result['links'] == []
    assert not observation.active()
