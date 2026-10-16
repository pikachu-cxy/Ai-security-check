"""Protocol simulations only: no installed host, credentials or model calls."""
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys

from jsonschema import Draft202012Validator, ValidationError
import pytest


@pytest.fixture
def client(monkeypatch):
    scripts = Path(__file__).parents[1] / 'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location('isolated_client_unit_test',
                                                 scripts/'codex_app_server_client.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_schema():
    return dict(type='object', additionalProperties=False,
        required=['coverage', 'findings', 'limitations'], properties=dict(
            coverage=dict(enum=['REVIEWED', 'PARTIAL']),
            findings=dict(type='array', maxItems=10, items=dict(type='object',
                additionalProperties=False, required=['title'], properties=dict(
                    title=dict(type='string', minLength=1, maxLength=500),
                    evidence=dict(const='issued-evidence')))),
            limitations=dict(type='array', maxItems=30, uniqueItems=True,
                             items=dict(type='string', minLength=1)),
            optional_note=dict(type='string')),
        allOf=[{'if': {'properties': {'coverage': {'const': 'PARTIAL'}}},
                'then': {'properties': {'limitations': {'minItems': 1}}}}])


def test_strict_schema_makes_only_optional_fields_nullable_and_preserves_local_contract(client):
    original = local_schema()
    frozen = deepcopy(original)
    converted = client.strict_schema(original)
    assert original == frozen
    assert converted['required'] == ['coverage', 'findings', 'limitations', 'optional_note']
    assert converted['additionalProperties'] is False
    assert 'allOf' not in converted
    assert converted['properties']['coverage'] == dict(type='string', enum=['REVIEWED', 'PARTIAL'])
    assert converted['properties']['optional_note'] == dict(anyOf=[dict(type='string'), dict(type='null')])
    item = converted['properties']['findings']['items']
    assert item['required'] == ['title', 'evidence']
    assert item['properties']['title'] == dict(type='string')
    assert item['properties']['evidence'] == dict(anyOf=[
        dict(type='string', enum=['issued-evidence']), dict(type='null')])
    assert 'maxItems' not in converted['properties']['findings']
    assert 'uniqueItems' not in converted['properties']['limitations']
    # Provider subset is deliberately weaker. The original local validator must
    # still reject a PARTIAL declaration without its required limitation.
    result = dict(coverage='PARTIAL', findings=[], limitations=[], optional_note=None)
    Draft202012Validator(converted).validate(result)
    with pytest.raises(ValidationError):
        Draft202012Validator(original).validate(client.remove_optional_nulls(result))


def test_remove_optional_nulls_recurses_without_mutating_or_dropping_falsy_values(client):
    value = dict(remove=None, keep_zero=0, keep_false=False, keep_empty='',
                 nested=[dict(remove=None, keep='yes'), None, [], {}])
    before = deepcopy(value)
    assert client.remove_optional_nulls(value) == dict(keep_zero=0, keep_false=False,
        keep_empty='', nested=[dict(keep='yes'), None, [], {}])
    assert value == before


@pytest.mark.parametrize('tool,namespace', [
    ('read_security_batch_context', 'security_review'),
    ('security_review.read_security_batch_context', 'security_review'),
    ('security_review.read_security_batch_context', None),
])
def test_bound_reader_accepts_only_explicit_namespace_or_fully_qualified_name(client, tool, namespace):
    assert client.validate_read_request(dict(tool=tool, namespace=namespace,
        arguments=dict(path='src/handler.js'))) == dict(path='src/handler.js', start_line=1, end_line=80)
    assert client.validate_read_request(dict(tool=tool, namespace=namespace,
        arguments=json.dumps(dict(path='src/handler.js', start_line=81, end_line=100)))) == dict(
            path='src/handler.js', start_line=81, end_line=100)


@pytest.mark.parametrize('params', [
    dict(tool='exec_command', namespace='security_review', arguments=dict(path='a.js')),
    dict(tool='read_security_batch_context', namespace='other', arguments=dict(path='a.js')),
    dict(tool='other.read_security_batch_context', namespace='security_review', arguments=dict(path='a.js')),
    dict(tool='read_security_batch_context', arguments=dict(path='a.js')),
    dict(tool='security_review.read_security_batch_context', namespace='other', arguments=dict(path='a.js')),
])
def test_unregistered_or_ambiguous_tool_cannot_reach_bound_callback(client, params):
    with pytest.raises(ValueError, match='UNREGISTERED_REVIEW_TOOL'):
        client.validate_read_request(params)


@pytest.mark.parametrize('extra', ['workspace', 'task_ref', 'batch_ref', 'review_session',
                                  'source_version', 'file_path'])
def test_tool_arguments_reject_every_binding_override(client, extra):
    with pytest.raises(ValueError, match='INVALID_REVIEW_TOOL_ARGUMENTS'):
        client.validate_read_request(dict(namespace='security_review',
            tool='read_security_batch_context', arguments=dict(path='handler.js', **{extra: 'override'})))


@pytest.mark.parametrize('path', ['', 'bad\x00.js', 'line\n.js', 'x'*4097,
                                  '../secret', 'src/../../secret', '/etc/passwd',
                                  'C:/secret', '\\\\server\\share', 'src\\handler.js'])
def test_context_path_must_be_a_bounded_project_relative_posix_path(client, path):
    with pytest.raises(ValueError, match='INVALID_REVIEW_PATH'):
        client.validate_read_request(dict(namespace='security_review',
            tool='read_security_batch_context', arguments=dict(path=path)))


@pytest.mark.parametrize('low,high', [(True, 80), (1, False), ('1', 80), (1, 80.0),
                                    (0, 80), (-1, 80), (5, 4)])
def test_context_range_never_coerces_bool_string_float_or_invalid_bounds(client, low, high):
    with pytest.raises(ValueError, match='INVALID_REVIEW_RANGE'):
        client.validate_read_request(dict(namespace='security_review', tool='read_security_batch_context',
                                          arguments=dict(path='a.js', start_line=low, end_line=high)))


def test_usage_normalization_preserves_missing_breakdowns_as_unknown(client):
    usage = client.normalize_usage(dict(tokenUsage=dict(total=dict(
        inputTokens=100, cachedInputTokens=0, outputTokens=20))))
    assert usage == dict(input_tokens=100, cached_input_tokens=0, output_tokens=20,
                        reasoning_output_tokens=None, cache_write_input_tokens=None, total_tokens=None)


@pytest.mark.parametrize('value', [True, -1, 0.5, '3', None])
def test_invalid_usage_values_are_not_coerced_to_zero(client, value):
    usage = client.normalize_usage(dict(tokenUsage=dict(total=dict(inputTokens=value,
        cachedInputTokens=0, outputTokens=4, reasoningOutputTokens=1, totalTokens=4))))
    assert usage['input_tokens'] is None
    assert usage['cached_input_tokens'] == 0
    assert usage['output_tokens'] == 4 and usage['reasoning_output_tokens'] == 1


@pytest.mark.parametrize('notification', [{}, {'tokenUsage': None}, {'tokenUsage': 'unknown'},
    {'tokenUsage': {}}, {'tokenUsage': {'total': None}}, {'tokenUsage': {'total': []}}])
def test_unknown_usage_notification_shape_is_unknown(client, notification):
    assert client.normalize_usage(notification) is None


def _simulated_turn(client, monkeypatch, tmp_path, *, runtime_status, completed_before_reply=False,
                    usage_after_completed=False, no_model_response=False, cancel_event=None,
                    cancel_after_read=False):
    """Drive native JSON-RPC ordering through pipes, without any child process."""
    schema = local_schema()
    output = dict(coverage='REVIEWED', findings=[], limitations=[], optional_note=None)
    usage = dict(method='thread/tokenUsage/updated', params=dict(threadId='thread-unit',
        tokenUsage=dict(total=dict(inputTokens=100, cachedInputTokens=10,
            outputTokens=20, reasoningOutputTokens=5, totalTokens=120))))
    completed = dict(method='turn/completed', params=dict(threadId='thread-unit',
        turn=dict(id='turn-unit', status='completed')))
    if no_model_response:
        usage['params']['tokenUsage']['total'] = dict(inputTokens=0, cachedInputTokens=0,
            outputTokens=0, reasoningOutputTokens=0, totalTokens=0)
        completed['params']['turn']['status'] = 'failed'
    tool_call = dict(id=91, method='item/tool/call', params=dict(namespace='security_review',
        tool='read_security_batch_context', arguments=dict(path='handler.js')))
    messages = [dict(id=1, result=dict(userAgent='unit-host')),
        dict(id=2, result=dict(thread=dict(id='thread-unit'), model='unit-model',
            modelProvider='unit-provider', reasoningEffort='medium')),
        dict(id=3, result=dict(data=[dict(name='disabled-server', tools={}, resources=[],
            resourceTemplates=[], runtimeStatus=runtime_status)]))]
    turn_reply = dict(id=4, result=dict(turn=dict(id='turn-unit', status='inProgress')))
    body = [] if no_model_response else [tool_call,
        dict(method='item/completed', params=dict(threadId='thread-unit',
            item=dict(type='agentMessage', text=json.dumps(output))))]
    body += [completed, usage] if usage_after_completed else [usage, completed]
    messages += body+[turn_reply] if completed_before_reply else [turn_reply]+body

    class FakeProcess:
        def __init__(self):
            self.stdin = io.StringIO()
            self.stdout = [json.dumps(item)+'\n' for item in messages]
            self.stderr = []
            self.returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    process = FakeProcess()
    monkeypatch.setattr(client.subprocess, 'Popen', lambda *args, **kwargs: process)
    monkeypatch.setitem(sys.modules, 'codex_host_probe', SimpleNamespace(
        DISABLED_FEATURES=[], readonly_host_config=lambda: {'unit.setting': 'true'}))
    executable = tmp_path/'fake-codex.exe'
    executable.write_bytes(b'unit-test binary content, never executable')
    binary_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    monkeypatch.setitem(sys.modules, 'codex_tool_execution_probe', SimpleNamespace(
        profile_fingerprint=lambda executable, config: dict(host_binary_sha256=binary_sha,
                                                          isolation_config_sha256='unit-config-sha')))
    monkeypatch.setitem(sys.modules, 'codex_readonly_host', SimpleNamespace(
        isolation_profile=lambda *args, **kwargs: dict(global_config_sha256='unit-global-config-sha')))
    profile = dict(binary_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        host_binary_sha256=binary_sha, isolation_config_sha256='unit-config-sha',
        global_config_sha256='unit-global-config-sha', effective_reasoning_effort='medium',
        disabled_features=[], config_overrides={'unit.setting': 'true',
            'features.code_mode.direct_only_tool_namespaces': '["security_review"]'},
        effective_model='unit-model', profile_sha256='unit-profile')
    callbacks = []

    def read_context(**kwargs):
        callbacks.append(kwargs)
        if cancel_after_read:
            cancel_event.set()
        return dict(evidence_id='issued-evidence', text='bounded sanitized context')

    receipt = client.run_model_turn(executable, 'Unit protocol simulation only.', schema,
        read_context, tmp_path/'output', timeout_s=10, expected_profile=profile,
        cancel_event=cancel_event)
    sent = [json.loads(line) for line in process.stdin.getvalue().splitlines()]
    return SimpleNamespace(receipt=receipt, sent=sent, callbacks=callbacks, schema=schema)


@pytest.mark.parametrize('runtime_status', ['disabled', {'status': 'disabled'}])
def test_disabled_mcp_status_string_and_object_are_compatible(client, monkeypatch, tmp_path, runtime_status):
    simulated = _simulated_turn(client, monkeypatch, tmp_path, runtime_status=runtime_status)
    assert simulated.receipt['status'] == 'COMPLETED'
    assert simulated.receipt['result'] == dict(coverage='REVIEWED', findings=[], limitations=[])
    assert simulated.receipt['usage']['input_tokens'] == 100
    assert simulated.callbacks == [dict(path='handler.js', start_line=1, end_line=80)]
    turn = next(message for message in simulated.sent if message.get('method') == 'turn/start')
    assert 'allOf' not in turn['params']['outputSchema']
    assert 'Full local output contract:' in turn['params']['input'][0]['text']
    assert json.dumps(simulated.schema, ensure_ascii=False) in turn['params']['input'][0]['text']


def test_turn_completion_before_rpc_reply_is_not_lost(client, monkeypatch, tmp_path):
    simulated = _simulated_turn(client, monkeypatch, tmp_path,
                               runtime_status={'status': 'disabled'}, completed_before_reply=True)
    assert simulated.receipt['status'] == 'COMPLETED'
    assert simulated.receipt['host_turn_status'] == 'completed'
    assert simulated.receipt['usage_complete'] is True


def test_usage_arriving_after_completion_is_preserved_before_host_shutdown(client, monkeypatch, tmp_path):
    simulated = _simulated_turn(client, monkeypatch, tmp_path,
        runtime_status={'status': 'disabled'}, usage_after_completed=True)
    assert simulated.receipt['status'] == 'COMPLETED'
    assert simulated.receipt['usage_complete'] is True
    assert simulated.receipt['usage']['cached_input_tokens'] == 10


def test_initial_zero_usage_does_not_prove_real_model_execution(client, monkeypatch, tmp_path):
    simulated = _simulated_turn(client, monkeypatch, tmp_path,
        runtime_status={'status': 'disabled'}, no_model_response=True)
    assert simulated.receipt['status'] == 'HOST_TURN_FAILED'
    assert simulated.receipt['usage']['input_tokens'] == 0
    assert simulated.receipt['model_observed'] is False


def test_cancellation_after_snapshot_read_discards_late_result_and_keeps_cost_unknown(client, monkeypatch, tmp_path):
    import threading
    cancelled = threading.Event()
    simulated = _simulated_turn(client, monkeypatch, tmp_path, runtime_status='disabled',
        cancel_event=cancelled, cancel_after_read=True)
    assert simulated.receipt['status'] == 'CANCELLED'
    assert len(simulated.callbacks) == 1
    assert simulated.receipt['result'] is None
    assert simulated.receipt['usage_complete'] is False
    assert simulated.receipt['usage_accounting_may_be_incomplete'] is True
