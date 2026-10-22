"""Optional metadata for the exact bounded BYOK request, never a model caller.

No headers, endpoint, key, prompt, response body or exception text is retained.
The manifest measures UTF-8 content, not tokens or a server's hidden prompt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from uuid import uuid4

_KEY = secrets.token_bytes(32)
MAX_BODY = 262144
CATEGORIES = frozenset({'system_instructions', 'developer_instructions', 'user_input',
    'repository_evidence', 'related_evidence', 'product_evidence', 'output_schema',
    'json_framing', 'history', 'tool_results', 'unknown'})
ROLES = frozenset({'system', 'developer', 'user', 'assistant', 'tool', 'unknown'})


def fingerprint(kind, value):
    return hmac.new(_KEY, kind.encode() + b'\0' + value, hashlib.sha256).hexdigest()


def provider_usage(value):
    """Validate the response's usage. Absent optional details stay unknown."""
    if value is None:
        return None, 'MISSING'
    try:
        if type(value) is not dict:
            raise ValueError()
        def count(v):
            if type(v) is not int or not 0 <= v <= 10**12:
                raise ValueError()
            return v
        incoming, outgoing = count(value['prompt_tokens']), count(value['completion_tokens'])
        if 'total_tokens' in value and count(value['total_tokens']) != incoming + outgoing:
            raise ValueError()
        result = dict(input_tokens=incoming, output_tokens=outgoing,
                      total_tokens=incoming + outgoing, cached_input_tokens=None,
                      reasoning_output_tokens=None)
        for source, field, target, total in (
                ('prompt_tokens_details', 'cached_tokens', 'cached_input_tokens', incoming),
                ('completion_tokens_details', 'reasoning_tokens', 'reasoning_output_tokens', outgoing)):
            detail = value.get(source)
            if detail is not None:
                if type(detail) is not dict:
                    raise ValueError()
                if detail.get(field) is not None:
                    result[target] = count(detail[field])
                    if result[target] > total:
                        raise ValueError()
        return result, 'REPORTED'
    except (ValueError, TypeError, KeyError):
        return None, 'INVALID'


def input_manifest(body):
    """Partition actual message content without reserializing its inner JSON.

    Component byte counts sum to content_bytes. JSON framing is explicit;
    request_bytes additionally includes wire escaping, roles and configuration.
    """
    if type(body) is not bytes or len(body) > MAX_BODY:
        raise ValueError('MODEL_OBSERVATION_BUDGET')
    data = json.loads(body)
    messages = data.get('messages')
    if type(messages) is not list or len(messages) > 128:
        raise ValueError('MODEL_OBSERVATION_SHAPE')
    groups = {}
    decoder = json.JSONDecoder()
    def add(role, category, text):
        raw = text.encode('utf-8')
        key = role, category
        group = groups.setdefault(key, dict(bytes=0, parts=0, digest=hmac.new(_KEY, digestmod=hashlib.sha256)))
        group['bytes'] += len(raw)
        group['parts'] += 1
        group['digest'].update(len(raw).to_bytes(8, 'big') + raw)

    def skip(text, index):
        while index < len(text) and text[index] in ' \r\n\t':
            index += 1
        return index

    def partition(text, role, depth=0, packet=False):
        # Only split the Runtime-authored evidence envelope. Unknown content is
        # measured as user input, never guessed from phrases or file names.
        if depth > 3 or not text.lstrip().startswith('{'):
            add(role, 'product_evidence' if packet else 'user_input', text)
            return
        index = skip(text, 0) + 1
        previous = 0
        fields = 0
        while True:
            index = skip(text, index)
            if text[index] == '}':
                break
            key, end = decoder.raw_decode(text, index)
            index = skip(text, end)
            if text[index] != ':':
                raise ValueError('MODEL_OBSERVATION_SHAPE')
            start = skip(text, index + 1)
            value, end = decoder.raw_decode(text, start)
            fields += 1
            if fields > 128:
                raise ValueError('MODEL_OBSERVATION_BUDGET')
            add(role, 'json_framing', text[previous:start])
            segment = text[start:end]
            if key == 'evidence_packet' and type(value) is dict:
                partition(segment, role, depth + 1, packet=True)
            elif key == 'evidence_packets' and type(value) is list:
                pos, last = skip(segment, 0) + 1, 0
                if len(value) > 64:
                    raise ValueError('MODEL_OBSERVATION_BUDGET')
                for _ in value:
                    pos = skip(segment, pos)
                    _, stop = decoder.raw_decode(segment, pos)
                    add(role, 'json_framing', segment[last:pos])
                    partition(segment[pos:stop], role, depth + 1, packet=True)
                    last = stop
                    pos = skip(segment, stop)
                    if segment[pos] == ',':
                        pos += 1
                add(role, 'json_framing', segment[last:])
            else:
                category = ('repository_evidence' if key == 'shared_UNTRUSTED_CODE' or packet and key == 'context'
                    else 'related_evidence' if packet and key == 'related_evidence'
                    else 'output_schema' if key == 'required_output_schema'
                    else 'product_evidence')
                add(role, category, segment)
            previous = end
            index = skip(text, end)
            if text[index] != ',':
                break
            index += 1
        add(role, 'json_framing', text[previous:])

    total = 0
    for message in messages:
        role, content = message.get('role'), message.get('content')
        if role not in ROLES or type(content) is not str:
            raise ValueError('MODEL_OBSERVATION_SHAPE')
        total += len(content.encode('utf-8'))
        if role == 'user':
            try:
                value = json.loads(content)
            except ValueError:
                value = None
            if type(value) is dict and ('evidence_packet' in value or 'evidence_packets' in value):
                partition(content, role)
            else:
                add(role, 'user_input', content)
        else:
            add(role, {'system':'system_instructions', 'developer':'developer_instructions',
                'assistant':'history', 'tool':'tool_results'}.get(role, 'unknown'), content)
    components = [dict(role=role, category=category, bytes=group['bytes'], parts=group['parts'],
                       fingerprint=group['digest'].hexdigest()) for (role, category), group in groups.items()]
    if sum(item['bytes'] for item in components) != total:
        raise ValueError('MODEL_OBSERVATION_PARTITION')
    return dict(status='COMPLETE_CLIENT_MESSAGES', request_bytes=len(body), content_bytes=total,
                message_count=len(messages), components=components,
                request_fingerprint=fingerprint('request', body))


def begin_request(body):
    """Called only after existing authorization and body-size validation."""
    if os.getenv('SECURITY_RUNTIME_CONTEXT_MONITOR') == '0' or os.getenv('SECURITY_RUNTIME_CONTEXT_MODE') == 'off':
        return None
    from .context_cost_worker import get_worker
    collector = get_worker()
    setting = collector.snapshot_settings() if collector is not None else {}
    if setting.get('mode') not in {'basic', 'debug'}:
        return None
    attempt = Attempt(collector, setting, input_manifest(body))
    attempt.publish('STARTED')
    return attempt


class Attempt:
    def __init__(self, collector, setting, manifest):
        self.collector, self.setting, self.manifest = collector, setting, manifest
        self.request_id, self.attempt_id = uuid4().hex, uuid4().hex
        self.started_at, self.monotonic_start = time.time(), time.monotonic()
        self.usage, self.usage_status, self.response_fingerprint = None, 'MISSING', None

    def response(self, data):
        if type(data) is dict:
            self.usage, self.usage_status = provider_usage(data.get('usage'))
            value = data.get('id')
            if type(value) is str and 0 < len(value) <= 256:
                self.response_fingerprint = fingerprint('provider_response', value.encode('utf-8'))

    def publish(self, state):
        from .observation import current_facts
        facts = current_facts()
        correlation = facts.get('correlation', {})
        now = time.time()
        self.collector.offer(dict(tool='byok_request', transport='workspace',
            workspace=facts.get('workspace'), chat_owner=facts.get('owner'), correlation=correlation,
            mode=self.setting['mode'], run_label='unobserved-start-setting'
                if self.setting.get('source') == 'startup' else self.setting.get('run', 'default'),
            started_at=self.started_at, finished_at=now,
            elapsed_ms=max(0, int((time.monotonic()-self.monotonic_start)*1000)),
            succeeded=state == 'COMPLETED', measurements={}, observations={},
            model_request=dict(request_id=self.request_id, attempt_id=self.attempt_id, state=state,
                usage=self.usage, usage_status=self.usage_status, response_fingerprint=self.response_fingerprint,
                manifest=self.manifest)))


def validate_model_record(value):
    """Fixed metadata schema at the queue and persistence boundary."""
    from .context_cost_worker import _mapping, _text, _number, _HEX, _CALL_ID
    value = _mapping(value, {'request_id', 'attempt_id', 'state', 'usage', 'usage_status',
                             'response_fingerprint', 'manifest'})
    out = {}
    for name in ('request_id', 'attempt_id'):
        out[name] = _text(value[name], 64)
        if not _CALL_ID.fullmatch(out[name]):
            raise ValueError()
    if value.get('state') not in {'STARTED', 'COMPLETED', 'FAILED'} or value.get('usage_status') not in {'REPORTED', 'MISSING', 'INVALID'}:
        raise ValueError()
    out.update(state=value['state'], usage_status=value['usage_status'], usage=None, response_fingerprint=None)
    if value.get('response_fingerprint') is not None:
        out['response_fingerprint'] = _text(value['response_fingerprint'], 64)
        if not _HEX.fullmatch(out['response_fingerprint']):
            raise ValueError()
    if value.get('usage') is not None:
        usage = _mapping(value['usage'], {'input_tokens', 'output_tokens', 'total_tokens',
                                          'cached_input_tokens', 'reasoning_output_tokens'})
        out['usage'] = {name: None if count is None and name in {'cached_input_tokens', 'reasoning_output_tokens'}
                       else _number(count, 2*10**12) for name, count in usage.items()}
        if (set(usage) != {'input_tokens','output_tokens','total_tokens','cached_input_tokens','reasoning_output_tokens'}
                or usage['total_tokens'] != usage['input_tokens'] + usage['output_tokens']
                or any(usage[sub] is not None and usage[sub] > usage[total] for sub,total in
                    (('cached_input_tokens','input_tokens'),('reasoning_output_tokens','output_tokens')))):
            raise ValueError()
    if (out['usage'] is None) != (out['usage_status'] != 'REPORTED'):
        raise ValueError()
    manifest = _mapping(value['manifest'], {'status','request_bytes','content_bytes','message_count','components','request_fingerprint'})
    if manifest.get('status') != 'COMPLETE_CLIENT_MESSAGES':
        raise ValueError()
    clean = {name:_number(manifest[name], maximum) for name,maximum in
             (('request_bytes',MAX_BODY),('content_bytes',MAX_BODY),('message_count',128))}
    clean.update(status=manifest['status'], request_fingerprint=_text(manifest['request_fingerprint'],64), components=[])
    if not _HEX.fullmatch(clean['request_fingerprint']):
        raise ValueError()
    components = manifest['components']
    if type(components) is not list or len(components) > 64:
        raise ValueError()
    for item in components:
        item = _mapping(item, {'role','category','bytes','parts','fingerprint'})
        if item.get('role') not in ROLES or item.get('category') not in CATEGORIES:
            raise ValueError()
        hashed = _text(item['fingerprint'],64)
        if not _HEX.fullmatch(hashed):
            raise ValueError()
        clean['components'].append(dict(role=item['role'],category=item['category'],fingerprint=hashed,
            bytes=_number(item['bytes'],MAX_BODY),parts=_number(item['parts'],10000)))
    if sum(item['bytes'] for item in clean['components']) != clean['content_bytes']:
        raise ValueError()
    out['manifest'] = clean
    return out
