"""Bounded response projection; only numeric metadata leaves this module.

Never invoke arbitrary serializers or retain bodies in a queue. Unsupported
or oversized payloads are explicitly incomplete, never full wire measures.
"""
import hashlib
import hmac
import math
import secrets

from pydantic import BaseModel

MAX_CAPTURE_BYTES = 256 * 1024
MAX_CAPTURE_NODES = 4096
MAX_CAPTURE_DEPTH = 24
_KEY = secrets.token_bytes(32)


def capture_response(result, *, tool_name=None):
    from .context_cost import _measure, _observations
    remaining = MAX_CAPTURE_BYTES
    nodes = 0
    limited = False

    def copy(value, depth=0):
        nonlocal remaining, nodes, limited
        nodes += 1
        if nodes > MAX_CAPTURE_NODES or depth > MAX_CAPTURE_DEPTH or remaining <= 0:
            limited = True
            return None
        if isinstance(value, BaseModel):
            fields = type(value).model_fields
            if len(fields) > 128:
                limited = True
                return None
            values = object.__getattribute__(value, '__dict__')
            extras = object.__getattribute__(value, '__pydantic_extra__')
            if extras is not None and (type(extras) is not dict or len(extras) > 128):
                limited = True
                return None
            value = {field.alias or name: values[name] for name, field in fields.items()
                     if name in values and values[name] is not None}
            if extras:
                value.update({name: item for name, item in extras.items() if item is not None})
        if type(value) is str:
            if len(value) > remaining:
                limited = True
                return None
            size = len(value.encode('utf-8'))
            if size > remaining:
                limited = True
                return None
            remaining -= size
            return value
        if value is None or type(value) is bool:
            remaining -= 5
            return value
        if type(value) is int:
            if value.bit_length() > 256:
                limited = True
                return None
            remaining -= 80
            return value
        if type(value) is float and math.isfinite(value):
            remaining -= 32
            return value
        if type(value) is dict:
            out = {}
            for key, item in value.items():
                nodes += 1
                if nodes >= MAX_CAPTURE_NODES or remaining <= 0:
                    limited = True
                    break
                if type(key) is not str or len(key) > 256:
                    limited = True
                    continue
                remaining -= len(key.encode('utf-8')) + 4
                out[key] = copy(item, depth + 1)
            return out
        if type(value) in (list, tuple):
            out = []
            for item in value:
                if nodes >= MAX_CAPTURE_NODES or remaining <= 0:
                    limited = True
                    break
                out.append(copy(item, depth + 1))
            return out
        limited = True
        return None

    mapped, sizes = _measure(copy(result))
    digest = lambda kind, value: hmac.new(_KEY, (kind+'\0'+value).encode('utf-8'), hashlib.sha256).hexdigest()
    observations = _observations(mapped, digest, tool_name=tool_name)
    if limited:
        sizes.update(text_bytes=0, structured_bytes=0, wire_bytes=0, measurement_limited=True)
        observations.update(inspection_limited=True, observation_status='PARTIAL')
    return sizes, observations
