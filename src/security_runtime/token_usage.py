"""Host-neutral validation for reported token counters, never token estimates."""
from __future__ import annotations

MAX_TOKENS = 10**12
TOKEN_FIELDS = ('input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_output_tokens')


def normalized_usage(value):
    """Validate counts without copying arbitrary host report fields.

    Cached input and reasoning output are subsets. The total counts input and
    output once, so neither subset can inflate the reported total.
    """
    if not isinstance(value, dict):
        return None
    if any(name not in value for name in ('input_tokens', 'output_tokens')):
        return None
    result = {}
    for name in TOKEN_FIELDS:
        count = value.get(name, 0)
        if type(count) is not int or not 0 <= count <= MAX_TOKENS:
            return None
        result[name] = count
    if (result['cached_input_tokens'] > result['input_tokens']
            or result['reasoning_output_tokens'] > result['output_tokens']):
        return None
    result['total_tokens'] = result['input_tokens'] + result['output_tokens']
    return result
