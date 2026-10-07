"""Simulated Host identifiers for isolated MCP acceptance scripts only.

Each call represents a different tool invocation. Never use this to fill missing
claims in a production Hook adapter; Runtime rejects missing host identifiers.
Opaque Runtime references are forwarded unchanged.
"""
import uuid


def invocation_claims(name, arguments):
    if name != 'handle_hook_event':
        return arguments
    return {**arguments, 'turn_id': 'simulated-host-turn',
            'tool_use_id': 'simulated-host-call-' + uuid.uuid4().hex, 'permission_mode': 'default'}
