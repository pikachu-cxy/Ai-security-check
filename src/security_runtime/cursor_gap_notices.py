"""Bounded, persistent Cursor presentation deduplication; never check evidence."""
from __future__ import annotations

import hashlib
import hmac
import json

from .cursor_event_adapter import claim
from .hook_state import MAX_SESSIONS, atomic_bytes, identity, no_links

MAX_BYTES = 20_000


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def claim_gap_notice(hooks, root, session, generation):
    """Claim one generic notice for the currently verified session generation.

    Callers must verify the Cursor workspace/session/generation binding first.
    The lock and signed record survive separate command-Hook processes. Only
    digests are stored; this is not a delivery receipt or a scan result.
    """
    if not claim(session) or not claim(generation):
        raise ValueError('Invalid Cursor notice binding')
    with hooks.lock(root, wait_seconds=2) as acquired:
        if not acquired:
            raise ValueError('Cursor notice state unavailable')
        path = hooks.workspace_directory(root) / 'cursor-gap-notices.json'
        no_links(path)
        key = hooks.key(root)
        value = dict(version=1, sessions={})
        if path.exists():
            if path.stat().st_size > MAX_BYTES:
                raise ValueError('Cursor notice state budget exceeded')
            signed = json.loads(path.read_bytes())
            if not isinstance(signed, dict):
                raise ValueError('Invalid Cursor notice state')
            signature = signed.pop('signature', None)
            if (not isinstance(signature, str) or not hmac.compare_digest(signature,
                    hmac.new(key, _encode(signed), hashlib.sha256).hexdigest())):
                raise ValueError('Unverified Cursor notice state')
            value = signed
        sessions = value.get('sessions')
        def digest(item):
            return (isinstance(item, str) and len(item) == 64
                    and all(c in '0123456789abcdef' for c in item))
        if (set(value) != {'version', 'sessions'} or type(value['version']) is not int or value['version'] != 1
                or not isinstance(sessions, dict) or len(sessions) > MAX_SESSIONS
                or not all(digest(s) and digest(g) for s, g in sessions.items())):
            raise ValueError('Invalid Cursor notice state')
        sid, gid = identity(session), identity(generation)
        if sessions.get(sid) == gid:
            return False
        if sid not in sessions and len(sessions) >= MAX_SESSIONS:
            raise ValueError('Cursor notice session budget exceeded')
        sessions[sid] = gid
        content = _encode(dict(value, signature=hmac.new(key, _encode(value), hashlib.sha256).hexdigest()))
        if len(content) > MAX_BYTES:
            raise ValueError('Cursor notice state budget exceeded')
        atomic_bytes(path, content)
        return True
