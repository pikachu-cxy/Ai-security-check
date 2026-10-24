"""Read original baseline lines from an authenticated, explicit body locator.

The caller supplies an already verified typed source and remains responsible
for task/session authorization. This internal adapter neither reads live files
nor provides semantic proof, source capture, retention pins or review evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
import time

from ..tasks.frozen_body_context import MAX_CONTEXT_BYTES, verify_context
from ..tasks.preimages import MAX_FILE_BODY_BYTES, TaskPreimageStore
from .snapshot_source import TypedSnapshotSource, _path


class FrozenBodySourceError(ValueError):
    def __init__(self, suffix):
        self.reason_code = 'FROZEN_BODY_' + suffix
        super().__init__(self.reason_code)


def _fail(suffix):
    raise FrozenBodySourceError(suffix)


def _detach(packet):
    try:
        raw = json.dumps(packet, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > MAX_CONTEXT_BYTES:
            _fail('INVALID_ARGUMENT')
        return json.loads(raw)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail('INVALID_ARGUMENT')


class FrozenBodySource:
    """Use within the lifetime of the caller-owned TypedSnapshotSource."""

    def __init__(self, hooks, root, context, *, typed_source, now=time.time):
        if (not isinstance(typed_source, TypedSnapshotSource)
                or not isinstance(context, dict) or not callable(now)):
            _fail('INVALID_ARGUMENT')
        try:
            self.root = Path(root)
        except (TypeError, ValueError):
            _fail('INVALID_ARGUMENT')
        self.hooks, self.source, self.now = hooks, typed_source, now
        self._packet = _detach(context)
        self._entered, self._closed, self._store = False, False, None

    def _context(self):
        # scope also verifies that the original typed view is still active and
        # that its source/root and private storage identities remain valid.
        scope = self.source.scope
        payload = verify_context(self.hooks, self.root, self._packet,
                                 task_ref=scope['task_ref'], owner=scope['owner'], now=self.now)
        pairs = (('task_ref', 'task_ref'), ('owner', 'owner'),
                 ('workspace', 'workspace'), ('root_identity', 'root_identity'),
                 ('field', 'field'), ('source', 'source'),
                 ('representation_version', 'representation_version'))
        if (str(self.root) != scope['workspace']
                or any(payload[left] != scope[right] for left, right in pairs)):
            _fail('SCOPE_MISMATCH')
        # Capture identity is independent of later review revisions or raw page
        # references. Their canonical source, task and owner must still match.
        if payload['field'] != 'baseline' or payload['preimage_namespace'] != 'closeout':
            _fail('SCOPE_MISMATCH')
        return payload

    def __enter__(self):
        if self._closed or self._entered:
            _fail('CLOSED')
        try:
            payload = self._context()
            self._store = TaskPreimageStore(self.hooks, self.root, now=self.now,
                                           namespace=payload['preimage_namespace'])
            self._entered = True
            return self
        except BaseException:
            self._closed = True
            raise

    def read_lines(self, path, max_bytes=65536):
        if self._closed or not self._entered:
            _fail('CLOSED')
        if (not _path(path) or type(max_bytes) is not int
                or not 1 <= max_bytes <= MAX_FILE_BODY_BYTES):
            _fail('INVALID_ARGUMENT')
        payload = self._context()
        entry = self.source.entry(path)
        if entry is None:
            _fail('SOURCE_UNAVAILABLE')
        maps = entry['maps']
        expected_hash, reference = maps.get('hashes'), maps.get('preimages')
        if not isinstance(expected_hash, str) or not isinstance(reference, dict):
            _fail('SOURCE_UNAVAILABLE')
        # Reference authentication and expiry checks perform no body SQL. A
        # budget failure must not materialize an oversized body to measure it.
        metadata = self._store._reference(payload['preimage_task_ref'], path,
            expected_hash, reference, self._store._key())
        if (metadata['contract'] != payload['preimage_contract']
                or metadata['redaction_version'] != payload['representation_version']
                or metadata['created_at'] != payload['created_at']
                or metadata['expires_at'] != payload['expires_at']):
            _fail('SOURCE_UNAVAILABLE')
        if metadata['body_bytes'] > max_bytes:
            _fail('WAITING_BODY_BUDGET')
        # Keep the original reader's seal, row, hash, length and TTL checks.
        # No inline, alternate namespace, live or semantic-proof fallback.
        return self._store.read(payload['preimage_task_ref'], path, expected_hash, reference,
                                strict_readonly=True)

    def close(self):
        self._closed, self._entered, self._store = True, False, None

    def __exit__(self, *exception):
        # This adapter owns no SQLite handle and never closes its caller's
        # verified typed source or changes any retained body/context state.
        self.close()
        return False
