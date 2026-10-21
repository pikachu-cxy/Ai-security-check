"""Incremental, read-only adapter for one explicitly selected host usage file.

No raw text, prompts, paths or session ids are returned or persisted. Retain
only counters and timestamps in memory; incomplete lines wait for the next poll.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import stat

from ..token_usage import TOKEN_FIELDS, normalized_usage

MAX_FILE = 32 * 1024 * 1024
MAX_LINE = 1024 * 1024


def canonical_project(path):
    return os.path.normcase(os.path.abspath(str(path)))


class HostReader:
    def __init__(self, path=None, project=None, *, expected_identity=None):
        self.path = Path(path) if path is not None else None
        self.expected_identity = expected_identity
        self.project = canonical_project(project) if project is not None else None
        self.offset = 0
        self.identity = None
        self.file_identity = None
        self.usage = None
        self.at = None
        self.cwd = None
        self.previous_project = None
        self.previous_usage = None
        self.project_usage = {name: 0 for name in (*TOKEN_FIELDS, 'total_tokens')}
        self.project_samples = 0
        self.invalid = 0
        self.model = None
        self.last_at = None
        self.status = 'NOT_CONNECTED'

    def _consume(self, row):
        if not isinstance(row, dict):
            return
        payload = row.get('payload')
        payload = payload if isinstance(payload, dict) else {}
        kind = row.get('type')
        if kind in {'session_meta', 'thread.started'}:
            value = payload.get('id') if kind == 'session_meta' else row.get('thread_id')
            if isinstance(value, str) and 0 < len(value) <= 256:
                identity = hashlib.sha256(value.encode()).hexdigest()
                if self.expected_identity is not None and identity != self.expected_identity:
                    raise ValueError('CHAT_IDENTITY_MISMATCH')
                if self.identity is not None and self.identity != identity:
                    raise ValueError('CHAT_IDENTITY_CHANGED')
                self.identity = identity
            cwd = payload.get('cwd')
            if isinstance(cwd, str) and len(cwd) <= 4096 and os.path.isabs(cwd):
                self.cwd = cwd
        if kind == 'turn_context':
            cwd = payload.get('cwd')
            if isinstance(cwd, str) and len(cwd) <= 4096 and os.path.isabs(cwd):
                self.cwd = cwd
            else:
                self.cwd = None
            model = payload.get('model')
            if isinstance(model, str) and len(model) <= 100 and all(c.isalnum() or c in '._-' for c in model):
                self.model = model
        if kind == 'event_msg' and payload.get('type') == 'token_count':
            info = payload.get('info')
            current = normalized_usage(info.get('total_token_usage')) if isinstance(info, dict) else None
            if current is None:
                return
            if self.identity is None:
                self.invalid += 1
                return
            if self.previous_usage is not None and any(current[name] < self.previous_usage[name] for name in TOKEN_FIELDS):
                raise ValueError('COUNTER_RESET')
            project = canonical_project(self.cwd) if self.cwd else None
            if (self.previous_usage is not None and self.project is not None
                    and project == self.previous_project == self.project):
                for name in self.project_usage:
                    self.project_usage[name] += current[name] - self.previous_usage[name]
                self.project_samples += 1
            self.usage, self.previous_usage = current, current
            self.previous_project = project
            try:
                at = datetime.fromisoformat(row.get('timestamp', '').replace('Z', '+00:00'))
                self.at = at.timestamp() if at.tzinfo is not None else None
            except (ValueError, TypeError, AttributeError):
                self.at = None

    def poll(self):
        if self.path is None:
            return self.view()
        try:
            info = self.path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or getattr(info, 'st_file_attributes', 0) & 0x400 or info.st_size > MAX_FILE):
                raise ValueError('UNSAFE_OR_OVERSIZE_FILE')
            identity = (info.st_dev, info.st_ino)
            if self.file_identity is not None and (identity != self.file_identity or info.st_size < self.offset):
                raise ValueError('FILE_REPLACED_OR_TRUNCATED')
            self.file_identity = identity
            with self.path.open('rb') as stream:
                if (stream_stat := os.fstat(stream.fileno())).st_ino != info.st_ino or stream_stat.st_dev != info.st_dev:
                    raise ValueError('FILE_CHANGED')
                stream.seek(self.offset)
                # Freeze this poll at the observed size, permitting safe appends.
                while stream.tell() < info.st_size:
                    start = stream.tell()
                    line = stream.readline(min(MAX_LINE + 1, info.st_size - start))
                    if len(line) > MAX_LINE:
                        raise ValueError('LINE_TOO_LARGE')
                    if not line.endswith(b'\n'):
                        break
                    try:
                        self._consume(json.loads(line))
                    except (json.JSONDecodeError, UnicodeError, RecursionError):
                        self.invalid += 1
                    self.offset = stream.tell()
            self.status = 'PARTIAL' if self.invalid else 'AVAILABLE' if self.usage is not None else 'WAITING_FOR_USAGE'
        except (OSError, ValueError, TypeError):
            self.status = 'UNAVAILABLE'
        return self.view()

    def view(self):
        return dict(status=self.status, usage=dict(self.usage) if self.usage is not None and self.status != 'UNAVAILABLE' else None,
                    as_of=self.at, model=self.model, invalid_records=self.invalid,
                    identity_known=self.identity is not None,
                    project_usage=dict(self.project_usage) if self.project_samples and self.status != 'UNAVAILABLE' else None,
                    project_samples=self.project_samples,
                    project_scope='SELECTED_CHAT_OBSERVED_DELTAS_ONLY; FIRST_BASELINE_AND_OTHER_CHATS_EXCLUDED')
