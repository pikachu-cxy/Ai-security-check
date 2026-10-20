"""Bounded, explicit import of Codex host usage; session bodies are discarded.

No directory discovery, model requests or token estimation happens here. Cached
input and reasoning output are subsets, never added to input/output totals.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from .token_usage import MAX_TOKENS, TOKEN_FIELDS, normalized_usage

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_LINES = 100_000
MAX_THREADS = 512


def _sum_usage(items):
    result = {name: 0 for name in TOKEN_FIELDS}
    for item in items:
        for name in TOKEN_FIELDS:
            result[name] += item[name]
    result['total_tokens'] = result['input_tokens'] + result['output_tokens']
    return result


def parse_codex_usage(path):
    """Read only a user-selected JSONL file, returning metadata and no text/path.

    Official ``codex exec --json`` turn.completed events are per turn. Rollout
    event_msg/token_count snapshots are cumulative: only the last snapshot per
    thread is used, including when a resumed session repeats older snapshots.
    A mixed file prefers cumulative snapshots instead of double counting them.
    Oversized inputs fail with a fixed error rather than silently undercounting.
    """
    source = Path(path)
    try:
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or source.is_symlink()
                or getattr(info, 'st_file_attributes', 0) & 0x400
                or info.st_size > MAX_FILE_BYTES):
            raise ValueError()
        digest = hashlib.sha256()
        turns, snapshots, warnings = {}, {}, set()
        # The path is used only for an in-memory opaque source key. Persistent
        # storage keys it again with a private random salt; no path is retained.
        source_identity = hashlib.sha256(os.path.normcase(str(source.absolute())).encode('utf-8')).hexdigest()
        current_thread = 'source:' + source_identity
        snapshot_count = 0
        total_read = 0
        with source.open('rb') as stream:
            for number in range(MAX_LINES + 1):
                line = stream.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                total_read += len(line)
                if number == MAX_LINES or len(line) > MAX_LINE_BYTES or total_read > MAX_FILE_BYTES:
                    raise ValueError()
                digest.update(line)
                try:
                    item = json.loads(line)
                except (ValueError, UnicodeError, RecursionError):
                    warnings.add('INVALID_JSON_LINE_IGNORED')
                    continue
                if not isinstance(item, dict):
                    continue
                kind = item.get('type')
                payload = item.get('payload')
                if kind == 'thread.started' and isinstance(item.get('thread_id'), str):
                    current_thread = 'thread:' + hashlib.sha256(item['thread_id'].encode()).hexdigest()
                elif kind == 'session_meta' and isinstance(payload, dict) and isinstance(payload.get('id'), str):
                    current_thread = 'thread:' + hashlib.sha256(payload['id'].encode()).hexdigest()
                elif kind == 'turn.completed':
                    usage = normalized_usage(item.get('usage'))
                    if usage is None:
                        warnings.add('INVALID_USAGE_IGNORED')
                    else:
                        if current_thread not in turns and len(turns) >= MAX_THREADS:
                            raise ValueError()
                        turns.setdefault(current_thread, []).append(usage)
                elif kind == 'event_msg' and isinstance(payload, dict) and payload.get('type') == 'token_count':
                    details = payload.get('info')
                    if not isinstance(details, dict) or details.get('total_token_usage') is None:
                        continue
                    usage = normalized_usage(details.get('total_token_usage'))
                    if usage is None:
                        warnings.add('INVALID_USAGE_IGNORED')
                        continue
                    if current_thread not in snapshots and len(snapshots) >= MAX_THREADS:
                        raise ValueError()
                    snapshots[current_thread] = usage
                    snapshot_count += 1
            else:
                raise ValueError()
        if total_read != info.st_size:
            raise ValueError()
    except (OSError, ValueError, TypeError):
        raise ValueError('CODEX_USAGE_INPUT_UNAVAILABLE_OR_OVER_BUDGET') from None
    if snapshots and turns:
        warnings.add('MIXED_FORMAT_CUMULATIVE_PREFERRED')
    streams = []
    for identity in sorted(set(snapshots) | set(turns)):
        streams.append(dict(identity=identity, identity_verified=identity.startswith('thread:'),
                            source_identity=source_identity,
                            basis='cumulative' if identity in snapshots else 'turn_sum',
                            usage=snapshots[identity] if identity in snapshots else _sum_usage(turns[identity])))
    if any(not item['identity_verified'] for item in streams):
        warnings.add('THREAD_IDENTITY_UNAVAILABLE')
    values = [item['usage'] for item in streams]
    return dict(schema_version=1, status='AVAILABLE' if values else 'UNKNOWN',
                format='mixed' if snapshots and turns else 'codex_rollout' if snapshots else
                       'codex_exec' if turns else 'unknown',
                usage=_sum_usage(values) if values else None,
                observed_turns=sum(len(items) for items in turns.values()), cumulative_snapshots=snapshot_count,
                import_key=digest.hexdigest(), streams=streams, warnings=sorted(warnings),
                complete=bool(values) and not bool(warnings & {
                    'INVALID_JSON_LINE_IGNORED', 'INVALID_USAGE_IGNORED', 'THREAD_IDENTITY_UNAVAILABLE'}))
