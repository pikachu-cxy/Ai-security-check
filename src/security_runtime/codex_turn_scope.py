"""Bounded Codex ancestry lookup for an otherwise unmatched native Stop only.

The host owns its task ancestry. This adapter returns identifier hashes, never
chat text, paths to new scan inputs, or authority for another chat/workspace.
Ordinary matching turns do not invoke it.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from .hook_state import no_links
from .performance_trace import timed

_UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
_MAX_BYTES = 4_000_000
_FILE_BYTES = 1_000_000


@timed('hook.resolve_child_turns')
def resolve_child_turns(root, session_id, turn_id, pending_turns):
    """Prove recorded executor turns belong to this root turn using host records.

Missing, unsupported, stale or unreadable host metadata grants no association.
No full transcript traversal, model request, scanner or retry is performed.
"""
    if not all(isinstance(v, str) and _UUID.fullmatch(v) for v in (session_id, turn_id)):
        return frozenset()
    wanted = frozenset(pending_turns)
    if not wanted or len(wanted) > 9:
        return frozenset()
    home = Path(os.getenv('SECURITY_RUNTIME_CODEX_HOME') or os.getenv('CODEX_HOME') or Path.home()/'.codex')
    path = home/'state_5.sqlite'
    deadline = time.monotonic() + .2
    found = set()
    budget = _MAX_BYTES
    try:
        for candidate in (path, path.with_name(path.name+'-wal'), path.with_name(path.name+'-shm')):
            no_links(candidate)
        if not path.is_file():
            return frozenset()
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=.02)) as db:
            db.execute('PRAGMA query_only=ON')
            db.set_progress_handler(lambda: int(time.monotonic() > deadline), 500)
            rows = db.execute('''WITH RECURSIVE children(id, depth) AS (
                SELECT child_thread_id, 1 FROM thread_spawn_edges WHERE parent_thread_id=?
                UNION ALL SELECT e.child_thread_id, c.depth+1 FROM thread_spawn_edges e
                JOIN children c ON e.parent_thread_id=c.id WHERE c.depth<8)
                SELECT DISTINCT t.id, t.cwd, t.rollout_path FROM children c
                JOIN threads t ON t.id=c.id ORDER BY t.created_at DESC LIMIT 65''', (session_id,)).fetchall()
        if len(rows) > 64:
            return frozenset()
        for child, cwd, transcript in rows:
            if budget <= 0 or time.monotonic() > deadline:
                break
            if not isinstance(child, str) or not _UUID.fullmatch(child) or Path(cwd).absolute() != Path(root).absolute():
                continue
            file = Path(transcript)
            if not file.is_absolute() or not file.is_relative_to(home/'sessions') or not file.name.endswith('-'+child+'.jsonl'):
                continue
            no_links(file)
            if not file.is_file():
                continue
            with file.open('rb') as stream:
                size = os.fstat(stream.fileno()).st_size
                count = min(size, _FILE_BYTES, budget)
                if count == size:
                    data = stream.read(count)
                    lines = data.splitlines()
                else:
                    # Long single-turn children keep attribution near the head;
                    # reused children put recent turn starts near the tail.
                    head = stream.read(count // 2)
                    stream.seek(size - (count - len(head)))
                    tail = stream.read(count - len(head))
                    data = head + tail
                    lines = head.splitlines()[:-1] + tail.splitlines()[1:]
            budget -= len(data)
            for line in reversed(lines):
                if b'"task_started"' not in line:
                    continue
                try:
                    event = json.loads(line)
                except (ValueError, UnicodeError, RecursionError):
                    continue
                if not isinstance(event, dict):
                    continue
                payload = event.get('payload', {})
                if event.get('type') != 'event_msg' or not isinstance(payload, dict) or payload.get('type') != 'task_started':
                    continue
                attribution = payload.get('turn_attribution', {})
                if not isinstance(attribution, dict):
                    continue
                executor = payload.get('turn_id')
                if not isinstance(executor, str) or not _UUID.fullmatch(executor):
                    continue
                digest = hashlib.sha256(executor.encode()).hexdigest()
                if (digest in wanted and payload.get('root_turn_id') == turn_id
                        and attribution.get('turn_id') == executor
                        and attribution.get('root_turn_id') == turn_id):
                    found.add(digest)
            if found == wanted:
                break
    except (OSError, ValueError, TypeError, sqlite3.Error):
        return frozenset()
    return frozenset(found)
