"""Explicit one-click launch; exact session matching, never latest-log guessing."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import webbrowser

from ..hook_state import no_links
from ..tasks.ownership import valid_owner

MAX_ENTRIES = 20_000
HEADER_BYTES = 65_536
SESSION_SUFFIX = re.compile(r'([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\.jsonl$')


def codex_home():
    return Path(os.getenv('SECURITY_RUNTIME_CODEX_HOME') or os.getenv('CODEX_HOME') or Path.home() / '.codex')


def find_chat_log(session_hash, *, home=None):
    """Read only exact filename candidates' session metadata, with finite work.

    Session identity is supplied by a validated Hook reference or the launching
    host's thread environment. Timestamps never select a chat. No transcript is
    read until the caller opts into monitoring that exact session.
    """
    if not isinstance(session_hash, str) or re.fullmatch('[a-f0-9]{64}', session_hash) is None:
        raise ValueError('MONITOR_SESSION_REQUIRED')
    root = Path(home) if home is not None else codex_home()
    sessions = root / 'sessions'
    no_links(sessions)
    pending, found, consumed = [(sessions, 0)], [], 0
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    consumed += 1
                    if consumed > MAX_ENTRIES:
                        raise ValueError('MONITOR_DISCOVERY_LIMIT')
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if depth < 3:
                            pending.append((Path(entry.path), depth + 1))
                        else:
                            raise ValueError('MONITOR_DISCOVERY_LIMIT')
                        continue
                    match = SESSION_SUFFIX.search(entry.name)
                    if not match or hashlib.sha256(match[1].encode()).hexdigest() != session_hash:
                        continue
                    path = Path(entry.path)
                    no_links(path)
                    info = path.lstat()  # DirEntry.stat on Windows omits link counts.
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ValueError('MONITOR_LOG_UNAVAILABLE')
                    with path.open('rb') as stream:
                        opened = os.fstat(stream.fileno())
                        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
                            raise ValueError('MONITOR_LOG_UNAVAILABLE')
                        line = stream.readline(HEADER_BYTES + 1)
                    if len(line) > HEADER_BYTES:
                        raise ValueError('MONITOR_LOG_UNAVAILABLE')
                    header = json.loads(line)
                    payload = header.get('payload') if isinstance(header, dict) else None
                    if (not isinstance(header, dict) or header.get('type') != 'session_meta' or not isinstance(payload, dict)
                            or payload.get('id') != match[1]):
                        raise ValueError('MONITOR_LOG_IDENTITY_MISMATCH')
                    found.append(path)
        except FileNotFoundError:
            continue
    if len(found) != 1:
        raise ValueError('MONITOR_LOG_AMBIGUOUS' if found else 'MONITOR_LOG_NOT_FOUND')
    return found[0]


def start_monitor(project, owner, *, store=None, home=None, open_browser=True):
    """Launch an optional local process; no scanner, task or model is started."""
    from ..context_cost import ContextCostStore
    if not valid_owner(owner) or owner['host'] != 'codex':
        raise ValueError('MONITOR_HOST_USAGE_UNSUPPORTED')
    project = Path(project).resolve(strict=True)
    if not project.is_dir():
        raise ValueError('MONITOR_PROJECT_REQUIRED')
    log = find_chat_log(owner['session'], home=home)
    store = store or ContextCostStore()
    # Retain shared collection preferences. A short-lived private lease enables
    # details only on verified calls from this chat; explicit off still wins.
    directory = store.path.parent / 'monitoring' / secrets.token_hex(16)
    no_links(directory)
    directory.mkdir(parents=True, mode=0o700)
    config = dict(project=str(project), chat_log=str(log), owner=owner,
                  db=str(store.path.absolute()))
    from .active import register, unregister
    register(store, owner, directory.name)
    job = directory / 'job.json'
    with job.open('x', encoding='utf-8') as stream:
        json.dump(config, stream)
    if os.name != 'nt':
        job.chmod(0o600)
    command = [sys.executable] if getattr(sys, 'frozen', False) else [sys.executable, '-m', 'security_runtime.cli']
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    try:
        process = subprocess.Popen(command + ['context-usage', 'monitor-worker', '--job', str(job)],
            cwd=str(directory), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True, **options)
    except OSError:
        unregister(store, owner, directory.name)
        raise
    ready = directory / 'ready.json'
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if ready.exists():
            no_links(ready)
            data = json.loads(ready.read_text(encoding='utf-8'))
            url = data.get('url', '')
            from urllib.parse import urlsplit
            parsed = urlsplit(url)
            if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port or parsed.username or parsed.password:
                process.terminate()
                raise ValueError('MONITOR_START_FAILED')
            opened = False
            if open_browser:
                try:
                    opened = bool(webbrowser.open(url))
                except Exception:
                    pass
            return dict(status='AVAILABLE', url=url, browser_opened=opened,
                chat_binding='EXACT_SESSION_ID', scanner_run=False, model_called=False,
                message='监控已启动并关联本聊天；使用结束后点击“结束并导出报告”。',
                collection_mode=store.monitoring().get('mode'))
        if process.poll() is not None:
            unregister(store, owner, directory.name)
            raise ValueError('MONITOR_START_FAILED')
        time.sleep(.05)
    process.terminate()
    unregister(store, owner, directory.name)
    raise ValueError('MONITOR_START_TIMEOUT')


def run_worker(job):
    from ..context_cost import ContextCostStore
    from .server import MonitorServer
    from .service import MonitorService
    path = Path(job)
    no_links(path)
    if path.stat().st_size > 16_384:
        raise ValueError('MONITOR_JOB_INVALID')
    data = json.loads(path.read_text(encoding='utf-8'))
    owner = data['owner']
    if not valid_owner(owner) or owner['host'] != 'codex':
        raise ValueError('MONITOR_JOB_INVALID')
    store = ContextCostStore(data['db'])
    from .active import unregister
    service = MonitorService(store, project=data['project'],
        chat_log=data['chat_log'], chat_owner=owner)
    service.release_monitor = lambda: unregister(store, owner, path.parent.name)
    host = service.reader.poll()
    if service.reader.identity != owner['session'] or host['status'] == 'UNAVAILABLE':
        raise ValueError('MONITOR_LOG_IDENTITY_MISMATCH')
    service.task('start')
    server = MonitorServer(service)
    ready = path.with_name('ready.json')
    from ..hook_state import atomic_bytes
    atomic_bytes(ready, json.dumps(dict(url=server.url)).encode())
    import threading
    # A forgotten page must not leave a permanent background process.
    lifetime = threading.Timer(8 * 60 * 60, server.shutdown)
    lifetime.daemon = True
    lifetime.start()
    try:
        server.serve_forever()
    finally:
        service.release_monitor()
        lifetime.cancel()
        server.server_close()
        ready.unlink(missing_ok=True)


def start_from_environment(project=None, *, store=None):
    session = os.getenv('CODEX_THREAD_ID')
    if not session:
        raise ValueError('MONITOR_SESSION_REQUIRED')
    from ..tasks.ownership import session_owner
    return start_monitor(project or Path.cwd(), session_owner('codex', session), store=store)
