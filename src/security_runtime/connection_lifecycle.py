"""Bounded process-exit diagnostics; no request arguments or per-call disk IO."""
import json
import os
from pathlib import Path
import re
import signal
import threading
import time
import uuid

CURRENT = None


def diagnostics(directory=None):
    """Read bounded retained exits. Missing exits never imply a clean shutdown."""
    from .storage import SQLiteStore
    from .hook_state import no_links
    root = Path(directory) if directory else SQLiteStore.default_path().parent / 'connections'
    records = []
    no_links(root)
    if root.is_dir():
        paths = sorted(root.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:32]
        for path in paths:
            try:
                no_links(path)
                if path.stat().st_size > 8192:
                    continue
                row = json.loads(path.read_bytes())
                if row.get('contract') != 'connection-lifecycle-v1':
                    continue
                if row.get('state') == 'RUNNING' and type(row.get('pid')) is int and row['pid'] > 0:
                    try:
                        os.kill(row['pid'], 0)
                    except ProcessLookupError:
                        row = dict(row, state='EXIT_UNRECORDED', reason='PROCESS_NOT_FOUND', exit_code=None)
                    except PermissionError:
                        row = dict(row, state='PROCESS_STATUS_UNKNOWN')
                records.append(row)
            except (ValueError, OSError, TypeError):
                continue
    return dict(contract='connection-diagnostics-v1', records=records, scanner_run=False,
                limitation='SIGKILL, host transport failure and lost diagnostics may have no recorded exit reason. PID existence is not connection health.')


class Lifecycle:
    def __init__(self, directory=None):
        from .storage import SQLiteStore
        self.directory = Path(directory) if directory else SQLiteStore.default_path().parent / 'connections'
        self.path = self.directory / (uuid.uuid4().hex + '.json')
        self.lock = threading.Lock()
        self.row = dict(contract='connection-lifecycle-v1', pid=os.getpid(), parent_pid=os.getppid(),
                        started_at=time.time(), state='RUNNING', last_request=None,
                        last_completed=None, active_requests=0)

    def save(self):
        from .hook_state import no_links, atomic_bytes
        try:
            no_links(self.directory)
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Only our own fixed-shape files, at startup/exit, never on Stop.
            files = sorted(self.directory.glob('*.json'), key=lambda p: p.stat().st_mtime)
            for path in files[:-31]:
                if re.fullmatch(r'[a-f0-9]{32}\.json', path.name):
                    no_links(path)
                    path.unlink()
            atomic_bytes(self.path, json.dumps(self.row, separators=(',', ':')).encode())
        except (OSError, ValueError):
            pass  # Diagnostics cannot terminate a connection.

    async def call(self, original, name, arguments):
        label = name if isinstance(name, str) and re.fullmatch(r'[a-z_]{1,80}', name) else 'unknown'
        with self.lock:
            self.row.update(last_request=dict(tool=label, at=time.time()))
            self.row['active_requests'] += 1
        outcome = 'RAISED'
        try:
            result = await original(name, arguments)
            outcome = 'ERROR_RESULT' if getattr(result, 'isError', False) else 'RETURNED'
            return result
        finally:
            with self.lock:
                self.row['active_requests'] -= 1
                self.row['last_completed'] = dict(tool=label, at=time.time(), outcome=outcome)

    def finish(self, reason, code, error=None):
        self.row.update(state='EXITED', ended_at=time.time(), reason=reason, exit_code=code)
        if error is not None:
            # Types only: exceptions may contain source, paths or credentials.
            pending, names = [error], []
            while pending and len(names) < 8:
                item = pending.pop(0)
                names.append(type(item).__name__[:80])
                if isinstance(item, BaseExceptionGroup):
                    pending.extend(item.exceptions[:8])
            self.row['exception_types'] = names
            frames, trace = [], error.__traceback__
            while trace is not None and len(frames) < 8:
                filename = Path(trace.tb_frame.f_code.co_filename)
                if 'security_runtime' in filename.parts:
                    index = filename.parts.index('security_runtime')
                    frames.append(dict(module='/'.join(filename.parts[index:]), line=trace.tb_lineno))
                trace = trace.tb_next
            self.row['runtime_frames'] = frames
        self.save()


def run(serve):
    global CURRENT
    tracker = Lifecycle()
    CURRENT = tracker
    tracker.save()
    previous = {}
    received = None
    def interrupted(number, frame):
        nonlocal received
        received = number
        raise SystemExit(128 + number)
    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, interrupted)
    try:
        serve()
    except BaseException as error:
        code = error.code if isinstance(error, SystemExit) and type(error.code) is int else 1
        tracker.finish('SIGNAL' if received else 'UNHANDLED_EXCEPTION', code, error)
        raise
    else:
        tracker.finish('STDIO_ENDED', 0)  # Does not prove why the peer closed stdin.
    finally:
        CURRENT = None
        for number, handler in previous.items():
            signal.signal(number, handler)
