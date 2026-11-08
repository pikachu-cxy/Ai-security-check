"""Process-local watcher control; remote callers hold a signed task capability.

Only loopback, bounded messages and three watcher lifecycle operations. No source,
path, scan, model or arbitrary function execution crosses this channel.
"""
import hmac
import json
import os
import secrets
import socket
import socketserver
import threading
import time

_lock = threading.Lock()
_server = None


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(('127.0.0.1', 0), _Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never log capability-bearing input or private paths.


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        try:
            raw = self.rfile.readline(4097)
            if len(raw) > 4096 or not raw.endswith(b'\n'):
                return
            value = json.loads(raw)
            if not isinstance(value, dict):
                return
            from . import development_file_watch as watching
            with watching._lock:
                window = next((w for w in watching._windows.values()
                               if w.id == value.get('id')), None)
                token = value.get('token')
                if (window is None or not isinstance(token, str) or len(token) != 64
                        or not hmac.compare_digest(window.control.get('token', ''), token)):
                    return
            current = window.store.load(window.ref, window.owner).get('file_watch', {})
            if current.get('id') != window.id or current.get('status') != 'ACTIVE':
                return
            operation = value.get('operation')
            invocation = value.get('invocation')
            if invocation is not None and (not isinstance(invocation, str) or len(invocation) > 256):
                return
            if operation == 'touch':
                with watching._lock:
                    if window.closing.is_set() or not window.thread.is_alive():
                        result = False
                    else:
                        window.last_activity = time.monotonic()
                        window.pending_tools.add(invocation)
                        result = True
            elif operation == 'complete':
                with watching._lock:
                    result = window.thread.is_alive() and not window.closing.is_set()
                    if result and invocation is not None and invocation in window.pending_tools:
                        window.pending_tools.remove(invocation)
                        window.quiet_since = time.monotonic()
            elif operation == 'stop':
                budget = value.get('budget')
                if type(budget) not in (int, float) or not 0 <= budget <= 600:
                    return
                watching.stop_window(window.store, window.ref, window.owner,
                                     deadline=time.monotonic()+budget)
                result = window.done.is_set()
            else:
                return
            self.wfile.write(json.dumps({'ok': result}).encode()+b'\n')
        except (OSError, ValueError, TypeError, RecursionError):
            return


def endpoint():
    global _server
    with _lock:
        if _server is None:
            _server = _Server()
            threading.Thread(target=_server.serve_forever, daemon=True,
                             name='watch-control').start()
        return dict(pid=os.getpid(), port=_server.server_address[1],
                    token=secrets.token_hex(32))


def request(watch, operation, *, invocation=None, budget=1):
    """None means unavailable, False means an authenticated owner declined."""
    control = watch.get('control') or {}
    port, token = control.get('port'), control.get('token')
    if (type(port) is not int or not 1 <= port <= 65535
            or not isinstance(token, str) or len(token) != 64):
        return None
    timeout = max(0.001, min(float(budget), 600))
    end = time.monotonic()+timeout
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as stream:
            stream.sendall(json.dumps(dict(id=watch['id'], token=token, operation=operation,
                                          invocation=invocation, budget=timeout)).encode()+b'\n')
            stream.settimeout(max(0.001, end-time.monotonic()))
            with stream.makefile('rb') as source:
                raw = source.readline(129)
            if len(raw) > 128 or not raw.endswith(b'\n'):
                return None
            result = json.loads(raw)
            return result['ok'] if isinstance(result, dict) and type(result.get('ok')) is bool else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def owner_lost(watch, now):
    """Absence from this process is never evidence of another owner's death."""
    pid = (watch.get('control') or {}).get('pid')
    if type(pid) is int and pid > 0:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
    return watch.get('lease_until', 0) <= now
