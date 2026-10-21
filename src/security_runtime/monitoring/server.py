"""Explicitly started loopback sidecar, with no product lifecycle dependency."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
from urllib.parse import parse_qs, urlsplit

from .service import MonitorService
from .page import page


class MonitorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, service, port=0):
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError('INVALID_LOCAL_PORT')
        self.service = service
        self.capability = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(24)
        super().__init__(('127.0.0.1', port), Handler)
        self.origin = 'http://127.0.0.1:' + str(self.server_port)
        self.prefix = '/' + self.capability
        self.url = self.origin + self.prefix + '/'


class Handler(BaseHTTPRequestHandler):
    server_version = 'LocalMonitor'

    def log_message(self, *_):
        pass  # Never log capability URLs, input or paths.

    def reply(self, status, value, content_type='application/json; charset=utf-8'):
        payload = value if isinstance(value, bytes) else value.encode('utf-8') if isinstance(value, str) else json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(payload)))
        if content_type == 'application/zip':
            self.send_header('Content-Disposition', 'attachment; filename="trial-consumption-report.zip"')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+self.server.nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def route(self):
        if self.headers.get('Host') != urlsplit(self.server.origin).netloc:
            return None
        split = urlsplit(self.path)
        if not split.path.startswith(self.server.prefix + '/'):
            return None
        return split.path[len(self.server.prefix):], parse_qs(split.query, max_num_fields=8)

    def do_GET(self):
        try:
            route = self.route()
            if route is None:
                return self.reply(403, dict(status='FORBIDDEN'))
            path, query = route
            if path == '/':
                return self.reply(200, page(self.server.nonce), 'text/html; charset=utf-8')
            if path == '/api/data':
                scope = query.get('scope', ['all'])[0]
                return self.reply(200, self.server.service.snapshot(scope))
            return self.reply(404, dict(status='NOT_FOUND'))
        except (ValueError, TypeError):
            return self.reply(400, dict(status='INVALID_REQUEST'))
        except Exception:
            return self.reply(503, dict(status='MONITOR_UNAVAILABLE'))

    def do_POST(self):
        try:
            route = self.route()
            if route is None or self.headers.get('Origin') != self.server.origin:
                return self.reply(403, dict(status='FORBIDDEN'))
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 1024 or self.headers.get('Content-Type') != 'application/json':
                return self.reply(400, dict(status='INVALID_REQUEST'))
            self.connection.settimeout(2)
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                return self.reply(400, dict(status='INVALID_REQUEST'))
            if route[0] == '/api/mode' and set(body) == {'mode'}:
                return self.reply(200, self.server.service.set_mode(body['mode']))
            if route[0] == '/api/task' and set(body) == {'action'}:
                return self.reply(200, self.server.service.task(body['action']))
            if route[0] == '/api/finish-export' and not body:
                from .report import report_bundle
                return self.reply(200, report_bundle(self.server.service.finish_report()), 'application/zip')
            if route[0] == '/api/stop' and not body:
                release = getattr(self.server.service, 'release_monitor', None)
                if release is not None:
                    release()
                self.reply(200, dict(status='AVAILABLE', stopped='MONITOR_ONLY'))
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            return self.reply(404, dict(status='NOT_FOUND'))
        except (ValueError, TypeError, TimeoutError):
            return self.reply(400, dict(status='INVALID_REQUEST'))
        except Exception:
            return self.reply(503, dict(status='MONITOR_UNAVAILABLE'))


def serve(store, *, project=None, chat_log=None, port=0):
    server = MonitorServer(MonitorService(store, project=project, chat_log=chat_log), port)
    print(json.dumps(dict(status='LISTENING', url=server.url, stop='Ctrl+C',
                         scope='OPTIONAL_LOOPBACK_MONITOR; NO_PROJECT_SCAN_OR_MODEL_REQUEST')), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
