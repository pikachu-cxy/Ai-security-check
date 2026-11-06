#!/usr/bin/env python3
"""Run Codex with loopback-only OTLP timing. Never persist prompts, headers or deltas."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading


def timing_rows(packet):
    for resource in packet.get('resourceLogs', []):
        for scope in resource.get('scopeLogs', []):
            for record in scope.get('logRecords', []):
                attrs = {v['key']: next(iter(v['value'].values()), '') for v in record.get('attributes', [])}
                name = attrs.get('event.name', record.get('eventName'))
                if name not in {'codex.api_request', 'codex.sse_event', 'codex.websocket_request', 'codex.websocket_event'}:
                    continue
                # Rust's tracing bridge can set event time to zero and supply
                # the local observation time in observedTimeUnixNano instead.
                ns = int(record.get('timeUnixNano') or 0) or int(record.get('observedTimeUnixNano') or 0)
                if not ns:
                    raise ValueError('missing local event timestamp')
                row = {'ns': ns, 'event': name}
                for key in ('event.kind', 'kind', 'duration_ms', 'attempt', 'http.status_code', 'success'):
                    value = attrs.get(key)
                    if value is not None and re.fullmatch(r'[A-Za-z0-9_.-]{1,96}', str(value)):
                        row[key] = value
                if name == 'codex.api_request' and 'duration_ms' in row:
                    row['request_start_estimate_ns'] = ns - int(row['duration_ms']) * 1_000_000
                yield row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('args', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    path = '/' + secrets.token_hex(20)
    with os.fdopen(os.open(options.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                size = int(self.headers.get('Content-Length', 0))
                if self.path != path or not 0 < size <= 8_000_000:
                    self.send_error(400)
                    return
                try:
                    for row in timing_rows(json.loads(self.rfile.read(size))):
                        output.write(json.dumps(row) + '\n')
                    output.flush()
                except (ValueError, TypeError, KeyError):
                    self.send_error(400)
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{}')

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            endpoint = f'http://127.0.0.1:{server.server_port}{path}'
            exporter = 'otel.exporter={otlp-http={protocol="json",endpoint="' + endpoint + '"}}'
            args = options.args[1:] if options.args[:1] == ['--'] else options.args
            try:
                return subprocess.call(['codex', '-c', exporter, '-c', 'otel.log_user_prompt=false', *args])
            finally:
                server.shutdown()


if __name__ == '__main__':
    raise SystemExit(main())
