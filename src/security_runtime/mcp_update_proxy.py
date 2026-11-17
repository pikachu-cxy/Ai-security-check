"""Keep an installed global MCP stdio connection across compatible updates."""
import hashlib
import json
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import subprocess
import sys
from threading import Event, Thread
import time
import uuid

from .delivery import EXE, package_metadata

CONTRACT = 'runtime-mcp-proxy-v1'
RESTORE = '_runtime_proxy_restore'
# Compatibility is conservative: a change in an installed host entry point or
# event adapter requires reconnecting even when its external schema is unchanged.
HOOK_SOURCES = (
    'codex_integration.py', 'codex_mcp_hook.py', 'codex_event_adapter.py', 'connection_guard.py',
    'cursor_integration.py', 'cursor_automatic.py', 'cursor_event_adapter.py',
    'workbuddy_integration.py', 'workbuddy_hook.py', 'host_event_runtime.py', 'host_events.py',
)


def hook_identity(package):
    digest = hashlib.sha256()
    for name in HOOK_SOURCES:
        digest.update(name.encode())
        digest.update(hashlib.sha256((package / name).read_bytes()).digest())
    return digest.hexdigest()


def compatible(old, new):
    fields = ('mcp_proxy_contract', 'mcp_hook_identity', 'storage_contracts', 'state_schema', 'launcher_contract')
    return (old.get('mcp_proxy_contract') == CONTRACT and all(field in old for field in fields)
            and all(old[field] == new.get(field) for field in fields))


def structured(message):
    result = message.get('result', {})
    return result.get('structuredContent') or {}


def read_messages(stream, emit):
    try:
        for line in stream:
            try:
                message = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(message, dict):
                emit(message)
    finally:
        emit(None)


def send(stream, message):
    stream.write(json.dumps(message, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')
    stream.flush()


class Backend:
    def __init__(self, command):
        self.restore_key = secrets.token_hex(32)
        environment = dict(os.environ, SECURITY_RUNTIME_MCP_PROXY_CHILD='1',
                           SECURITY_RUNTIME_MCP_PROXY_KEY=self.restore_key)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=environment)
        self.events = Queue()
        self.relay = None
        Thread(target=read_messages, args=(self.process.stdout, self.receive), daemon=True).start()

    def receive(self, message):
        if self.relay is None:
            self.events.put(message)
        else:
            self.relay(message)

    def request(self, method, params, deadline):
        identity = uuid.uuid4().hex
        self.send(dict(jsonrpc='2.0', id=identity, method=method, params=params))
        while True:
            message = self.events.get(timeout=max(0, deadline - time.monotonic()))
            if message is None or time.monotonic() > deadline or 'method' in message and 'id' in message:
                raise ValueError('MCP_PROXY_PROBE_UNAVAILABLE')
            if message.get('id') == identity:
                if 'error' in message or message.get('result', {}).get('isError'):
                    raise ValueError('MCP_PROXY_PROBE_REJECTED')
                return message

    def send(self, message):
        send(self.process.stdin, message)

    def close(self):
        try:
            self.process.stdin.close()
        except OSError:
            pass
        Thread(target=self.process.wait, daemon=True).start()


def command(bundle):
    return [str(bundle / EXE), 'mcp']


def negotiation(message):
    result = message.get('result', {})
    info = {k: v for k, v in result.get('serverInfo', {}).items() if k != 'version'}
    return dict(result, serverInfo=info)


def caller_route(params):
    args = params.get('arguments') or {}
    if not isinstance(args, dict):
        return None
    args = args.get('arguments', args)
    if isinstance(args, dict) and isinstance(args.get('workspace_path'), str) and isinstance(args.get('session_ref'), str):
        return args['workspace_path'], args['session_ref']
    return None


class Proxy:
    def __init__(self, update, initial, *, backend=Backend):
        self.update = update
        self.metadata = initial
        self.backend_factory = backend
        self.events = Queue()
        self.server = backend(command(update.delivery.slot(initial['build_id'])))
        self.bind(self.server)
        self.client_requests = {}
        self.server_requests = set()
        self.routes = set()
        self.native_routes = set()
        self.routing_unknown = False
        self.init = None
        self.hello = None
        self.tools = None
        self.resources = None
        self.initialized = False
        self.rejected = None
        self.warming = None
        self.ready = Queue()
        self.stopped = Event()
        self.observed_pointer = self.pointer_stamp() if update.active()['build_id'] == initial['build_id'] else None

    def pointer_stamp(self):
        try:
            info = (self.update.delivery.root / 'active.json').stat()
            return info.st_mtime_ns, info.st_ctime_ns, info.st_size
        except OSError:
            return None

    def bind(self, backend):
        backend.relay = lambda message: self.events.put((backend, message))
        while not backend.events.empty():
            backend.relay(backend.events.get_nowait())

    def candidate(self, snapshot):
        hello, init, expected_tools, expected_resources, routes = snapshot
        incoming = self.update.active()
        build = incoming['build_id']
        if build in {self.metadata['build_id'], self.rejected} or not compatible(self.metadata, incoming):
            return None
        self.rejected = build
        slot = self.update.delivery.slot(build)
        incoming = package_metadata(slot)
        if incoming['build_id'] != build or not compatible(self.metadata, incoming):
            return None
        child = self.backend_factory(command(slot))
        deadline = time.monotonic() + 5
        try:
            if negotiation(child.request('initialize', init, deadline)) != hello:
                raise ValueError('MCP_PROXY_NEGOTIATION_CHANGED')
            child.send(dict(jsonrpc='2.0', method='notifications/initialized'))
            tools = child.request('tools/list', {}, deadline)['result']
            resources = (child.request('resources/list', {}, deadline)['result']
                         if 'resources' in hello.get('capabilities', {}) else None)
            if (tools != expected_tools or tools.get('nextCursor')
                    or expected_resources is not None and resources != expected_resources
                    or resources is not None and resources.get('nextCursor')):
                raise ValueError('MCP_PROXY_DISCOVERY_CHANGED')
            info = structured(child.request('tools/call', dict(name='get_runtime_info',
                              arguments={'view': 'summary'}), deadline))
            if (info.get('build_identity') or {}).get('build_id') != build:
                raise ValueError('MCP_PROXY_WRONG_BUILD')
            for workspace, ref in sorted(routes):
                args = dict(workspace_path=workspace, session_ref=ref)
                proof = structured(child.request('tools/call', dict(name=RESTORE,
                    arguments=dict(args, key=child.restore_key)), deadline))
                if not proof.get('routing_binding_confirmed'):
                    raise ValueError('MCP_PROXY_ROUTE_UNVERIFIED')
            if self.update.active()['build_id'] != build:
                raise ValueError('MCP_PROXY_ACTIVE_CHANGED')
            return child, incoming
        except (OSError, ValueError, KeyError, TypeError, Empty, subprocess.SubprocessError):
            child.close()
            return None

    def prepare(self, snapshot):
        try:
            candidate = self.candidate(snapshot)
        except (OSError, ValueError, KeyError, TypeError):
            candidate = None
        if self.stopped.is_set() and candidate:
            candidate[0].close()
        else:
            self.ready.put((snapshot, candidate))

    def maybe_switch(self):
        if (self.client_requests or self.server_requests or self.routing_unknown or not self.initialized
                or self.hello is None or self.tools is None):
            return
        snapshot = (self.hello, self.init, self.tools, self.resources, frozenset(self.routes))
        try:
            prepared, candidate = self.ready.get_nowait()
        except Empty:
            if self.warming is None:
                pointer = self.pointer_stamp()
                if pointer is None or pointer == self.observed_pointer:
                    return
                self.observed_pointer = pointer
                self.warming = Thread(target=self.prepare, args=(snapshot,), daemon=True)
                self.warming.start()
            return
        self.warming = None
        if (candidate and prepared == snapshot and self.events.empty()
                and self.pointer_stamp() == self.observed_pointer):
            old = self.server
            self.server, self.metadata = candidate
            self.bind(self.server)
            old.close()
        elif candidate:
            # Events from the current backend arrived during preflight. Keep its
            # connection and retry only at another genuinely idle boundary.
            candidate[0].close()
            self.rejected = None
            self.observed_pointer = None

    def from_host(self, message):
        method = message.get('method')
        params = message.get('params') or {}
        identity = message.get('id')
        if method and identity is not None:
            self.maybe_switch()
            if method == 'initialize':
                self.init = params
            self.client_requests[identity] = method, params
        elif method == 'notifications/initialized':
            self.initialized = True
        # Release server-initiated request only when its reply is forwarded.
        self.server.send(message)
        if not method:
            self.server_requests.discard(identity)

    def from_backend(self, message):
        identity = message.get('id')
        if identity is None:
            if message.get('method') == 'notifications/tools/list_changed':
                self.tools = None
            elif message.get('method') == 'notifications/resources/list_changed':
                self.resources = None
            return
        if message.get('method'):
            self.server_requests.add(identity)
            return
        method, params = self.client_requests.pop(identity, ('', {}))
        if 'result' not in message:
            return
        if method == 'initialize':
            self.hello = negotiation(message)
        elif method == 'tools/list' and not params.get('cursor'):
            self.tools = message['result']
        elif method == 'resources/list' and not params.get('cursor'):
            self.resources = message['result']
        elif method == 'tools/call' and not message['result'].get('isError'):
            args = params.get('arguments') or {}
            if not isinstance(args, dict):
                return
            token = structured(message).get('task_session_ref')
            route = caller_route(params)
            if not route and isinstance(token, str) and isinstance(args.get('workspace_path'), str):
                route = (args['workspace_path'], token)
                if isinstance(args.get('session_id'), str):
                    self.native_routes.add((args['workspace_path'], args['session_id']))
            if route:
                self.routes.add(route)
                if len(self.routes) > 16:
                    self.routing_unknown = True
            elif ((args.get('workspace_path') or (isinstance(args.get('arguments'), dict)
                                                  and args['arguments'].get('workspace_path')))
                  and (args.get('workspace_path'), args.get('session_id')) not in self.native_routes):
                self.routing_unknown = True

    def run(self, stdin, stdout):
        Thread(target=read_messages, args=(stdin, lambda message: self.events.put((None, message))),
               daemon=True).start()
        try:
            while True:
                source, message = self.events.get()
                if source not in (None, self.server):
                    continue
                if message is None:
                    break
                if source is None:
                    self.from_host(message)
                else:
                    self.from_backend(message)
                    send(stdout, message)
        finally:
            self.stopped.set()
            while not self.ready.empty():
                _, candidate = self.ready.get_nowait()
                if candidate:
                    candidate[0].close()
            self.server.close()


def serve_proxy():
    if (os.getenv('SECURITY_RUNTIME_GLOBAL') != '1'
            or os.getenv('SECURITY_RUNTIME_MCP_PROXY_CHILD') == '1'
            or os.getenv('SECURITY_RUNTIME_MCP_SELF_TEST') == '1'):
        return False
    from .runtime_update import installed_update
    update = installed_update()
    if update is None:
        return False
    try:
        initial = package_metadata(update.delivery.slot(update.running_build))
        if initial.get('mcp_proxy_contract') != CONTRACT:
            return False
        proxy = Proxy(update, initial)
    except (OSError, ValueError):
        return False
    proxy.run(sys.stdin.buffer, sys.stdout.buffer)
    return True
