"""On-demand local health checks. Never imported by scanning or Stop."""
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import threading
import time

_LOCK = threading.Lock()
_CACHED = None


def _metadata(directory):
    try:
        path = directory / 'metadata.json'
        if path.stat().st_size > 64000:
            return {}
        value = json.loads(path.read_bytes())
        return {key: value[key] for key in ('Version', 'UpdatedAt', 'NextUpdate', 'DownloadedAt')
                if key in value and isinstance(value[key], (str, int))}
    except (OSError, ValueError, TypeError):
        return {}


async def _mcp_discover():
    from datetime import timedelta
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from .codex_integration import current_runtime, check_capabilities
    runtime = current_runtime()
    env = dict(os.environ, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_HOST='codex',
               SECURITY_RUNTIME_WORKSPACE='', SECURITY_RUNTIME_MCP_SELF_TEST='1')
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as errors:
        params = StdioServerParameters(command=runtime['command'],
            args=[*runtime['prefix'], 'mcp'], env=env)
        async with stdio_client(params, errlog=errors) as (reader, writer):
            async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=20)) as client:
                await client.initialize()
                tools = (await client.list_tools()).tools
                result = await client.call_tool('get_runtime_info', {'view': 'summary'})
                if result.isError:
                    raise ValueError('MCP_READ_FAILED')
                info = result.structuredContent or json.loads(result.content[0].text)
                check_capabilities(info, {tool.name for tool in tools})
                return dict(status='READY', version=info['version'], interfaces=[
                    dict(name=tool.name, status='READ_VERIFIED' if tool.name == 'get_runtime_info' else 'REGISTERED',
                         operations=tool.inputSchema.get('properties', {}).get('operation', {}).get('enum', []))
                    for tool in tools])


def probe_mcp():
    try:
        return asyncio.run(asyncio.wait_for(_mcp_discover(), timeout=30))
    except Exception:
        # Exception messages can contain commands, environment or credentials.
        return dict(status='UNAVAILABLE', interfaces=[], reason='MCP_PROBE_FAILED')


def collect(*, manager=None, mcp_probe=None):
    from ._version import __version__
    from .toolchain import ToolManager, ON_DEMAND_ENGINES
    from .install_readiness import validate_database_directory
    from .rulepacks import DEFAULT_RULE_PACK
    from .scan_preferences import preferences, section
    from .connection_lifecycle import diagnostics
    start = time.monotonic()
    manager = manager or ToolManager()
    base = Path(__file__).parent
    components = []
    with preferences():
        sast, secret = section('rules', 'sast'), section('rules', 'gitleaks')
        for name in manager.versions:
            try:
                value = manager.resolve(name)
                row = dict(name=name, status=str(value.status), version=value.version,
                           expected_version=manager.versions[name], path=value.path or str(manager.managed_path(name)),
                           optional=name in ON_DEMAND_ENGINES)
            except Exception:
                row = dict(name=name, status='UNKNOWN', version='', expected_version=manager.versions[name],
                           path='', optional=name in ON_DEMAND_ENGINES)
            if name in ('opengrep', 'semgrep'):
                row.update(rules=[str(base / 'rules')] if sast['mode'] == 'builtin' else
                    ([str(base / 'rules')] if sast['mode'] == 'extend' else []) + sast['paths'],
                    rule_version=DEFAULT_RULE_PACK.version if sast['mode'] != 'replace' else '自定义规则',
                    rule_status='CONFIGURED', rule_mode=sast['mode'])
            elif name == 'gitleaks':
                row.update(rules=[secret['config_path']] if secret['config_path'] else [],
                           rule_version='随工具版本内置', rule_status='CONFIGURED', rule_mode='custom' if secret['config_path'] else 'embedded')
            components.append(row)
        # Importability is a component check, not execution of a source scan.
        try:
            from . import dataflow
            native = dict(name='native-dataflow', status='READY', version=__version__,
                          path=str(Path(dataflow.__file__)), optional=False,
                          rules=[str(base / 'flow_core.py')], rule_version=__version__, rule_status='BUILTIN')
        except ImportError:
            native = dict(name='native-dataflow', status='UNAVAILABLE', version=__version__, path='', optional=False)
        components.append(native)
        db = manager.trivy_cache_dir() / 'db'
        fresh = manager.database_freshness()
        readable = validate_database_directory(db)
        database = dict(name='Trivy 漏洞库', path=str(db), metadata=_metadata(db),
                        freshness=fresh.get('status', 'UNKNOWN'), status='READY' if readable else 'UNAVAILABLE')
        java = manager.trivy_cache_dir() / 'java-db'
        java_database = dict(name='Trivy Java 索引（按需）', path=str(java), metadata=_metadata(java),
                             status='PRESENT' if (java / 'trivy-java.db').is_file() else 'MISSING')
    mcp = (mcp_probe or probe_mcp)()
    try:
        connections = [{key: item.get(key) for key in ('started_at', 'ended_at', 'state', 'reason', 'exit_code', 'last_request', 'last_completed', 'exception_types', 'runtime_frames')}
                       for item in diagnostics()['records']]
    except (ValueError, OSError):
        connections = []
    healthy = all(c['status'] == 'READY' for c in components if not c['optional']) and readable and fresh.get('status') == 'FRESH' and mcp['status'] == 'READY'
    return dict(contract='dashboard-health-v1', checked_at=time.time(), elapsed_seconds=time.monotonic()-start,
                product=dict(status='READY' if healthy else 'ATTENTION', version=__version__, web='READY',
                             path=str(base), desktop_connection='UNKNOWN'), components=components,
                databases=[database, java_database], mcp=mcp, connections=connections, scanner_run=False)


def _history(value):
    from .dashboard_service import directory
    from .hook_state import no_links, atomic_bytes
    path = directory() / 'health-history.json'
    rows = []
    try:
        no_links(path)
        if path.is_file() and path.stat().st_size <= 131072:
            data = json.loads(path.read_bytes())
            if isinstance(data, list):
                rows = [r for r in data if isinstance(r, dict)][-15:]
        rows.append(dict(checked_at=value['checked_at'], status=value['product']['status'],
                         mcp=value['mcp']['status'], elapsed_seconds=value['elapsed_seconds'],
                         components={r['name']: r['status'] for r in value['components']}))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_bytes(path, json.dumps(rows).encode())
        return rows
    except (OSError, ValueError, TypeError):
        return rows


def snapshot():
    """Coalesce browser refreshes; work only on demand, at most once per 30s."""
    global _CACHED
    if not _LOCK.acquire(blocking=False):
        return dict(deepcopy(_CACHED) if _CACHED else {}, checking=True)
    try:
        if _CACHED and time.time() - _CACHED['checked_at'] < 30:
            return deepcopy(_CACHED)
        value = collect()
        value['history'] = _history(value)
        _CACHED = value
        return deepcopy(value)
    finally:
        _LOCK.release()
