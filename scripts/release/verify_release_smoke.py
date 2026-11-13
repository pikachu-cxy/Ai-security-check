"""Fast native artifact gate; development regressions run before release dispatch."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import tomllib
from urllib.request import Request, build_opener, ProxyHandler, HTTPCookieProcessor
from http.cookiejar import CookieJar
from urllib.parse import urlsplit

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from security_runtime._version import __version__
from security_runtime.delivery import package_metadata
from security_runtime.toolchain import platform_key
from security_runtime.trial import TrialProfile, isolated_environment
from verify_artifact import extract, run


async def probe(executable: Path, root: Path, env: dict, expected_identity: dict, *,
                args: tuple[str, ...] = ('mcp',), verify_dashboard: bool = False) -> list[str]:
    with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as stderr:
        async with stdio_client(StdioServerParameters(
                command=str(executable), args=list(args), cwd=root, env=env), errlog=stderr) as (read, write):
            async with ClientSession(read, write) as client:
                await asyncio.wait_for(client.initialize(), timeout=30)
                names = sorted(tool.name for tool in (await client.list_tools()).tools)
                if 'start_risk_dashboard' not in names or 'start_usage_monitor' in names:
                    raise ValueError('Unexpected default MCP surface')
                result = await client.call_tool('get_runtime_info', {'view': 'summary'})
                if result.isError:
                    raise ValueError('Installed Runtime identity unavailable')
                data = result.structuredContent or json.loads(result.content[0].text)
                identity = data.get('result', data)['build_identity']
                if identity.get('status') != 'IDENTIFIED' or any(
                        identity.get(key) != expected_identity.get(key)
                        for key in ('version', 'build_id', 'source_commit')):
                    raise ValueError('Installed Runtime build identity mismatch')
                if not verify_dashboard:
                    return names
                dashboard = await client.call_tool('start_risk_dashboard', {})
                payload = dashboard.structuredContent or json.loads(dashboard.content[0].text)
                payload = payload.get('result', payload)
                if dashboard.isError or payload.get('status') != 'AVAILABLE':
                    raise ValueError('Native risk dashboard failed to start')
                parsed = urlsplit(payload['url'])
                if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1':
                    raise ValueError('Unexpected risk dashboard origin')
                with build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar())).open(payload['url'], timeout=5) as response:
                    if response.status != 200:
                        raise ValueError('Native risk dashboard page unavailable')
                return names


def main(archive: Path) -> None:
    started = time.monotonic()
    archive = archive.resolve()
    with tempfile.TemporaryDirectory(prefix='asr-', ignore_cleanup_errors=True) as temporary:
        root = Path(temporary).resolve()
        extract(archive, root)
        bundle = root / 'security-check'
        metadata = package_metadata(bundle)
        if metadata['version'] != __version__:
            raise ValueError('Artifact version mismatch')
        executable = bundle / ('security-check.exe' if os.name == 'nt' else 'security-check')
        profile = root / 'p'
        TrialProfile(profile).create()
        env = isolated_environment(profile)
        if os.name == 'nt':
            env.update(USERPROFILE=str(profile), HOME=str(profile),
                       LOCALAPPDATA=str(profile / 'AppData/Local'),
                       APPDATA=str(profile / 'AppData/Roaming'))
        env['SECURITY_RUNTIME_CONFIG'] = str(profile / 'product.toml')
        workbuddy = profile / 'workbuddy-home'
        workbuddy.mkdir()
        env['WORKBUDDY_CONFIG_DIR'] = str(workbuddy)
        env.pop('__PYVENV_LAUNCHER__', None)
        version = run([str(executable), '--version'], cwd=root, env=env).stdout.strip()
        if version != f'AI Security Runtime {__version__}':
            raise ValueError('Frozen entry point version mismatch')
        config = profile / 'codex-home/config.toml'
        retained = '# retained smoke setting\nmodel="smoke-user-model"\n'
        config.write_text(retained, encoding='utf-8')
        receipt = json.loads(run([str(executable), 'install', 'codex', '--root', str(profile / 'program'),
                                 '--offline', '--json'], cwd=root, env=env, timeout=180).stdout)
        if not receipt['installation']['local_files_ready'] or not config.read_text().startswith(retained):
            raise ValueError('Native installation or settings preservation failed')
        command = tomllib.loads(config.read_text())['mcp_servers']['ai_security_runtime']['command']
        try:
            names = asyncio.run(asyncio.wait_for(
                probe(Path(command), root, env, metadata, verify_dashboard=True), timeout=60))
            hosts = {}
            for host, required in [('codex', 'development_check'), ('cursor', 'begin_development_check')]:
                host_env = dict(env, SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_HOST=host,
                                SECURITY_RUNTIME_WORKSPACE='')
                host_names = asyncio.run(asyncio.wait_for(probe(Path(command), root, host_env, metadata), timeout=60))
                if required not in host_names or 'development_review' not in host_names:
                    raise ValueError('Supported host development tools missing')
                hosts[host] = host_names
            settings = workbuddy / 'settings.json'
            settings.write_text(json.dumps({'smoke_user_setting': True}), encoding='utf-8')
            workbuddy_receipt = json.loads(run([str(executable), 'install', 'workbuddy', '--root',
                str(profile / 'program'), '--offline', '--json'], cwd=root, env=env, timeout=180).stdout)
            installed_settings = json.loads(settings.read_text(encoding='utf-8'))
            if (not workbuddy_receipt['installation']['local_files_ready']
                    or workbuddy_receipt['skill']['status'] != 'INSTALLED'
                    or installed_settings.get('smoke_user_setting') is not True
                    or set(installed_settings['hooks']) != {'SessionStart', 'PreToolUse', 'PostToolUse', 'Stop'}):
                raise ValueError('WorkBuddy installation or settings preservation failed')
            entry = json.loads((workbuddy / 'mcp.json').read_text(encoding='utf-8'))['mcpServers']['ai-security-runtime']
            if entry['env'].get('SECURITY_RUNTIME_HOST') != 'workbuddy':
                raise ValueError('WorkBuddy MCP host configuration mismatch')
            hosts['workbuddy'] = asyncio.run(asyncio.wait_for(probe(Path(entry['command']), root,
                dict(env, **entry['env']), metadata, args=tuple(entry['args'])), timeout=60))
            if not {'development_check', 'development_review'} <= set(hosts['workbuddy']):
                raise ValueError('WorkBuddy development tools missing')
        finally:
            # Close only this isolated profile's service, including on probe failure.
            endpoint = Path(env['SECURITY_RUNTIME_STATE_DIR']) / 'dashboard/endpoint.json'
            if endpoint.exists():
                value = json.loads(endpoint.read_text())
                request = Request(f"http://127.0.0.1:{value['port']}/shutdown", data=b'',
                                  headers={'Authorization': 'Bearer '+value['token']}, method='POST')
                try:
                    with build_opener(ProxyHandler({})).open(request, timeout=5) as response:
                        response.read(1024)
                except OSError:
                    pass  # Already exited; the probe result remains authoritative.
        record = dict(version=__version__, source_commit=metadata['source_commit'],
                      platform='-'.join(platform_key()), archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                      smoke=True, validation_scope='native-install-startup-and-mcp-only',
                      local_files_ready=True, settings_preserved=True, usage_monitor_disabled=True,
                      native_dashboard_page=True, build_id=metadata['build_id'],
                      workbuddy_installation=True,
                      mcp_tools=names, global_host_tools=hosts, managed_engines=False,
                      development_regressions_repeated=False, scanner_run=False,
                      seconds=round(time.monotonic() - started, 3))
        archive.with_name(archive.name + '.verification.json').write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    main(parser.parse_args().archive)
