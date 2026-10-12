"""Fresh installed MCP identity and ordinary read-only root probe; never Hook events."""
import asyncio
from datetime import timedelta
import json
import os
from pathlib import Path
import time

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BASE = Path(__file__).resolve().parents[1] / 'artifacts/workspace-root-fix-20261012'
LAUNCHER = Path(os.environ['LOCALAPPDATA']) / 'AI-Security-Runtime-install/launcher-v2/security-check.exe'
WRAPPER = Path(r'C:\Users\24170\Downloads\FlyCRM-AI-feat-ai-chat')


def value(response):
    payload = response.structuredContent
    if payload is None:
        payload = json.loads(next(item.text for item in response.content if item.type == 'text'))
    return {'is_error': bool(response.isError), 'response': payload}


async def main():
    env = {name: item for name, item in os.environ.items()
           if not name.startswith('SECURITY_RUNTIME_') and name not in {'PYTHONHOME', 'PYTHONPATH'}}
    env.update(SECURITY_RUNTIME_GLOBAL='1', SECURITY_RUNTIME_OFFLINE='1',
               SECURITY_RUNTIME_INTEGRATION='codex', PYTHONUTF8='1')
    started = time.perf_counter()
    with (BASE / 'fresh-installed-mcp-stderr.log').open('w', encoding='utf-8') as errors:
        async with stdio_client(StdioServerParameters(command=str(LAUNCHER), args=['mcp'],
            cwd=str(Path(__file__).resolve().parents[1]), env=env), errlog=errors) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=60)) as client:
                await client.initialize()
                identity = value(await client.call_tool('get_runtime_info', {}))
                wrapper = value(await client.call_tool('get_security_summary', {'workspace_path': str(WRAPPER)}))
    result = {'method': 'ACTUAL_FRESH_INSTALLED_STABLE_LAUNCHER_MCP_STDIO',
              'elapsed_ms': round((time.perf_counter()-started)*1000, 3),
              'runtime_info': identity, 'wrapper_read_only_summary_request': wrapper,
              'codex_current_connection_reconnected': False, 'automatic_hook_acceptance': '尚未通过',
              'hook_handlers_called': [], 'manual_scan_performed': False,
              'interpretation': 'New process identity and normal root rejection only; not SessionStart/PostToolUse proof.'}
    path = BASE / 'fresh-installed-mcp.json'
    if path.exists():
        raise ValueError('Preserve previous evidence')
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'build_identity': identity['response'].get('build_identity'),
        'runtime_executable': identity['response'].get('runtime_executable'),
        'wrapper_result': wrapper, 'automatic_hook_acceptance': '尚未通过'}, ensure_ascii=False))


if __name__ == '__main__':
    asyncio.run(main())
