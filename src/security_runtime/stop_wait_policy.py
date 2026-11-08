"""Native transport limits, inspected only for opt-in extended waiting."""
import json
import os
from pathlib import Path
import tomllib
from .hook_state import no_links


INSTALLED_HOOK_TIMEOUT = 600
HEADROOM_SECONDS = 10


def host_limit():
    directory = Path(os.getenv('SECURITY_RUNTIME_CODEX_HOME', str(Path.home()/'.codex')))
    try:
        def read(name):
            path = directory/name
            no_links(path)
            with path.open('rb') as stream:
                raw = stream.read(262145)
            if len(raw) > 262144:
                raise ValueError('CONFIG_TOO_LARGE')
            return raw
        hooks = json.loads(read('hooks.json'))
        config = tomllib.loads(read('config.toml').decode('utf-8'))
        limits = [h.get('timeout', 600) for group in hooks.get('hooks', {}).get('Stop', [])
                  for h in group.get('hooks', []) if h.get('type') == 'mcp_tool'
                  and h.get('server') == 'ai_security_runtime' and h.get('tool') == 'handle_stop_event']
        if not limits:
            raise ValueError('STOP_HOOK_MISSING')
        limits.append(config['mcp_servers']['ai_security_runtime'].get('tool_timeout_sec', 60))
        if any(type(v) not in (int, float) or v <= HEADROOM_SECONDS for v in limits):
            raise ValueError('HOST_TIMEOUT_INVALID')
        ceiling = min(*limits, INSTALLED_HOOK_TIMEOUT)
        return dict(status='BOUNDED_HOST', unlimited_supported=False,
                    host_timeout_seconds=ceiling, effective_wait_seconds=ceiling-HEADROOM_SECONDS,
                    message=f'当前安装配置允许本次最多等待 {ceiling-HEADROOM_SECONDS:g} 秒；Codex 不保证无限等待。修改宿主配置后需重连。')
    except (OSError, ValueError, KeyError, TypeError):
        return dict(status='UNVERIFIED', unlimited_supported=False, host_timeout_seconds=None,
                    effective_wait_seconds=18, message='无法核验宿主等待配置，暂按 18 秒等待；请检查产品接入配置。')


def extended(row):
    from .user_config import batch_config
    return (batch_config(row)['development']['stop_fallback'].get('wait_mode') == 'wait_for_result'
            and row.get('owner', {}).get('host', 'codex') == 'codex')
