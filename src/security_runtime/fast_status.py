"""Cheap saved-config facts only: never claim ownership, integrity or a live connection."""
import json
import tomllib
from .global_integration import codex_home
from .hook_state import no_links


def codex_saved_status():
    home = codex_home()
    result = dict(integration='codex', scope='GLOBAL', verification='NOT_REVALIDATED',
                  live_connection='NOT_REVALIDATED', ownership='NOT_REVALIDATED', scanner_run=False)
    documents = []
    for name, parser in [('config.toml', tomllib.loads), ('hooks.json', json.loads)]:
        path = home/name
        no_links(path)
        if not path.exists():
            documents.append({})
            continue
        with path.open('rb') as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError('SAVED_CONFIG_TOO_LARGE')
        document = parser(raw.decode('utf-8'))
        if not isinstance(document, dict):
            raise ValueError('SAVED_CONFIG_INVALID')
        documents.append(document)
    config, hooks = documents
    result.update(mcp_entry_present='ai_security_runtime' in config.get('mcp_servers', {}),
                  saved_hook_events=sorted(name for name in hooks.get('hooks', {})
                                          if name in {'SessionStart','PreToolUse','PostToolUse','Stop'}))
    return result
