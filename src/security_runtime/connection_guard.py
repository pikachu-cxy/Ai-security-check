"""Independent next-prompt recovery of signed, same-session unfinished edits."""
import json
import sys
from pathlib import Path


def check(event, *, hooks=None):
    if not isinstance(event, dict) or event.get('hook_event_name') != 'UserPromptSubmit':
        return {}
    root, session = event.get('cwd'), event.get('session_id')
    if (not isinstance(root, str) or not Path(root).is_absolute() or
            not isinstance(session, str) or not 1 <= len(session) <= 500):
        return {}
    from .storage import SQLiteStore
    from .hook_state import HookStateStore, identity, no_links
    from .development_recovery import resume
    from .tasks.ownership import session_owner
    root = Path(root)
    no_links(root)
    root = root.resolve(strict=True)
    directory = SQLiteStore.default_path().parent / 'global-workspaces' / identity(str(root)) / 'hooks'
    # Never admit a workspace, create a key, or infer a different owner.
    if not directory.is_dir():
        return {}
    notice = resume(hooks or HookStateStore(directory), root, session_owner('codex', session))
    if not notice:
        return {}
    message = '正在恢复此前开发的安全检查，沿用原检查编号和已保存结果。'
    return dict(systemMessage=message, hookSpecificOutput=dict(hookEventName='UserPromptSubmit',
        additionalContext=message + '\n' + notice['reason']))


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        result = check(json.loads(raw)) if len(raw) <= 65536 else {}
    except (ValueError, OSError, KeyError, TypeError):
        result = {}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
