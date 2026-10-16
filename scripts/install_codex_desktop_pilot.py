"""Project-only Codex pilot connection with byte-exact, compare-and-swap removal.

This installer does not trust hooks, change user configuration, start a model,
or assert that a native Codex event has been observed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import tomllib
from pathlib import Path

RUNTIME_ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(RUNTIME_ROOT / 'src'))

from security_runtime.codex_integration import product_hooks, unique_json
from security_runtime.global_toml import patch_server
from security_runtime.hook_state import atomic_bytes, no_links

VERSION = 'codex-desktop-pilot-install-v1'
MAX_BYTES = 262_144
FILES = ('.codex/config.toml', '.codex/hooks.json', 'AGENTS.md')
START = '<!-- BEGIN AI SECURITY RUNTIME DESKTOP PILOT V1 -->'
END = '<!-- END AI SECURITY RUNTIME DESKTOP PILOT V1 -->'
GUIDANCE = f'''{START}
This project explicitly opts into the experimental background security review.
For actual source/config development, before the first edit call
begin_security_task with a fresh task_key; retain its exact task_ref. Ordinary
chat/read-only work does not start a task. Reuse a supplied active task instead
of creating a second baseline, and never create a post-edit baseline to conceal
a missing one. Existing synchronous edit Hooks must complete normally.
After a meaningful coherent change (for example route plus authorization, or
input validation plus its caller), call prepare_security_batch with that task_ref
and a new checkpoint_key. Do not checkpoint every file or tool call. Continue
the authorized development while the trusted local pilot reviews that immutable
batch in the background. Its reader is restricted to the bound snapshot; do not
spawn another reviewer with inherited tools. A disabled/failed/limited reviewer
is a coverage gap, not a passed check. Do not wait for each intermediate batch.
Before the final development summary call finish_security_task, then
prepare_task_security_review if review_required. This retains the synchronous
task-scope static check and seals the intermediate queue. The main Codex agent
must read adequate final-version evidence with read_task_review_context and
submit_task_security_review using the returned submission_contract, including
integration_review and candidate dispositions when required. Do not replace this
final reasoning with an intermediate review or a zero-alert static result.
If source changes while final review is running, follow only the continuation
returned by Runtime. Retain STALE and uncovered ranges when review cannot be
completed; never restart a task or invent a post-edit baseline to clear the gap.
Never label stale candidates as current. Merge actual current risks and remaining
coverage gaps into the normal development summary. Review is not repair consent.
Use get_security_batches to inspect background work and
actual model usage; configuration status alone is not proof of execution.
{END}
'''


def _hash(raw):
    return hashlib.sha256(raw).hexdigest() if raw is not None else None


def _absolute(value, name):
    raw = str(value)
    if (not Path(raw).is_absolute() or raw.startswith(('\\\\', '//'))
            or '${' in raw or any(ord(c) < 32 for c in raw)):
        raise ValueError(f'{name}_PATH_INVALID')
    path = Path(os.path.abspath(raw))
    no_links(path)
    if path == Path(path.anchor) or path == Path.home():
        raise ValueError(f'{name}_PATH_INVALID')
    return path


def _locations(workspace, state_dir, runtime_root, home=None):
    root = _absolute(workspace, 'WORKSPACE')
    state = _absolute(state_dir, 'STATE')
    runtime = _absolute(runtime_root, 'RUNTIME')
    codex_home = _absolute(home or os.getenv('CODEX_HOME', Path.home() / '.codex'), 'CODEX_HOME')
    if not root.is_dir() or not runtime.is_dir():
        raise ValueError('WORKSPACE_OR_RUNTIME_MISSING')
    protected = [root, runtime, codex_home, Path.home() / '.codex',
                 Path.home() / '.ssh', Path.home() / '.aws', Path.home() / '.azure']
    if any(state == value or state.is_relative_to(value) for value in protected):
        raise ValueError('STATE_MUST_BE_OUTSIDE_PROJECT_SOURCE_AND_AUTH')
    if state in root.parents or state in runtime.parents:
        raise ValueError('STATE_MUST_NOT_CONTAIN_PROJECT_OR_RUNTIME')
    # Runtime may be a nested staging checkout. State never belongs inside an
    # enclosing source repository, including the user's original formal source.
    if any((parent / '.git').exists() for parent in (state, *state.parents)):
        raise ValueError('STATE_MUST_BE_OUTSIDE_SOURCE_REPOSITORIES')
    for name in FILES:
        no_links(root / name)
    receipt = state / ('project-install-' + _hash(os.path.normcase(str(root)).encode())[:24] + '.json')
    no_links(receipt)
    return root, state, runtime, codex_home, receipt


def _read(path, limit=MAX_BYTES):
    no_links(path)
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('CONFIGURATION_FILE_UNSUPPORTED')
    return path.read_bytes()


def _json(raw):
    value = unique_json(raw) if raw is not None else {'hooks': {}}
    if not isinstance(value, dict) or not isinstance(value.get('hooks'), dict):
        raise ValueError('HOOK_CONFIGURATION_INVALID')
    return value


def _toml(raw):
    return tomllib.loads(raw.decode('utf-8')) if raw is not None else {}


def _hooks_from_document(document):
    events = document.get('hooks', {})
    if not isinstance(events, dict):
        raise ValueError('HOOK_CONFIGURATION_INVALID')
    return {key: value for key, value in events.items() if key != 'state'}


def _hook_plan(global_json, global_toml, local_json, local_toml):
    import copy
    wanted = product_hooks()['hooks']
    sources = [_json(global_json)['hooks'], _hooks_from_document(_toml(global_toml)),
               _json(local_json)['hooks'], _hooks_from_document(_toml(local_toml))]
    result = copy.deepcopy(_json(local_json))
    reused, added = [], []
    for event, groups in wanted.items():
        goal = groups[0]
        handler = goal['hooks'][0]
        found = 0
        for events in sources:
            rows = events.get(event, [])
            if not isinstance(rows, list):
                raise ValueError('HOOK_CONFIGURATION_INVALID')
            for group in rows:
                if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                    raise ValueError('HOOK_CONFIGURATION_INVALID')
                for item in group['hooks']:
                    if (isinstance(item, dict) and item.get('type') == 'mcp_tool'
                            and item.get('server') == 'ai_security_runtime'
                            and item.get('tool') == handler['tool']):
                        if (group.get('matcher') != goal.get('matcher')
                                or item.get('input') != handler.get('input')):
                            raise ValueError('EXISTING_RUNTIME_HOOK_REQUIRES_REVIEW')
                        found += 1
        if found > 1:
            raise ValueError('DUPLICATE_RUNTIME_HOOKS')
        if found:
            reused.append(event)
        else:
            result['hooks'].setdefault(event, []).append(copy.deepcopy(goal))
            added.append(event)
    raw = ((json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
           if added else local_json)
    return raw, reused, added


def _server_block(python, entrypoint, root, state, codex):
    args = ['-I', str(entrypoint), '--workspace', str(root), '--state-dir', str(state)]
    if codex is not None:
        args += ['--codex', str(codex)]
    server = {'command': str(python), 'args': args, 'enabled': True, 'required': True,
              'startup_timeout_sec': 90, 'tool_timeout_sec': 180}
    lines = ['\n# Project-only experimental security connection.\n[mcp_servers.ai_security_runtime]']
    for name, value in server.items():
        lines.append(f'{name} = ' + (json.dumps(value, ensure_ascii=False)))
    lines.append('[mcp_servers.ai_security_runtime.env]')
    env = {'SECURITY_RUNTIME_GLOBAL': '0', 'SECURITY_RUNTIME_WORKSPACE': str(root),
           'SECURITY_RUNTIME_INTEGRATION': 'codex', 'SECURITY_RUNTIME_STATE_DIR': str(state),
           'SECURITY_RUNTIME_BATCH_REVIEW': '1'}
    for name, value in env.items():
        lines.append(f'{name} = {json.dumps(value, ensure_ascii=False)}')
    return ('\n'.join(lines) + '\n').encode('utf-8')


def _load_receipt(path, root):
    raw = _read(path, 2_000_000)
    if raw is None:
        return None
    value = unique_json(raw)
    if (not isinstance(value, dict) or value.get('version') != VERSION
            or value.get('workspace') != str(root) or value.get('phase') not in {'PREPARED', 'INSTALLED', 'REMOVED'}
            or set(value.get('files', {})) != set(FILES)):
        raise ValueError('PILOT_RECEIPT_INVALID')
    for row in value['files'].values():
        original = row.get('original_base64')
        try:
            original = base64.b64decode(original, validate=True) if original is not None else None
        except (ValueError, TypeError):
            raise ValueError('PILOT_RECEIPT_INVALID') from None
        if original is not None and len(original) > MAX_BYTES or _hash(original) != row.get('original_sha256'):
            raise ValueError('PILOT_RECEIPT_INVALID')
    return value


def _save_receipt(path, value):
    atomic_bytes(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _connection_observation(state, root):
    value = {'status': 'NOT_OBSERVED', 'startup_observed': False,
             'readiness_callback_observed': False, 'authority': 'RUNTIME_REPORTED'}
    try:
        raw = _read(state / 'pilot-connection.json', 16_384)
        if raw is None:
            return value
        observed = unique_json(raw)
        if not isinstance(observed, dict) or observed.get('workspace') != str(root):
            raise ValueError('OBSERVATION_BINDING_INVALID')
        for name in ('startup_observed', 'readiness_callback_observed'):
            if name in observed and type(observed[name]) is not bool:
                raise ValueError('OBSERVATION_SHAPE_INVALID')
            value[name] = observed.get(name, False)
        if value['readiness_callback_observed']:
            value['status'] = 'CALLBACK_REPORTED'
        elif value['startup_observed']:
            value['status'] = 'STARTUP_REPORTED'
        return value
    except (ValueError, OSError, TypeError, UnicodeError):
        return {**value, 'status': 'UNVERIFIABLE'}


def status(workspace, state_dir, *, runtime_root=RUNTIME_ROOT, home=None):
    root, state, runtime, codex_home, receipt = _locations(workspace, state_dir, runtime_root, home)
    saved = _load_receipt(receipt, root)
    if saved is None or saved['phase'] == 'REMOVED':
        return {'status': 'NOT_INSTALLED', 'workspace': str(root), 'native_events': 'NOT_OBSERVED_BY_INSTALLER'}
    drift = [name for name, row in saved['files'].items()
             if _hash(_read(root / name)) != row.get('installed_sha256')]
    observed = _connection_observation(state, root)
    callback = observed['status'] == 'CALLBACK_REPORTED'
    return {'status': ('CONFIGURATION_CHANGED' if drift else
                       'INSTALLED_CALLBACK_REPORTED' if callback else 'INSTALLED_NOT_OBSERVED'),
            'workspace': str(root), 'state_dir': str(state), 'changed_files': drift,
            'phase': saved['phase'], 'hooks_reused': saved['hooks_reused'],
            'hooks_added': saved['hooks_added'], 'connection_observation': observed,
            'native_events': 'RUNTIME_REPORTED_CALLBACK' if callback else 'NOT_OBSERVED_BY_INSTALLER',
            'requires_new_codex_session': True, 'project_trust': 'USER_REVIEW_IN_CODEX',
            'hook_trust': 'USER_REVIEW_IN_CODEX_REQUIRED_IF_UNTRUSTED'}


def install(workspace, state_dir, *, runtime_root=RUNTIME_ROOT, python=None, codex=None, home=None):
    root, state, runtime, codex_home, receipt = _locations(workspace, state_dir, runtime_root, home)
    old = _load_receipt(receipt, root)
    if old is not None and old['phase'] != 'REMOVED':
        return status(root, state, runtime_root=runtime, home=codex_home)
    executable = _absolute(python or sys.executable, 'PYTHON')
    entrypoint = runtime / 'scripts/codex_desktop_pilot.py'
    no_links(entrypoint)
    if not executable.is_file() or not entrypoint.is_file():
        raise ValueError('PILOT_LAUNCHER_MISSING')
    codex = _absolute(codex, 'CODEX') if codex is not None else None
    if codex is not None and not codex.is_file():
        raise ValueError('CODEX_EXECUTABLE_MISSING')
    before = {name: _read(root / name) for name in FILES}
    hooks, reused, added = _hook_plan(_read(codex_home / 'hooks.json'),
        _read(codex_home / 'config.toml'), before['.codex/hooks.json'], before['.codex/config.toml'])
    agents = (before['AGENTS.md'] or b'').decode('utf-8')
    if START in agents or END in agents:
        raise ValueError('UNOWNED_PILOT_GUIDANCE_PRESENT')
    desired = {'.codex/config.toml': patch_server(before['.codex/config.toml'] or b'',
                   _server_block(executable, entrypoint, root, state, codex)),
               '.codex/hooks.json': hooks,
               'AGENTS.md': (agents + ('\n' if agents and not agents.endswith('\n') else '')
                             + '\n' + GUIDANCE).encode('utf-8')}
    if any(raw is not None and len(raw) > MAX_BYTES for raw in desired.values()):
        raise ValueError('CONFIGURATION_FILE_TOO_LARGE')
    saved = {'version': VERSION, 'workspace': str(root), 'runtime_root': str(runtime),
             'phase': 'PREPARED', 'hooks_reused': reused, 'hooks_added': added, 'files': {}}
    for name in FILES:
        saved['files'][name] = {'original_base64': base64.b64encode(before[name]).decode('ascii')
                               if before[name] is not None else None,
                               'original_sha256': _hash(before[name]), 'installed_sha256': _hash(desired[name])}
    _save_receipt(receipt, saved)
    for name in FILES:
        if _read(root / name) != before[name]:
            raise ValueError('PROJECT_CONFIGURATION_CHANGED_DURING_INSTALL')
    for name in FILES:
        if desired[name] != before[name] and desired[name] is not None:
            atomic_bytes(root / name, desired[name])
    saved['phase'] = 'INSTALLED'
    _save_receipt(receipt, saved)
    return status(root, state, runtime_root=runtime, home=codex_home)


def remove(workspace, state_dir, *, runtime_root=RUNTIME_ROOT, home=None):
    root, state, runtime, codex_home, receipt = _locations(workspace, state_dir, runtime_root, home)
    saved = _load_receipt(receipt, root)
    if saved is None or saved['phase'] == 'REMOVED':
        return status(root, state, runtime_root=runtime, home=codex_home)
    for name, row in saved['files'].items():
        current = _hash(_read(root / name))
        permitted = {row['installed_sha256']}
        if saved['phase'] == 'PREPARED':
            permitted.add(row['original_sha256'])
        if current not in permitted:
            raise ValueError('ROLLBACK_REFUSED_PROJECT_CONFIGURATION_CHANGED')
    for name, row in saved['files'].items():
        raw = row['original_base64']
        if raw is None:
            (root / name).unlink(missing_ok=True)
        else:
            atomic_bytes(root / name, base64.b64decode(raw, validate=True))
    saved['phase'] = 'REMOVED'
    _save_receipt(receipt, saved)
    return status(root, state, runtime_root=runtime, home=codex_home)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'status', 'remove'])
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--runtime-root', default=str(RUNTIME_ROOT))
    parser.add_argument('--python')
    parser.add_argument('--codex')
    args = parser.parse_args(argv)
    kwargs = {'runtime_root': args.runtime_root}
    if args.action == 'install':
        kwargs.update(python=args.python, codex=args.codex)
    try:
        value = globals()[args.action](args.workspace, args.state_dir, **kwargs)
    except (ValueError, OSError) as exc:
        # Deliberately no source, original config bytes, or environment values.
        value = {'status': 'FAILED', 'reason': str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
        print(json.dumps(value, ensure_ascii=False))
        return 1
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
