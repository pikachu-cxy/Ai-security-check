"""Thin lifecycle translation and project config; no scanner or delta logic."""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Protocol

from .hook_runtime import HOSTS, HookCoordinator
from .hook_state import atomic_bytes, no_links
from .hook_user_feedback import scan_status_feedback
from .hooks import HookEvent
from .mcp_config import resolve_runtime_command
from .workspace import WorkspaceResolver

MARKER = 'AI Security Runtime [hook-v1]'
COMMAND_MARKER = 'ai-security-runtime-hook-v1'
CODEX_EVENTS = {'SessionStart':HookEvent.SESSION_START,'PostToolUse':HookEvent.FILE_CHANGED,'Stop':HookEvent.AGENT_STOP}


class HostHookAdapter(Protocol):
    host: str
    def translate(self, payload: dict, workspace: Path) -> tuple[HookEvent,str | None]: ...
    def config(self, workspace: Path) -> dict: ...


def command(workspace: Path, host: str, event: str) -> str:
    runtime = resolve_runtime_command()
    args = [runtime.command,*runtime.args[:-1], 'hook',event,'--path',str(workspace),'--host',host,'--json']
    if event == 'host-event':
        args += ['--stdin']
    if host == 'cursor':
        args += ['--adapter-id',COMMAND_MARKER]
    if os.name == 'nt':
        # cmd expands percent/exclamation even inside double quotes. Refuse
        # unrepresentable installation paths rather than creating executable
        # configuration containing interpolated shell input.
        if any(any(c in value for c in '%!"\r\n') for value in args):
            raise ValueError('Runtime/workspace path cannot be safely represented in a Windows hook command')
        return ' '.join('"'+value+'"' for value in args)
    return shlex.join(args)


class CodexHookAdapter:
    host = 'codex'
    config_relative = '.codex/hooks.json'

    def translate(self,payload,workspace):
        if not isinstance(payload,dict):
            raise ValueError('Invalid host hook payload')
        event = CODEX_EVENTS.get(payload.get('hook_event_name'))
        if event is None:
            raise ValueError('Unsupported Codex hook event')
        if event == HookEvent.FILE_CHANGED and payload.get('tool_name') not in {'Bash','apply_patch','Edit','Write'}:
            raise ValueError('Unsupported Codex edit event')
        cwd = payload.get('cwd')
        if not isinstance(cwd,str) or WorkspaceResolver().resolve(
                cwd, allow_non_git_explicit=True, allow_non_git_source=True).path != workspace:
            raise ValueError('Host event does not belong to configured workspace')
        session = payload.get('session_id')
        if not isinstance(session,str) or not session or len(session)>500:
            raise ValueError('Invalid host session identity')
        # Ignore transcript_path, tool_input/response, model and assistant text.
        # None is source data for commands, metadata state or model prompts.
        return event,session

    def config(self,workspace):
        handler = {'type':'command','command':command(workspace,self.host,'host-event'),
                   'timeout':120,'statusMessage':MARKER}
        return {'SessionStart':[{'hooks':[dict(handler)]}],
                'PostToolUse':[{'matcher':'^(Bash|apply_patch|Edit|Write)$','hooks':[dict(handler)]}],
                'Stop':[{'hooks':[dict(handler)]}]}

    def output(self,payload,result):
        display = scan_status_feedback(result)
        value = {'systemMessage':display['message']}
        if payload['hook_event_name'] in {'SessionStart','PostToolUse'}:
            # Small fixed metadata only. This is not a request to continue or
            # block the turn, nor an automatic MCP/model invocation.
            value['hookSpecificOutput'] = {'hookEventName':payload['hook_event_name'],
                'additionalContext':json.dumps({**{k:result[k] for k in ('status','scan_id','coverage','execution','baseline_available')},
                                               'reply_plan':display['reply_plan']})}
        return value


class CursorHookAdapter:
    host = 'cursor'
    config_relative = '.cursor/hooks.json'
    events = {'sessionStart':HookEvent.SESSION_START,'afterFileEdit':HookEvent.FILE_CHANGED,'stop':HookEvent.AGENT_STOP}

    def translate(self,payload,workspace):
        if not isinstance(payload,dict) or payload.get('hook_event_name') not in self.events:
            raise ValueError('Unsupported Cursor lifecycle payload')
        roots = payload.get('workspace_roots')
        if not isinstance(roots,list) or not 1 <= len(roots) <= 50 or not all(isinstance(r,str) for r in roots):
            raise ValueError('Invalid Cursor workspace binding')
        if workspace not in {WorkspaceResolver().resolve(r).path for r in roots}:
            raise ValueError('Host event does not belong to configured workspace')
        session = payload.get('conversation_id')
        if not isinstance(session,str) or not session or len(session)>500:
            raise ValueError('Invalid Cursor conversation identity')
        # Ignore edit strings, file contents, transcript and model fields.
        return self.events[payload['hook_event_name']],session

    def config(self,workspace):
        return {event:[{'command':command(workspace,self.host,'host-event'),'type':'command','timeout':120}]
                for event in self.events}

    def output(self,payload,result):
        if payload['hook_event_name']=='sessionStart':
            return {'additional_context':json.dumps({k:result[k] for k in ('status','scan_id','coverage','baseline_available','execution')})}
        # afterFileEdit has no documented output contract, and stop's only
        # output would auto-submit another prompt. Advisory checks do neither.
        return {}


def run_host_event(payload,workspace,host,coordinator=None):
    adapters={'codex':CodexHookAdapter(),'cursor':CursorHookAdapter()}
    if host not in adapters:
        raise ValueError('Host payload schema is not implemented; use neutral hook commands')
    root = WorkspaceResolver().resolve(workspace).path
    adapter = adapters[host]
    event,session = adapter.translate(payload,root)
    if host == 'codex':
        from .codex_event_adapter import CodexEventAdapter
        from .host_event_runtime import handle_normalized_event
        args = dict(event=payload['hook_event_name'], workspace_path=payload['cwd'],
                    session_id=session, tool_name=payload.get('tool_name'),
                    tool_input=payload.get('tool_input'), stop_hook_active=payload.get('stop_hook_active', False))
        normalized = CodexEventAdapter().normalize(args, root, legacy=True)
        result, _ = handle_normalized_event(normalized, coordinator=coordinator or HookCoordinator())
    else:
        # Existing Cursor command/config support is not a normalized adapter v1.
        result = (coordinator or HookCoordinator()).handle(event,root,host,session)
    return adapter.output(payload,result)


class HookIntegrationRegistry:
    def __init__(self):
        self.adapters = {'codex':CodexHookAdapter(),'cursor':CursorHookAdapter()}

    def _load(self,root,adapter):
        path = root / adapter.config_relative
        no_links(path)
        config = root / '.codex/config.toml'
        no_links(config)
        if adapter.host == 'codex' and config.exists():
            import tomllib
            try:
                if config.stat().st_size > 1_000_000:
                    raise ValueError()
                tomllib.loads(config.read_text(encoding='utf-8-sig'))
            except (ValueError,UnicodeError):
                raise ValueError('Existing Codex configuration is invalid; no changes made') from None
        if not path.exists():
            return path,{'version':1,'hooks':{}} if adapter.host=='cursor' else {'hooks':{}}
        try:
            if path.stat().st_size > 1_000_000:
                raise ValueError()
            value = json.loads(path.read_text(encoding='utf-8-sig'))
            if not isinstance(value,dict) or not isinstance(value.get('hooks'),dict):
                raise ValueError()
            if adapter.host=='cursor' and value.get('version')!=1:
                raise ValueError()
            for groups in value['hooks'].values():
                if not isinstance(groups,list):
                    raise ValueError()
                for group in groups:
                    if not isinstance(group,dict):
                        raise ValueError()
                    if adapter.host=='codex' and (not isinstance(group.get('hooks'),list) or any(not isinstance(h,dict) for h in group['hooks'])):
                        raise ValueError()
                    if adapter.host=='cursor' and not isinstance(group.get('command'),str):
                        raise ValueError()
            return path,value
        except (ValueError,UnicodeError):
            raise ValueError('Existing hook configuration is invalid; no changes made') from None

    @staticmethod
    def _remove_owned(value,host='codex'):
        for event,groups in list(value['hooks'].items()):
            if host=='cursor':
                kept=[h for h in groups if COMMAND_MARKER not in h.get('command','')]
                if kept:
                    value['hooks'][event]=kept
                else:
                    del value['hooks'][event]
                continue
            kept = []
            for group in groups:
                handlers = [h for h in group['hooks'] if h.get('statusMessage') != MARKER]
                if handlers:
                    kept.append(dict(group,hooks=handlers))
                elif not any(h.get('statusMessage') == MARKER for h in group['hooks']):
                    kept.append(group)
                elif set(group) - {'hooks','matcher'}:
                    kept.append(dict(group,hooks=[]))
            if kept:
                value['hooks'][event] = kept
            else:
                del value['hooks'][event]

    def manage(self,action,host,workspace):
        if action != 'status' and host in self.adapters:
            from .hook_state import HookStateStore
            root = WorkspaceResolver().resolve(workspace).path
            with HookStateStore().lock(root,wait_seconds=2) as locked:
                if not locked:
                    raise ValueError('Workspace hook operation is busy; retry configuration update')
                return self._manage(action,host,root)
        return self._manage(action,host,workspace)

    def _manage(self,action,host,workspace):
        root = WorkspaceResolver().resolve(workspace).path
        if host not in HOSTS:
            raise ValueError('Unknown hook host')
        if host not in self.adapters:
            return {'host':host,'status':'MANUAL_CONFIGURATION_REQUIRED','schema_verified':False,
                'commands':{e:command(root,host,e) for e in ('session-start','file-changed','agent-stop')},
                'message':'Official lifecycle schema has not been validated for this Runtime adapter. No host configuration was written.'}
        adapter = self.adapters[host]
        path,value = self._load(root,adapter)
        created = not path.exists()
        expected = adapter.config(root)
        if action == 'status':
            actual = {e:[g for g in value['hooks'].get(e,[]) if
                (COMMAND_MARKER in g.get('command','') if host=='cursor' else any(h.get('statusMessage') == MARKER for h in g['hooks']))] for e in expected}
            exact = actual == expected
            return {'host':host,'status':'CONFIG_ONLY' if exact else 'NOT_IMPLEMENTED' if not path.exists() else 'NEEDS_REPAIR',
                'implementation':'IMPLEMENTED','schema_verified':True,'config_path':str(path),
                'fresh_host_trial':'PENDING','message':'Review/trust these project hooks in Codex and start a fresh session; generated configuration is not host execution proof.'}
        if action not in {'install','repair','remove'}:
            raise ValueError('Invalid hook configuration action')
        original = json.loads(json.dumps(value))
        original_bytes = path.read_bytes() if path.exists() else None
        self._remove_owned(value,host)
        if action != 'remove':
            for event,groups in expected.items():
                value['hooks'].setdefault(event,[]).extend(groups)
        if value != original:
            atomic_bytes(path,(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode())
        from .integration_config import IntegrationConfigStore
        local = IntegrationConfigStore(root,adapter.config_relative)
        try:
            if action != 'remove' and (created or value == ({'version':1,'hooks':expected} if host=='cursor' else {'hooks':expected})):
                local._local_exclude(add=True)
            elif action == 'remove':
                owned = local._local_exclude()
                from .git import GitService
                tracked = GitService(root)._run('ls-files','--',adapter.config_relative)
                empty = value == ({'version':1,'hooks':{}} if host=='cursor' else {'hooks':{}})
                if owned and not tracked and empty:
                    path.unlink(missing_ok=True)
                local._local_exclude(add=False)
        except Exception:
            if original_bytes is None:
                path.unlink(missing_ok=True)
            else:
                atomic_bytes(path,original_bytes)
            raise
        return {'host':host,'status':'CONFIG_ONLY' if action != 'remove' else 'REMOVED','implementation':'IMPLEMENTED',
                'schema_verified':True,'config_path':str(path),'fresh_host_trial':'PENDING',
                'message':'Project configuration updated. Review/trust in Codex; fresh host execution remains pending.'}

    def status(self,workspace):
        return [self.manage('status',host,workspace) for host in ('codex','cursor','kiro','workbuddy','qoder')]
