"""Exact routine-tool preapprovals; preserve user JSONC and signed ownership."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import sys
from pathlib import Path

from .codex_integration import unique_json
from .hook_state import atomic_bytes, no_links
from .owned_json import encode

ROUTINE_TOOLS = (
    'get_task_isolation_capabilities',
    'get_task_closeout_status', 'wait_task_closeout', 'cancel_task_closeout',
    'begin_security_task', 'switch_security_task', 'finish_security_task', 'prepare_task_security_review',
    'get_task_review_plan', 'get_task_review_method', 'submit_task_review_batch',
    'read_task_review_context', 'submit_task_security_review', 'get_task_security_review',
    'get_task_risk_ledger', 'get_runtime_info', 'get_scan_preparation_status', 'get_security_summary',
    'get_scan_status', 'get_scan_result', 'list_scan_jobs',
    'get_findings', 'prepare_finding_feedback', 'submit_finding_feedback', 'get_finding_feedback',
    'mark_finding_false_positive', 'revoke_finding_feedback', 'set_finding_disposition',
    'prepare_task_risk_feedback', 'submit_task_risk_feedback', 'get_task_risk_feedback',
    'mark_task_risk_false_positive', 'revoke_task_risk_feedback', 'set_task_risk_disposition',
    # Bundled guidance and existing-scan triage: never starts another scan.
    'get_runtime_guidance', 'get_professional_guidance',
    'prepare_task_triage', 'prepare_triage', 'submit_triage', 'get_triage',
    # Analysis records/evidence do not authorize the selected repair itself.
    'prepare_repair_impact', 'read_repair_impact_context', 'submit_repair_impact',
    'get_repair_impact', 'get_closeout_status',
)
ENTRIES = tuple('ai-security-runtime:' + tool for tool in ROUTINE_TOOLS)
MAX_BYTES = 262144
CONTRACT = 'cursor-routine-permissions-v1'


def document(raw):
    """Mask JSONC comments/trailing commas without changing character offsets."""
    text = raw.decode('utf-8-sig') if raw is not None else '{}'
    chars = list(text)
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(text):
        if text[pos] == '"':
            _, pos = decoder.raw_decode(text, pos)
        elif text.startswith('//', pos):
            end = text.find('\n', pos)
            end = len(text) if end < 0 else end
            chars[pos:end] = [' '] * (end-pos)
            pos = end
        elif text.startswith('/*', pos):
            end = text.find('*/', pos+2)
            if end < 0:
                raise ValueError('CURSOR_PERMISSIONS_INVALID')
            end += 2
            chars[pos:end] = [c if c in '\r\n' else ' ' for c in text[pos:end]]
            pos = end
        else:
            pos += 1
    masked = ''.join(chars)
    pos = 0
    while pos < len(masked):
        if masked[pos] == '"':
            _, pos = decoder.raw_decode(masked, pos)
            continue
        if masked[pos] == ',':
            following = pos+1
            while following < len(masked) and masked[following].isspace():
                following += 1
            if following < len(masked) and masked[following] in ']}':
                chars[pos] = ' '
        pos += 1
    clean = ''.join(chars)
    value = unique_json(clean)
    if not isinstance(value, dict):
        raise ValueError('CURSOR_PERMISSIONS_INVALID')
    entries = value.get('mcpAllowlist', [])
    if (not isinstance(entries, list) or len(entries) > 2000
            or any(not isinstance(v, str) or len(v) > 1000 for v in entries)):
        raise ValueError('CURSOR_PERMISSIONS_INVALID')
    return text, masked, clean, value


def members(clean):
    decoder = json.JSONDecoder()
    pos = clean.index('{')+1
    while True:
        while clean[pos].isspace():
            pos += 1
        if clean[pos] == '}':
            return
        start = pos
        name, pos = decoder.raw_decode(clean, pos)
        while clean[pos].isspace():
            pos += 1
        pos += 1  # colon; document() already validated the complete object.
        while clean[pos].isspace():
            pos += 1
        value_start = pos
        _, end = decoder.raw_decode(clean, pos)
        yield name, start, value_start, end
        pos = end
        while clean[pos].isspace():
            pos += 1
        if clean[pos] == ',':
            pos += 1


def edit_allowlist(raw, *, add=(), remove=(), drop_empty=False):
    if not add and not remove:
        return raw
    text, masked, clean, value = document(raw)
    field = next((m for m in members(clean) if m[0] == 'mcpAllowlist'), None)
    if field is None:
        if not add:
            return raw
        end = clean.rindex('}')
        last = next((i for i in range(end-1, -1, -1) if not masked[i].isspace()), 0)
        separator = ',' if value and masked[last] != ',' else ''
        text = text[:end] + '\n' + separator + '"mcpAllowlist": ' + json.dumps(list(add)) + '\n' + text[end:]
    else:
        _, start, array_start, end = field
        decoder = json.JSONDecoder()
        items, pos = [], array_start+1
        while pos < end-1:
            if clean[pos].isspace() or clean[pos] == ',':
                pos += 1
                continue
            item, stop = decoder.raw_decode(clean, pos)
            items.append((item, pos, stop))
            pos = stop
        removed = set(remove)
        kept = [item for item in items if item[0] not in removed]
        chars = list(text)
        # Only the exact, uniquely owned string tokens and their separators go.
        commas = []
        for index, (_, _, stop) in enumerate(items):
            next_start = items[index+1][1] if index+1 < len(items) else end-1
            commas.extend(i for i in range(stop, next_start) if masked[i] == ',')
        retain_commas = set()
        for left, right in zip(kept, kept[1:]):
            retain_commas.add(next(i for i in commas if left[2] <= i < right[1]))
        for item, begin, stop in items:
            if item in removed:
                chars[begin:stop] = [' '] * (stop-begin)
        for comma in commas:
            if comma not in retain_commas:
                chars[comma] = ' '
        if drop_empty and not kept and not add:
            # Keep comments even when removing a field introduced by us.
            for i in range(start, end):
                if not masked[i].isspace():
                    chars[i] = ' '
            following = end
            while following < len(masked) and masked[following].isspace():
                following += 1
            if masked[following] == ',':
                chars[following] = ' '
            else:
                previous = start-1
                while masked[previous].isspace():
                    previous -= 1
                if masked[previous] == ',':
                    chars[previous] = ' '
        text = ''.join(chars)
        if add:
            insertion = ('\n,' if kept else '\n') + ',\n'.join(json.dumps(v) for v in add) + '\n'
            text = text[:end-1] + insertion + text[end-1:]
    result = (b'\xef\xbb\xbf' if raw and raw.startswith(b'\xef\xbb\xbf') else b'') + text.encode('utf-8')
    document(result)  # Never publish an invalid edit.
    if len(result) > MAX_BYTES:
        raise ValueError('CURSOR_PERMISSIONS_INVALID')
    return result


def ide_allowlist(home):
    """Read only the existing IDE allowlist before a file would override it."""
    if home != Path.home()/'.cursor':
        return []  # Isolated/custom installs never import the live IDE profile.
    if os.name == 'nt':
        profile = Path(os.environ.get('APPDATA', str(Path.home()/'AppData/Roaming')))/'Cursor'
    elif sys.platform == 'darwin':
        profile = Path.home()/'Library/Application Support/Cursor'
    else:
        profile = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home()/'.config')))/'Cursor'
    path = profile/'User/globalStorage/state.vscdb'
    no_links(path)
    if not path.exists():
        return []
    key = 'src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser'
    try:
        with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=1) as db:
            row = db.execute('SELECT value FROM ItemTable WHERE key=? AND length(value)<=?', (key, 8*1024*1024)).fetchone()
            if row is None:
                exists = db.execute('SELECT 1 FROM ItemTable WHERE key=?', (key,)).fetchone()
                if exists:
                    raise ValueError('CURSOR_PERMISSION_SOURCE_UNAVAILABLE')
                return []
        state = unique_json(row[0]).get('composerState', {})
        entries = state.get('mcpAllowedTools', [])
        if (not isinstance(entries, list) or len(entries) > 2000
                or any(not isinstance(v, str) or len(v) > 1000 for v in entries)):
            raise ValueError('CURSOR_PERMISSION_SOURCE_UNAVAILABLE')
        return entries
    except (sqlite3.Error, ValueError, TypeError, AttributeError) as exc:
        raise ValueError('CURSOR_PERMISSION_SOURCE_UNAVAILABLE') from exc


class CursorRoutinePermissions:
    def __init__(self, home, store, *, observer=None, existing_allowlist=None):
        self.home, self.store, self.observer = home, store, observer
        self.path = home/'permissions.json'
        self.manifest = store.workspace_directory(home)/'routine-permissions-ownership.json'
        self.existing_allowlist = existing_allowlist or ide_allowlist

    def inspect(self):
        no_links(self.path)
        no_links(self.manifest)
        raw = self.path.read_bytes() if self.path.exists() else None
        if raw is not None and len(raw) > MAX_BYTES:
            raise ValueError('CURSOR_PERMISSIONS_INVALID')
        try:
            value = document(raw)[3]
            ownership = self.manifest.read_bytes() if self.manifest.exists() else None
            record = None
            if ownership is not None:
                if len(ownership) > MAX_BYTES:
                    raise ValueError('CURSOR_PERMISSION_OWNERSHIP_INVALID')
                signed = unique_json(ownership)
                signature = signed.pop('signature')
                key_path = self.store.workspace_directory(self.home)/'snapshot.key'
                no_links(key_path)
                key = key_path.read_bytes()
                if (len(key) != 32 or set(signed) != {'contract', 'added', 'had_key', 'created_hash'}
                        or signed['contract'] != CONTRACT or type(signed['had_key']) is not bool
                        or not isinstance(signed['added'], list) or len(signed['added']) > len(ENTRIES)
                        or any(v not in ENTRIES for v in signed['added'])
                        or not (signed['created_hash'] is None or isinstance(signed['created_hash'], str)
                            and len(signed['created_hash']) == 64
                            and all(c in '0123456789abcdef' for c in signed['created_hash']))
                        or not isinstance(signature, str) or not hmac.compare_digest(signature,
                            hmac.new(key, encode(signed), hashlib.sha256).hexdigest())):
                    raise ValueError('CURSOR_PERMISSION_OWNERSHIP_INVALID')
                record = signed
            return raw, value, ownership, record
        except (KeyError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('CURSOR_PERMISSIONS_INVALID') from exc

    def status(self):
        from .risk_disposition import VERSION as disposition_contract
        _, value, _, _ = self.inspect()
        entries = {v.casefold() for v in value.get('mcpAllowlist', [])}
        ready = all(v in entries for v in ENTRIES)
        return dict(status='CONFIGURED' if ready else 'NEEDS_REPAIR',
            routine_tools=list(ROUTINE_TOOLS), repair_preapproved_by_product=False,
            disposition_contract=disposition_contract,
            disposition_requires_explicit_user_request=True,
            exclusion_is_safety_proof=False,
            host_policy='RUN_MODE_AND_TEAM_POLICY_STILL_APPLY', live_no_prompt_verified=False)

    def write(self, path, before, desired):
        no_links(path)
        if (path.read_bytes() if path.exists() else None) != before:
            raise ValueError('CONFIGURATION_CHANGED')
        if before == desired:
            return
        if self.observer:
            self.observer(path, desired)
        if desired is None:
            path.unlink(missing_ok=True)
        else:
            atomic_bytes(path, desired)

    def execute(self, action):
        raw, value, ownership, record = self.inspect()
        entries = value.get('mcpAllowlist', [])
        if action == 'remove':
            if record is None:
                return  # Never adopt or remove a user's pre-existing approvals.
            remove = [v for v in record['added'] if entries.count(v) == 1]
            desired = edit_allowlist(raw, remove=remove, drop_empty=not record['had_key'])
            if raw is not None and record['created_hash'] == hashlib.sha256(raw).hexdigest():
                desired = None
            self.write(self.path, raw, desired)
            self.write(self.manifest, ownership, None)
            return
        if action not in {'setup', 'repair'}:
            raise ValueError('UNSUPPORTED_INTEGRATION')
        imported = self.existing_allowlist(self.home) if 'mcpAllowlist' not in value else []
        known = {v.casefold() for v in [*entries, *imported]}
        missing = [v for v in ENTRIES if v not in known]
        desired = edit_allowlist(raw, add=[*imported, *missing]) if imported or missing else raw
        added = list(dict.fromkeys([*(record['added'] if record else []), *missing]))
        created_hash = record['created_hash'] if record else (
            hashlib.sha256(desired).hexdigest() if raw is None else None)
        # An untouched product-created file stays removable after an upgrade.
        # Any user edit breaks this match and must survive uninstall.
        if record and raw is not None and created_hash == hashlib.sha256(raw).hexdigest():
            created_hash = hashlib.sha256(desired).hexdigest()
        data = dict(contract=CONTRACT, added=added, had_key=record['had_key'] if record else 'mcpAllowlist' in value,
                    created_hash=created_hash)
        signed = encode({**data, 'signature': hmac.new(self.store.key(self.home), encode(data), hashlib.sha256).hexdigest()})
        self.write(self.path, raw, desired)
        self.write(self.manifest, ownership, signed)
