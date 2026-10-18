"""Signed JSON authority with a recoverable, filesystem-enforced old-writer fence.

Only audited legacy writers which read or atomically replace the fixed old file
are fenced. An unrelated program deleting the nonempty fence directory is outside
this contract. Reads never create files, move legacy data or repair transitions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path

from .closeout_state import digest, encode
from .hook_state import atomic_bytes, no_links


AUDITED_WRITERS = ('v0.3.4', 'a51a58d', 'b352731')
FENCE_CONTRACT = 'private-authority-writer-fence-v1'


def revision(value):
    return hashlib.sha256(encode(value)).hexdigest()


class AuthorityRows(dict):
    """A read snapshot carrying a CAS identity, never an editing credential."""
    def __init__(self, values=(), *, revision=None, scope=None):
        super().__init__(values)
        self.revision = revision
        self.scope = scope


class PrivateAuthority:
    def __init__(self, hooks, root, *, legacy_name, name, contract, initial, legacy, maximum=2_000_000):
        if any(Path(item).name != item or item in {'', '.', '..'} for item in (legacy_name, name)):
            raise ValueError('Authority filenames must be fixed local names')
        self.hooks, self.root = hooks, Path(root)
        self.directory = hooks.workspace_directory(self.root)
        self.old = self.directory / legacy_name
        self.path = self.directory / name
        self.journal = self.directory / (name+'.transition')
        self.backup = self.directory / (legacy_name+'.verified-backup')
        self.moved = self.directory / (legacy_name+'.moved-backup')
        self.receipt = self.old / 'writer-fence.receipt'
        self.contract, self.initial, self.legacy, self.maximum = contract, initial, legacy, maximum

    def _key(self):
        path = self.directory/'snapshot.key'
        no_links(path)
        value = path.read_bytes()
        if len(value) != 32: raise ValueError('Authority key cannot be verified')
        return value

    def _raw(self, path):
        no_links(path)
        if not path.is_file() or path.stat().st_size > self.maximum:
            raise ValueError('Authority file cannot be verified')
        raw = path.read_bytes()
        if len(raw) > self.maximum: raise ValueError('Authority file budget exceeded')
        return raw

    def _decode(self, path, contract):
        value = json.loads(self._raw(path))
        if not isinstance(value, dict) or set(value) != {'content', 'mac'}:
            raise ValueError('Authority envelope cannot be verified')
        content = value['content']
        if (not isinstance(content, dict) or content.get('contract') != contract
                or content.get('workspace') != str(self.root)
                or not isinstance(value['mac'], str)
                or not hmac.compare_digest(value['mac'], digest(self._key(), content))):
            raise ValueError('Authority envelope cannot be verified')
        return content

    def _write(self, path, content):
        if not self.hooks.lock_held(self.root): raise ValueError('Authority workspace lock required')
        raw = encode(dict(content=content, mac=digest(self._key(), content)))
        if len(raw) > self.maximum: raise ValueError('Authority byte budget exceeded')
        no_links(path)
        atomic_bytes(path, raw)

    def _transition(self):
        value = self._decode(self.journal, FENCE_CONTRACT)
        if (set(value) != {'contract','workspace','target','legacy','phase','audited_writers','legacy_sha256'}
                or value.get('target') != self.path.name or value.get('legacy') != self.old.name
                or value.get('phase') not in {'PREPARED', 'COMMITTED'}
                or value.get('audited_writers') != list(AUDITED_WRITERS)
                or value['legacy_sha256'] is not None and (not isinstance(value['legacy_sha256'],str)
                    or re.fullmatch('[a-f0-9]{64}',value['legacy_sha256']) is None)):
            raise ValueError('Authority transition cannot be verified')
        return value

    def _seed(self, transition):
        sha = transition['legacy_sha256']
        if sha is None:
            return self.initial
        raw = self._raw(self.backup)
        if hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError('Authority backup changed')
        return self.legacy(raw, self._key())

    def _backup(self, transition):
        """Resume only a journal-owned copy of the exact authenticated source."""
        sha = transition['legacy_sha256']
        if sha is None:
            if self.backup.exists() or self.moved.exists():
                raise ValueError('Unexpected legacy backup; files preserved')
            return
        if not self.backup.exists():
            raw = self._raw(self.old)
            if hashlib.sha256(raw).hexdigest() != sha:
                raise ValueError('Legacy source changed before backup; files preserved')
            self.legacy(raw, self._key())
            atomic_bytes(self.backup, raw)
        self._seed(transition)
        if self.moved.exists() and hashlib.sha256(self._raw(self.moved)).hexdigest() != sha:
            raise ValueError('Moved legacy backup changed; files preserved')

    def _verify_fence(self, transition):
        no_links(self.old)
        if not self.old.is_dir(): raise ValueError('Legacy writer fence unavailable')
        if {path.name for path in self.old.iterdir()} != {self.receipt.name}:
            raise ValueError('Unknown legacy fence files are preserved')
        receipt = self._decode(self.receipt, FENCE_CONTRACT)
        expected = {key:value for key,value in transition.items() if key != 'phase'}
        if receipt != expected: raise ValueError('Legacy writer fence changed')

    def read(self):
        for path in (self.old, self.path, self.journal, self.backup, self.moved): no_links(path)
        if self.journal.exists():
            transition = self._transition()
            if transition['phase'] != 'COMMITTED': raise ValueError('Authority transition incomplete')
            self._verify_fence(transition)
            self._seed(transition)  # The original authenticated backup stays verifiable.
            if transition['legacy_sha256'] is not None:
                if hashlib.sha256(self._raw(self.moved)).hexdigest() != transition['legacy_sha256']:
                    raise ValueError('Moved legacy backup changed; files preserved')
            return self._decode(self.path, self.contract)['value']
        if self.path.exists() or self.old.is_dir() or self.backup.exists() or self.moved.exists():
            raise ValueError('Unowned authority transition files are preserved')
        if self.old.exists(): return self.legacy(self._raw(self.old), self._key())
        return json.loads(json.dumps(self.initial))

    def _ensure(self):
        if not self.hooks.lock_held(self.root): raise ValueError('Authority workspace lock required')
        self.hooks.key(self.root)
        for path in (self.old, self.path, self.journal, self.backup, self.moved): no_links(path)
        if self.journal.exists():
            transition = self._transition()
            if transition['phase'] == 'COMMITTED':
                self._verify_fence(transition)
                self._seed(transition)
                return
        else:
            seed = self.read()
            raw = self._raw(self.old) if self.old.exists() else None
            sha = hashlib.sha256(raw).hexdigest() if raw is not None else None
            if raw is not None:
                if self.legacy(raw, self._key()) != seed: raise ValueError('Legacy authority changed')
            transition = dict(contract=FENCE_CONTRACT, workspace=str(self.root), legacy=self.old.name,
                target=self.path.name, legacy_sha256=sha, audited_writers=list(AUDITED_WRITERS), phase='PREPARED')
            self._write(self.journal, transition)
        self._backup(transition)
        seed = self._seed(transition)
        if self.old.is_file():
            if self.moved.exists() or transition['legacy_sha256'] is None:
                raise ValueError('Concurrent legacy writer detected; files preserved')
            raw = self._raw(self.old)
            if hashlib.sha256(raw).hexdigest() != transition['legacy_sha256']:
                raise ValueError('Legacy authority changed; files preserved')
            os.replace(self.old, self.moved)
            if hashlib.sha256(self._raw(self.moved)).hexdigest() != transition['legacy_sha256']:
                raise ValueError('Concurrent legacy writer captured; backups preserved')
        if not self.old.exists():
            if transition['legacy_sha256'] is not None and not self.moved.is_file():
                raise ValueError('Legacy source move cannot be verified')
            self.old.mkdir(mode=0o700)
        if not self.old.is_dir(): raise ValueError('Legacy writer fence unavailable')
        receipt = {key:value for key,value in transition.items() if key != 'phase'}
        if self.receipt.exists(): self._verify_fence(transition)
        else: self._write(self.receipt, receipt)
        initial = dict(contract=self.contract, workspace=str(self.root), value=seed)
        if self.path.exists():
            if self._decode(self.path, self.contract) != initial:
                raise ValueError('Uncommitted authority changed; files preserved')
        else: self._write(self.path, initial)
        self._write(self.journal, dict(transition, phase='COMMITTED'))

    def save(self, value, expected_revision):
        self._ensure()
        current = self.read()
        if revision(current) != expected_revision:
            raise ValueError('Authority changed concurrently; read the current snapshot')
        self._write(self.path, dict(contract=self.contract, workspace=str(self.root), value=value))
