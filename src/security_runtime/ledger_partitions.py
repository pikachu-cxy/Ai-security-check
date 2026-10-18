"""Immutable per-origin task partitions, published by one signed index CAS.

Pending effects live in the index and never depend on an obsolete shard. A
writer may collect only authenticated, hash-named unreferenced product shards.
Readers never migrate or collect anything.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

from .closeout_state import digest, encode
from .hook_state import atomic_bytes, no_links

MAX_PARTITIONS = 256
MAX_ROWS = 1000
MAX_BYTES = 2_000_000
MAX_FILES = 2 * MAX_PARTITIONS
SHARD = re.compile(r'[a-f0-9]{64}\.state')


class LedgerCapacity(ValueError):
    def __init__(self, kind, count, limit):
        self.reason_code = 'TASK_RISK_LEDGER_' + kind + '_CAPACITY'
        self.count, self.limit = count, limit
        super().__init__(f'{self.reason_code}: count={count}, limit={limit}')


class LedgerPartitions:
    def __init__(self, authority):
        self.authority = authority
        self.directory = authority.directory / 'task-risk-partitions'

    def _decode(self, name):
        if not isinstance(name, str) or SHARD.fullmatch(name) is None:
            raise ValueError('Invalid risk partition identity')
        path = self.directory / name
        raw = self.authority._raw(path)
        if hashlib.sha256(raw).hexdigest() + '.state' != name:
            raise ValueError('Risk partition content changed')
        envelope = json.loads(raw)
        value = envelope.get('content')
        if (not isinstance(value, dict) or value.get('contract') != 'task-risk-partition-v1'
                or value.get('workspace') != str(self.authority.root)
                or not isinstance(envelope.get('mac'), str)
                or not hmac.compare_digest(envelope['mac'], digest(self.authority._key(), value))
                or not isinstance(value.get('rows'), dict) or len(value['rows']) > MAX_ROWS):
            raise ValueError('Risk partition cannot be verified')
        self._rows(value['task_ref'], value['rows'])
        return value, len(raw)

    @staticmethod
    def _rows(task_ref, rows):
        if not isinstance(task_ref, str) or not 1 <= len(task_ref) <= 200:
            raise ValueError('Invalid risk partition origin')
        for key, row in rows.items():
            if (not isinstance(row, dict) or row.get('origin_task_ref') != task_ref
                    or not isinstance(key, str) or not key.startswith(task_ref + ':')):
                raise ValueError('Risk partition origin mismatch')

    def read(self, stored, task_ref=None):
        if 'rows' in stored:  # Authenticated v1 seed, read-only until next write.
            return {key: row for key, row in stored['rows'].items()
                    if task_ref is None or row.get('origin_task_ref') == task_ref}
        index = stored.get('partitions')
        if not isinstance(index, dict) or len(index) > MAX_PARTITIONS:
            raise ValueError('Risk partition index cannot be verified')
        rows = {}
        for origin, entry in index.items():
            if task_ref is not None and origin != task_ref: continue
            if not isinstance(entry, dict): raise ValueError('Invalid risk partition entry')
            value, size = self._decode(entry['file'])
            if (value['task_ref'] != origin or entry.get('row_count') != len(value['rows'])
                    or entry.get('bytes') != size or 'scan_ids' in entry and entry['scan_ids'] !=
                    sorted({row['origin_scan_id'] for row in value['rows'].values() if row.get('origin_scan_id')})):
                raise ValueError('Risk partition index mismatch')
            rows.update(value['rows'])
        return rows

    def read_origins(self, stored, origins):
        rows = {}
        for origin in origins: rows.update(self.read(stored,origin))
        return rows

    def origins_for_scan(self, stored, scan_id):
        if 'rows' in stored:
            return sorted({row['origin_task_ref'] for row in stored['rows'].values()
                           if row.get('origin_scan_id') == scan_id})
        origins = []
        for origin, entry in stored['partitions'].items():
            scans = entry.get('scan_ids')
            if scans is not None:
                if not isinstance(scans,list): raise ValueError('Invalid risk scan index')
                if scan_id in scans: origins.append(origin)
            elif any(row.get('origin_scan_id') == scan_id for row in self.read(stored,origin).values()):
                origins.append(origin)
        return origins

    def _collect(self, referenced):
        """Only current-index-unreferenced signed product files are collectible."""
        if not self.authority.hooks.lock_held(self.authority.root):
            raise ValueError('Risk partition workspace lock required')
        if not self.directory.exists(): return
        no_links(self.directory)
        for path in self.directory.iterdir():
            if path.name in referenced or SHARD.fullmatch(path.name) is None: continue
            self._decode(path.name)  # Invalid or changed files are preserved and stop cleanup.
            path.unlink()

    def publish(self, stored, rows, scope=None):
        if not self.authority.hooks.lock_held(self.authority.root):
            raise ValueError('Risk partition workspace lock required')
        origins = ({scope} if isinstance(scope,str) else set(scope)) if scope is not None else None
        if scope is not None and 'rows' in stored:
            merged = dict(stored['rows'])
            merged = {key: row for key, row in merged.items() if row['origin_task_ref'] not in origins}
            merged.update(rows)
            rows, scope = merged, None
        groups = {}
        for key, row in rows.items():
            groups.setdefault(row['origin_task_ref'], {})[key] = row
        if scope is not None:
            if set(groups) - origins: raise ValueError('Risk partition write scope mismatch')
            for origin in origins: groups.setdefault(origin, {})
        index = dict(stored.get('partitions', {})) if scope is not None else {}
        if len(set(index) | set(groups)) > MAX_PARTITIONS:
            raise LedgerCapacity('PARTITION', len(set(index) | set(groups)), MAX_PARTITIONS)
        # Validate and encode every shard before any publication.
        candidates = {}
        for origin, group in groups.items():
            self._rows(origin, group)
            if len(group) > MAX_ROWS: raise LedgerCapacity('ROW', len(group), MAX_ROWS)
            content = dict(contract='task-risk-partition-v1', workspace=str(self.authority.root),
                           task_ref=origin, rows=group)
            raw = encode(dict(content=content, mac=digest(self.authority._key(), content)))
            if len(raw) > MAX_BYTES: raise LedgerCapacity('BYTE', len(raw), MAX_BYTES)
            name = hashlib.sha256(raw).hexdigest() + '.state'
            candidates[name] = raw
            index[origin] = dict(file=name, row_count=len(group), bytes=len(raw),
                scan_ids=sorted({row['origin_scan_id'] for row in group.values() if row.get('origin_scan_id')}))
        no_links(self.directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._collect({entry['file'] for entry in stored.get('partitions', {}).values()})
        current = set(path.name for path in self.directory.iterdir())
        if len(current | set(candidates)) > MAX_FILES:
            raise LedgerCapacity('SHARD_FILE', len(current | set(candidates)), MAX_FILES)
        for name, raw in candidates.items():
            path = self.directory / name
            if path.exists():
                if self.authority._raw(path) != raw: raise ValueError('Risk immutable partition changed')
            else: atomic_bytes(path, raw)
        return dict(partitions=index, outbox=stored['outbox'], inbox=stored['inbox'])

    def collect(self, stored):
        self._collect({entry['file'] for entry in stored.get('partitions', {}).values()})
