"""Current per-detector closure facts, independent of scans and repair grants."""
from __future__ import annotations

import json
import hmac
import os
from pathlib import Path
from types import SimpleNamespace

from .closeout_state import digest, encode
from .closeout_state import readonly_uri
from .equivalence import equivalence_key
from .hook_state import atomic_bytes, hook_session_paths, no_links
from .secret_coverage import covers, digest as file_digest
from .private_authority import PrivateAuthority, revision


def family_row(family):
    proof = family['proof']
    return {'id': family['equivalence_key'], 'fingerprint': '', 'category': family['category'],
            'file_path': family['file_path'], 'line_start': family['occurrences'][0]['line_start'],
            'line_end': family['occurrences'][0]['line_end'], 'scanner_sources': family['scanner_sources'],
            'technical_details': {'rule_id': family['rule_id'], 'engine': proof.get('engine', ''),
                'rule_pack_checksum': proof.get('rule_pack_checksum', ''), 'rule_version': proof.get('rule_version', '')}}


def original_family(row):
    details = row.get('technical_details', {})
    return {'equivalence_key': equivalence_key(row), 'category': row['category'],
        'file_path': row['file_path'], 'rule_id': details.get('rule_id', ''),
        'scanner_sources': row['scanner_sources'], 'count': 1,
        'occurrences': [{'line_start': row.get('line_start', 1), 'line_end': row.get('line_end', 1)}],
        'uncertain': False, 'proof': {k: details.get(k, '') for k in
            ('rule_pack_checksum', 'engine', 'rule_version')} | {
                'rule_versions': {details['rule_id']: details['rule_version']} if details.get('rule_version') else {}}}


class RiskClosureService:
    def __init__(self, hooks):
        self.hooks = hooks

    def _path(self, root):
        return self._authority(root).path

    def _authority(self, root):
        def legacy(raw, key):
            value = json.loads(raw)
            if (not isinstance(value, dict) or not isinstance(value.get('records'), dict)
                    or len(value['records']) > 2000 or not isinstance(value.get('mac'), str)
                    or not hmac.compare_digest(value['mac'], digest(key, value['records']))):
                raise ValueError('Closure proofs cannot be verified')
            return dict(records=value['records'], outbox={}, inbox={})
        return PrivateAuthority(self.hooks, Path(root), legacy_name='closures.state',
            name='closures-v2.state', contract='closure-authority-v2',
            initial=dict(records={}, outbox={}, inbox={}), legacy=legacy)

    def version(self, root):
        return revision(self._authority(root).read())

    def resume(self, root):
        if not self.hooks.lock_held(root): raise ValueError('Closure workspace lock required')
        authority = self._authority(root)
        if authority.journal.exists(): authority._ensure()

    def _read(self, root):
        value = self._authority(root).read()
        if (not isinstance(value, dict) or set(value) != {'records', 'outbox', 'inbox'}
                or any(not isinstance(value[k], dict) for k in value) or len(value['records']) > 2000):
            raise ValueError('Closure proof budget exceeded')
        return value['records']

    def reconcile_caches(self, root):
        """Retry only original session/version caches; never replace newer state."""
        if not self.hooks.lock_held(root): raise ValueError('Closure workspace lock required')
        authority = self._authority(root)
        if authority.journal.exists(): authority._ensure()
        value = authority.read()
        for event_id, effect in list(value['outbox'].items())[:64]:
            if not __import__('re').fullmatch(r'[a-f0-9]{64}\.json', effect['file']):
                raise ValueError('Closure cache owner cannot be verified')
            kind = effect.get('cache_kind', 'LEGACY_SESSION')
            if kind not in {'LEGACY_SESSION', 'SCAN_SESSION'}:
                raise ValueError('Closure cache namespace cannot be verified')
            path = authority.directory / effect['file'] if kind == 'LEGACY_SESSION' else (
                authority.directory / 'scan-sessions' / effect['file'])
            state, corrupt = self.hooks.load(path)
            if corrupt: continue  # Retain the intent; do not overwrite unknown content.
            if state is not None and (state['host'], state['session_id'], state['workspace_id']) != (
                    effect['host'], effect['session_id'], effect['workspace_id']):
                continue
            if (state is not None and state.get('schema_version') == 'hook-v1'
                    and revision(state) == effect['expected_version']):
                state['families'], state['last_result']['delta'] = self.overlay(
                    root, state['families'], state['last_result']['delta'])
                self.hooks.save(path, state)
            # Missing or newer session state supersedes only this cache intent.
            current = authority.read()
            before = revision(current)
            if current['outbox'].get(event_id) != effect:
                raise ValueError('Closure cache effect changed')
            del current['outbox'][event_id]
            authority.save(current, before)
        remaining = len(authority.read()['outbox'])
        return dict(state='PENDING' if remaining else 'APPLIED', pending=remaining)

    def activity_snapshot(self, root):
        """Read-only pending targets; a saved source can recognize its own ACK."""
        import sqlite3
        from contextlib import closing
        path = self.hooks.workspace_directory(Path(root)) / 'pending-activity.db'
        no_links(path)
        if not path.exists():
            return []
        with closing(sqlite3.connect(readonly_uri(path), uri=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pending_activity'").fetchone():
                return []
            rows = db.execute('SELECT session, sequence FROM pending_activity ORDER BY session').fetchall()
        return [list(row) for row in rows]

    def generation(self, root):
        """Read-only arrival epoch for independent checks, not repair authority."""
        return digest(b'activity-epoch', self.activity_snapshot(root))

    def effect_receipt(self, root, effect_id):
        """Read an authenticated target receipt without migrating or replaying."""
        return self._authority(root).read()['inbox'].get(effect_id)

    def effect_current(self, root, effect_id):
        value = self._authority(root).read()
        receipt = value['inbox'].get(effect_id)
        return (isinstance(receipt, dict) and receipt.get('status') == 'SAVED'
            and receipt.get('records_revision') == revision(value['records']))

    def record(self, root, originals, results, *, source, generation=None, closeout_ref=None,
               expected_activity=None, locked=False, effect_id=None, expected_version=None):
        root = Path(root).resolve()
        if not locked:
            with self.hooks.lock(root) as acquired:
                if not acquired:
                    return {'status': 'BUSY', 'confirmed': 0}
                return self.record(root, originals, results, source=source, generation=generation,
                    closeout_ref=closeout_ref, expected_activity=expected_activity, locked=True,
                    effect_id=effect_id, expected_version=expected_version)
        if not self.hooks.lock_held(root): raise ValueError('Closure workspace lock required')
        authority = self._authority(root)
        if authority.journal.exists(): authority._ensure()
        value = authority.read()
        if effect_id is not None and effect_id in value['inbox']:
            receipt = value['inbox'][effect_id]
            if receipt.get('records_revision') != revision(value['records']):
                return dict(status='SUPERSEDED', confirmed=0, already_applied=True)
            return dict(receipt, cache_sync=self.reconcile_caches(root), already_applied=True)
        if expected_version is not None and revision(value) != expected_version:
            return dict(status='SUPERSEDED', confirmed=0)
        if expected_activity is not None and self.generation(root) != expected_activity:
            return {'status': 'NEW_ACTIVITY', 'confirmed': 0}
        before = revision(value)
        records = value['records']
        accepted = 0
        accepted_keys = []
        for original, result in zip(originals, results):
            # Never extend another provider's proof, or accept only a verdict.
            if (original.get('category') != 'secret' or original.get('scanner_sources') != ['gitleaks'] or
                    result.get('finding_id') != original['id'] or
                    result.get('verification_status') != 'SCANNER_VERIFIED_RESOLVED' or
                    result.get('current_evidence') or
                    not result.get('runtime_observed_execution', {}).get('engine_process_observed')):
                continue
            if (os.getenv('GITLEAKS_CONFIG') or os.getenv('GITLEAKS_CONFIG_TOML') or
                    (root / '.gitleaksignore').exists() or (root / '.gitleaks.toml').exists()):
                continue
            run = next((r for r in result.get('scanner_runs', []) if r['scanner'] == 'gitleaks'), None)
            if not run or not covers(SimpleNamespace(**run), original.get('technical_details', {}),
                                      original['file_path'], root=root):
                continue
            key = equivalence_key(original)
            if not key:
                continue
            file_revision = run['scanner_diagnostics']['secret_coverage']['scanned_files'][original['file_path']]
            records[key] = {'family': original_family(original), 'file_revision': file_revision,
                'detector': original['technical_details'], 'source': source, 'generation': generation,
                'closeout_ref': closeout_ref, 'activity_epoch': expected_activity, 'execution': run}
            accepted += 1
            accepted_keys.append(key)
        if accepted:
            if expected_activity is not None and self.generation(root) != expected_activity:
                return {'status': 'NEW_ACTIVITY', 'confirmed': 0}
            if (os.getenv('GITLEAKS_CONFIG') or os.getenv('GITLEAKS_CONFIG_TOML') or
                    (root / '.gitleaksignore').exists() or (root / '.gitleaks.toml').exists()):
                return {'status': 'NEW_ACTIVITY', 'confirmed': 0}
            if any(file_digest(root / records[k]['family']['file_path']) != records[k]['file_revision']
                   for k in accepted_keys):
                return {'status': 'NEW_ACTIVITY', 'confirmed': 0}
            if len(records) > 2000:
                raise ValueError('Closure proof budget exceeded')
            # Keep all original scans/baselines. Only current session facts and
            # their cached deltas are updated under the same workspace lock.
            directory = self.hooks.workspace_directory(root)
            paths = [(path, 'LEGACY_SESSION') for path in hook_session_paths(directory)]
            paths.extend((path, 'SCAN_SESSION') for path in hook_session_paths(directory/'scan-sessions'))
            for path, kind in paths:
                state, _ = self.hooks.load(path)
                if not state or state.get('schema_version') != 'hook-v1':
                    continue
                event = dict(file=path.name, host=state['host'], session_id=state['session_id'],
                    workspace_id=state['workspace_id'], expected_version=revision(state))
                if kind != 'LEGACY_SESSION':
                    event['cache_kind'] = kind
                value['outbox'][revision(event)] = event
            if len(value['outbox']) > 64: raise ValueError('Closure pending cache budget exceeded')
        receipt = dict(status='SAVED', confirmed=accepted, records_revision=revision(records))
        if effect_id is not None:
            if not isinstance(effect_id, str) or not 1 <= len(effect_id) <= 200:
                raise ValueError('Invalid closure effect identity')
            if len(value['inbox']) >= 2000: raise ValueError('Closure receipt budget exceeded')
            value['inbox'][effect_id] = receipt
        if accepted or effect_id is not None:
            authority.save(value, before)
            return dict(receipt, cache_sync=self.reconcile_caches(root))
        return receipt

    def overlay(self, root, families, delta):
        current = dict(families)
        rows = {r['equivalence_key']: dict(r) for r in delta.get('families', [])}
        for key, record in self._read(root).items():
            family = record['family']
            try:
                valid = file_digest(Path(root) / family['file_path']) == record['file_revision'] and covers(
                    SimpleNamespace(**record['execution']), record['detector'], family['file_path'], root=root)
                valid = valid and not (os.getenv('GITLEAKS_CONFIG') or os.getenv('GITLEAKS_CONFIG_TOML') or
                    (Path(root) / '.gitleaksignore').exists() or (Path(root) / '.gitleaks.toml').exists())
            except (OSError, ValueError):
                valid = False
            # A newly observed detector identity is never overwritten by an old
            # rule proof even at the same equivalence key/content version.
            if key in current and current[key]['proof'] != family['proof']:
                valid = False
            if valid:
                current.pop(key, None)
            else:
                current.setdefault(key, family)
                if rows.get(key, {}).get('current_count', 0) > 0:
                    # An expired absence proof cannot erase fresh presence.
                    continue
            rows[key] = {k: family[k] for k in ('equivalence_key', 'file_path', 'rule_id', 'category')} | {
                'status': 'RESOLVED_FAMILY' if valid else 'UNCONFIRMED_ABSENCE',
                'previous_count': family['count'], 'current_count': 0,
                'occurrence_delta': -family['count'] if valid else 0,
                'count_certainty': 'COMPLETE_RULE_FILE_SCOPE' if valid else 'OBSERVED_LOWER_BOUND'}
        out = dict(delta, families=list(rows.values()))
        out.update(new=sum(r['status'] == 'NEW_FAMILY' for r in rows.values()),
            persisting=sum(r['status'] not in {'NEW_FAMILY', 'RESOLVED_FAMILY'} for r in rows.values()),
            resolved=sum(r['status'] == 'RESOLVED_FAMILY' for r in rows.values()))
        out.setdefault('additional_occurrences', 0)
        out.setdefault('removed_occurrences', 0)
        return current, out

    def statuses(self, root):
        _, delta = self.overlay(root, {}, {'families': []})
        records = self._read(root)
        return [{'file_path': r['file_path'], 'rule_id': r['rule_id'], 'equivalence_key': r['equivalence_key'],
                 'status': 'CONFIRMED_CLOSED' if r['status'] == 'RESOLVED_FAMILY' else 'UNCONFIRMED',
                 'source': records[r['equivalence_key']]['source']} for r in delta['families']]
