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
from .hook_state import atomic_bytes, no_links
from .secret_coverage import covers, digest as file_digest


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
        return self.hooks.workspace_directory(Path(root)) / 'closures.state'

    def _read(self, root):
        path = self._path(root)
        no_links(path)
        if not path.exists():
            return {}
        if path.stat().st_size > 2_000_000:
            raise ValueError('Closure proof budget exceeded')
        value = json.loads(path.read_bytes())
        key_path = self.hooks.workspace_directory(Path(root)) / 'snapshot.key'
        no_links(key_path)
        key = key_path.read_bytes()
        if len(key) != 32 or not hmac.compare_digest(value['mac'], digest(key, value['records'])):
            raise ValueError('Closure proofs cannot be verified')
        if not isinstance(value['records'], dict) or len(value['records']) > 2000:
            raise ValueError('Closure proof budget exceeded')
        return value['records']

    def generation(self, root):
        """Read-only arrival epoch for independent checks, not repair authority."""
        import sqlite3
        from contextlib import closing
        path = self.hooks.workspace_directory(Path(root)) / 'pending-activity.db'
        no_links(path)
        if not path.exists():
            return digest(b'activity-epoch', [])
        with closing(sqlite3.connect(readonly_uri(path), uri=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pending_activity'").fetchone():
                return digest(b'activity-epoch', [])
            rows = db.execute('SELECT session, sequence FROM pending_activity ORDER BY session').fetchall()
        return digest(b'activity-epoch', rows)

    def record(self, root, originals, results, *, source, generation=None, closeout_ref=None,
               expected_activity=None, locked=False):
        root = Path(root).resolve()
        if not locked:
            with self.hooks.lock(root) as acquired:
                if not acquired:
                    return {'status': 'BUSY', 'confirmed': 0}
                return self.record(root, originals, results, source=source, generation=generation,
                                   closeout_ref=closeout_ref, expected_activity=expected_activity, locked=True)
        if expected_activity is not None and self.generation(root) != expected_activity:
            return {'status': 'NEW_ACTIVITY', 'confirmed': 0}
        records = self._read(root)
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
            revision = run['scanner_diagnostics']['secret_coverage']['scanned_files'][original['file_path']]
            records[key] = {'family': original_family(original), 'file_revision': revision,
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
            envelope = encode({'records': records, 'mac': digest(self.hooks.key(root), records)})
            if len(envelope) > 2_000_000 or len(records) > 2000:
                raise ValueError('Closure proof budget exceeded')
            atomic_bytes(self._path(root), envelope)
            # Keep all original scans/baselines. Only current session facts and
            # their cached deltas are updated under the same workspace lock.
            for path in self.hooks.workspace_directory(root).glob('*.json'):
                state, _ = self.hooks.load(path)
                if not state:
                    continue
                state['families'], state['last_result']['delta'] = self.overlay(
                    root, state['families'], state['last_result']['delta'])
                self.hooks.save(path, state)
        return {'status': 'SAVED', 'confirmed': accepted}

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
