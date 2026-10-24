"""Small signed Hook references to workspace product observations.

An observation is neither a task preimage nor scanner evidence. Publication
does not require a quiet live tree and never completes a pending mutation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import time

from .hook_state import identity, no_links
from .host_lifecycle import HOSTS
from .product_epoch_capture import StableHashReader


SCHEMA = 'hook-product-epoch-v1'
CURRENT_FILE_BYTES = 1_000_000
CURRENT_BATCH_SECONDS = 0.2
_FIELDS = frozenset({'schema_version', 'workspace_id', 'state_id', 'host', 'session_id',
    'root_identity', 'epoch_ref', 'policy_digest', 'kind', 'consistency', 'representation',
    'last_processed_ref', 'signature'})


def _hex(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def validate_epoch_state(value):
    if (not isinstance(value, dict) or set(value) != _FIELDS or value['schema_version'] != SCHEMA
            or any(not _hex(value[key]) for key in ('workspace_id', 'state_id', 'session_id',
                                                   'policy_digest', 'signature'))
            or value['host'] not in HOSTS or value['kind'] != 'PRODUCT_COMPARISON'
            or value['consistency'] != 'OBSERVED_ONLY' or value['representation'] != 'HASH_ONLY'
            or not isinstance(value['root_identity'], list) or len(value['root_identity']) != 2
            or any(type(n) is not int or n < 0 for n in value['root_identity'])
            or not isinstance(value['epoch_ref'], str) or not 1 <= len(value['epoch_ref']) <= 128
            or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in value['epoch_ref'])
            or value['last_processed_ref'] is not None and not _hex(value['last_processed_ref'])):
        raise ValueError('Invalid product epoch Hook reference')
    return value


def _signature(value, key):
    body = {k:v for k,v in value.items() if k != 'signature'}
    raw = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hmac.new(key, b'hook-product-epoch-state-v1\0' + raw, hashlib.sha256).hexdigest()


def verify_epoch_state(value, path):
    validate_epoch_state(value)
    path = Path(path)
    no_links(path)
    key_path = path.parent / 'snapshot.key'
    no_links(key_path)
    try:
        info = key_path.stat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or os.name != 'nt' and info.st_mode & 0o077):
            raise ValueError('Product epoch Hook key unavailable')
        key = key_path.read_bytes()
    except OSError as error:
        raise ValueError('Product epoch Hook key unavailable') from error
    if (len(key) != 32 or value['workspace_id'] != path.parent.name or value['state_id'] != path.stem
            or not hmac.compare_digest(value['signature'], _signature(value, key))):
        raise ValueError('Product epoch Hook reference cannot be verified')
    return value


class ProductEpochHooks:
    def __init__(self, hooks, root, *, now, factory=None):
        self.hooks, self.root = hooks, Path(root)
        if factory is None:
            from .product_epoch_service import ProductEpochService
            self.service = ProductEpochService(hooks, self.root, now=now)
        else:
            self.service = factory(hooks, self.root)

    def _identity(self):
        no_links(self.root)
        info = self.root.stat()
        return [info.st_dev, info.st_ino]

    def verify(self, state, host, session_id):
        path = self.hooks.path(self.root, host, session_id)
        verify_epoch_state(state, path)
        status = self.service.status(epoch_ref=state['epoch_ref'])
        if (state['workspace_id'] != identity(os.path.normcase(str(self.root)))
                or state['host'] != host or state['session_id'] != identity(session_id or 'default')
                or state['root_identity'] != self._identity()
                or status.get('state') != 'SEALED' or status.get('epoch_ref') != state['epoch_ref']
                or status.get('root_identity') != state['root_identity']
                or status.get('workspace_id') != state['workspace_id']
                or status.get('policy_digest') != state['policy_digest']
                or status.get('representation') != 'HASH_ONLY'):
            raise ValueError('Product epoch Hook binding changed')
        return status

    @staticmethod
    def describe(result, status):
        result.update(product_epoch_ref=status.get('epoch_ref'), product_epoch_state=status.get('state'),
            product_epoch_policy_digest=status.get('policy_digest'),
            comparison_kind='PRODUCT_COMPARISON', comparison_consistency='OBSERVED_ONLY',
            comparison_representation='HASH_ONLY',
            task_baseline_requirement='SYNCHRONOUS_BEFORE_FIRST_EDIT',
            product_epoch_gap_count=status.get('gaps', {}).get('count'),
            product_epoch_observed_path_count=status.get('counts', {}).get('observed'),
            product_epoch_project_inventory_complete=status.get('project_inventory_complete', False),
            product_epoch_strict_task_preimage_eligible=False)
        if result.get('event') == 'SESSION_START':
            result['task_baseline_ready'] = False

    def start(self, result, host, session_id):
        path = self.hooks.path(self.root, host, session_id)
        before, recovered = self.hooks.load(path)
        if before is not None and before.get('schema_version') != SCHEMA:
            return False
        result.update(event_dispatch_route='SESSION_BASELINE',
            baseline_state_before='AVAILABLE' if before else 'INVALID' if recovered else 'MISSING',
            baseline_state_after='AVAILABLE' if before else 'MISSING', baseline_publish_status='NOT_ATTEMPTED',
            pending_mutation=self.hooks.pending_activity(self.root, host, session_id) is not None,
            scanner_invocation_count=0, scanner_trigger_reason=None,
            scanner_skipped_reason='PRODUCT_OBSERVATION_ONLY', project_scan_status='NOT_REQUESTED',
            initial_scope='PRODUCT_COMPARISON_ONLY', mutation_event_dropped=False, state_recovered=recovered)
        if recovered:
            raise ValueError('Original Hook state cannot be verified')
        if before is not None:
            status = self.verify(before, host, session_id)
            self.describe(result, status)
            result.update(status='BASELINE_ESTABLISHED', baseline_available=True, snapshot_available=True,
                baseline_publish_status='RETAINED', snapshot_source='PRODUCT_OBSERVED_EPOCH',
                snapshot_generation=before['epoch_ref'], next_step='The original product observation remains bound; it is not task-before evidence.')
            return True
        owner = dict(host=host, session=identity(session_id or 'default'))
        status = self.service.status()
        if status.get('epoch_ref') is None:
            status = self.service.ensure(owner)
        if status.get('state') not in {'SEALED', 'CAPTURE_CONFLICT', 'WAITING_CAPACITY', 'CANCELLED',
                                      'HISTORY_UNAVAILABLE', 'BUSY', 'PLATFORM_UNSUPPORTED'}:
            status = self.service.step(owner)
        self.describe(result, status)
        if status.get('state') != 'SEALED':
            result.update(status='BASELINE_PENDING', baseline_available=False, snapshot_available=False,
                baseline_publish_status='PENDING', reason='PRODUCT_EPOCH_' + str(status.get('state', 'UNAVAILABLE')),
                next_step='Continue the original bounded product observation; pending mutations remain recorded.')
            return True
        state = dict(schema_version=SCHEMA, workspace_id=result['workspace_id'], state_id=path.stem,
            host=host, session_id=result['session_id'], root_identity=self._identity(),
            epoch_ref=status['epoch_ref'], policy_digest=status['policy_digest'],
            kind='PRODUCT_COMPARISON', consistency='OBSERVED_ONLY', representation='HASH_ONLY',
            last_processed_ref=None)
        key = self.hooks.key(self.root)
        state['signature'] = _signature(state, key)
        # The existing workspace OS lock only protects this short CAS. File
        # enumeration and observations ran outside it, without a quiet-tree gate.
        with self.hooks.lock(self.root, wait_seconds=2) as acquired:
            if not acquired:
                result.update(status='BASELINE_PENDING', baseline_publish_status='PENDING',
                    reason='PRODUCT_EPOCH_PUBLICATION_BUSY')
                return True
            current, invalid = self.hooks.load(path)
            if invalid or self.hooks.key(self.root) != key:
                raise ValueError('Product epoch Hook state changed concurrently')
            if current != before:
                if (current is not None and current.get('schema_version') == SCHEMA
                        and current.get('epoch_ref') == state['epoch_ref']
                        and current.get('policy_digest') == state['policy_digest']):
                    self.verify(current, host, session_id)
                    result.update(status='BASELINE_ESTABLISHED', baseline_available=True, snapshot_available=True,
                        baseline_state_after='AVAILABLE', baseline_publish_status='RETAINED',
                        snapshot_source='PRODUCT_OBSERVED_EPOCH', snapshot_generation=current['epoch_ref'],
                        next_step='The concurrently published original product observation remains bound.')
                    return True
                raise ValueError('Product epoch Hook state changed concurrently')
            self.verify(state, host, session_id)
            self.hooks.save(path, state)
        result.update(status='BASELINE_ESTABLISHED', baseline_available=True, snapshot_available=True,
            baseline_state_after='AVAILABLE', baseline_publish_status='PUBLISHED',
            snapshot_source='PRODUCT_OBSERVED_EPOCH', snapshot_generation=state['epoch_ref'],
            next_step='A sealed product observation is bound; task-before evidence and security checks remain separate.')
        from .recent_hooks import observe
        observe('BASELINE_PUBLISHED', **result)
        return True

    def compare(self, state, host, session_id, paths, scope_unknown, *, event_ref=None):
        """Compare only the finite event hints, never re-enumerate the tree."""
        from .hook_runtime import safe_path, MAX_BYTES
        status = self.verify(state, host, session_id)
        if (not isinstance(paths, (tuple, list)) or len(paths) > 1000
                or type(scope_unknown) is not bool):
            raise ValueError('Invalid product observation event scope')
        names = sorted({safe_path(name) for name in paths})
        key, consumed = self.hooks.key(self.root), 0
        counts = dict(compared=0, changed=0, matched=0, unobserved=0, unavailable=0)
        for offset in range(0, len(names), 256):
            deadline = time.monotonic() + CURRENT_BATCH_SECONDS
            page = self.service.lookup(state['epoch_ref'], names[offset:offset+256])
            rows = page['results']
            if ([row.get('path') for row in rows] != names[offset:offset+256]
                    or page.get('epoch_ref') != state['epoch_ref']
                    or page.get('policy_digest') != state['policy_digest']):
                raise ValueError('Product observation lookup binding changed')
            for row in rows:
                if row.get('observed') is not True:
                    counts['unobserved'] += 1
                    continue
                if row.get('hash_algorithm') != 'HMAC_SHA256_HOOK_FILE_V1' or not _hex(row.get('hash')):
                    raise ValueError('Invalid product observation hash')
                reader = None
                try:
                    if time.monotonic() >= deadline or self._identity() != state['root_identity']:
                        raise ValueError('Current observation budget or root changed')
                    reader = StableHashReader(self.root, key, row['path'],
                                              expected_root_identity=state['root_identity'])
                    allowance = min(CURRENT_FILE_BYTES, max(0, MAX_BYTES-consumed))
                    if reader.size > allowance:
                        raise ValueError('Current observation byte budget exceeded')
                    observed = reader.advance(allowance, deadline)
                    consumed += observed['bytes_read']
                    if (observed['state'] == 'PENDING' and reader.read_bytes == reader.size
                            and time.monotonic() < deadline and reader._stable()):
                        # Reading the exact bound can leave no byte allowance
                        # for an EOF probe. All original bytes plus a repeated
                        # descriptor/path revision check establish completion;
                        # no extra byte or raw body is retained by this adapter.
                        observed = dict(state='OBSERVED', hash=reader.digest.hexdigest())
                    if (observed['state'] != 'OBSERVED' or time.monotonic() >= deadline
                            or self._identity() != state['root_identity']):
                        raise ValueError('Current observation unavailable')
                    digest = observed['hash']
                except FileNotFoundError:
                    try:
                        root_current = self._identity() == state['root_identity']
                    except (OSError, ValueError):
                        root_current = False
                    if not root_current or time.monotonic() >= deadline:
                        counts['unavailable'] += 1
                        continue
                    digest = hmac.new(key, b'hook-file-deleted-v1', hashlib.sha256).hexdigest()
                except (OSError, ValueError):
                    counts['unavailable'] += 1
                    continue
                finally:
                    if reader is not None:
                        reader.close()
                counts['compared'] += 1
                counts['matched' if hmac.compare_digest(digest, row['hash']) else 'changed'] += 1
        gap = scope_unknown or not names or bool(counts['unobserved'] or counts['unavailable'])
        # This cursor acknowledges comparison delivery only, never a security
        # check or unknown Shell scope. No pending-activity row is cleared here.
        if not gap and event_ref is not None:
            updated = dict(state, last_processed_ref=identity(event_ref))
            updated['signature'] = _signature(updated, key)
            with self.hooks.lock(self.root, wait_seconds=2) as acquired:
                current, invalid = self.hooks.load(self.hooks.path(self.root, host, session_id))
                if not acquired or invalid or current != state:
                    raise ValueError('Product epoch Hook state changed concurrently')
                self.verify(updated, host, session_id)
                self.hooks.save(self.hooks.path(self.root, host, session_id), updated)
            state = updated
        return state, dict(product_epoch_ref=state['epoch_ref'], product_epoch_state=status['state'],
            comparison_kind='PRODUCT_COMPARISON', comparison_consistency='OBSERVED_ONLY',
            comparison_representation='HASH_ONLY', product_epoch_strict_task_preimage_eligible=False,
            product_epoch_policy_digest=state['policy_digest'], product_epoch_comparison_scope='EVENT_PATHS_ONLY',
            product_epoch_comparison_complete=not gap, product_epoch_scope_unknown=scope_unknown or not names,
            product_epoch_compared_path_count=counts['compared'], product_epoch_changed_path_count=counts['changed'],
            product_epoch_unobserved_path_count=counts['unobserved'], product_epoch_unavailable_path_count=counts['unavailable'],
            product_epoch_comparison_reason='FIRST_OBSERVED_ORDER_UNKNOWN' if counts['unobserved'] else
                'EVENT_SCOPE_UNKNOWN' if scope_unknown or not names else 'CURRENT_PATH_UNAVAILABLE' if counts['unavailable'] else
                'OBSERVED_HASH_DELTA' if counts['changed'] else 'OBSERVED_HASH_MATCH')
