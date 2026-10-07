"""Signed setup comparison points. No trust bypass, source or remediation storage."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import time

from ._version import __version__
from .hook_state import HookStateStore, MAX_STATE_BYTES, atomic_bytes, identity, no_links
from .progress import ScanCancelled

SCHEMA = 'workspace-baseline-v1'
NAME = 'baseline-seed.json'


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


class WorkspaceBaselineSeeds:
    def __init__(self, integration=None, *, coordinator=None, now=time.time):
        if integration is None:
            from .codex_integration import CodexIntegrationAdapter
            integration = CodexIntegrationAdapter()
        self.integration = integration
        self.coordinator = coordinator
        self.now = now

    def path(self, root):
        return self.integration._state_path(root, NAME)

    def binding(self, root):
        from .codex_integration import fingerprint
        from .rulepacks import RulePackManager
        from .toolchain import VERSIONS
        adapter = self.integration
        manifest = adapter._manifest(root)
        configs = adapter._config(root)
        desired = adapter._desired(root)
        diagnostics, _, _ = adapter._inspection(root, configs, manifest, desired)
        if diagnostics or not manifest or manifest['phase'] != 'COMMITTED' or manifest['records'] != [desired[-1]]:
            raise ValueError('Baseline integration binding is not current')
        pack = RulePackManager().resolve()
        # Conservative compatibility contract, not source snapshot equality.
        # Exact actual scanner versions/coverage proofs also remain in projection.
        return dict(workspace_id=identity(os.path.normcase(str(root))), schema=SCHEMA,
            runtime_version=__version__, hook_schema='hook-v1', quick_providers='semgrep-gitleaks-v1',
            rule_pack=pack.checksum, catalog=identity(encode([asdict(r) for r in pack.catalog]).decode()),
            scanner_versions={n: VERSIONS[n] for n in ('semgrep', 'gitleaks')}, config=fingerprint(desired[-1]))

    def load(self, root):
        """Read only; reject corruption without reflecting or quarantining it."""
        try:
            path = self.path(root)
            if not path.exists():
                return None, 'NOT_ESTABLISHED'
            raw = self.integration._read(path, MAX_STATE_BYTES)
            from .codex_integration import unique_json
            value = unique_json(raw)
            if not isinstance(value, dict) or set(value) != {'schema', 'binding', 'status', 'reason', 'snapshot', 'created_at', 'signature'}:
                raise ValueError()
            signature = value.pop('signature')
            key = self.integration._read(self.integration._state_path(root, 'snapshot.key'), 32)
            if len(key) != 32 or not isinstance(signature, str) or not hmac.compare_digest(
                    signature, hmac.new(key, encode(value), hashlib.sha256).hexdigest()):
                raise ValueError()
            if (value['schema'] != SCHEMA or value['binding'] != self.binding(root)
                    or type(value['created_at']) not in (int, float) or not math.isfinite(value['created_at'])
                    or not 0 <= value['created_at'] <= self.now()):
                return None, 'STALE'
            if value['status'] not in {'READY', 'INCONCLUSIVE'} or value['reason'] not in {
                    'PRE_EXISTING_BASELINE', 'BASELINE_CHECK_INCONCLUSIVE'}:
                raise ValueError()
            if value['status'] != 'READY':
                if value['snapshot'] is not None:
                    raise ValueError()
                return None, 'INCONCLUSIVE'
            from .hook_runtime import validate_state
            snapshot = validate_state(value['snapshot'])
            if (snapshot['workspace_id'] != value['binding']['workspace_id'] or snapshot['host'] != 'codex'
                    or snapshot['session_id'] != identity('setup-seed')
                    or snapshot['last_result']['status'] != 'PRE_EXISTING_BASELINE'
                    or snapshot['last_result']['delta']['new'] != 0):
                raise ValueError()
            # The owned config might have changed while files were read.
            if value['binding'] != self.binding(root):
                return None, 'STALE'
            return snapshot, 'READY'
        except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError):
            return None, 'STALE'

    @staticmethod
    def status_value(status, operation=None):
        value = {'status': status, 'source': 'SETUP_SEED'}
        if operation:
            value['operation'] = operation
        if status == 'STALE':
            value['reason'] = 'BASELINE_SEED_STALE'
        return value

    def status(self, root):
        _, status = self.load(root)
        return self.status_value(status)

    def ensure(self, root, *, reestablish=False):
        """Called only under integration ownership lock after successful config."""
        previous, status = self.load(root)
        if previous is not None:
            return self.status_value('READY', 'BASELINE_READY')
        existed = self.path(root).exists()
        binding = self.binding(root)
        snapshot = None
        try:
            snapshot = self._capture(root)
            if binding != self.binding(root):
                snapshot = None
        except (ValueError, OSError, TypeError, KeyError, UnicodeError, RecursionError, ScanCancelled):
            pass
        value = dict(schema=SCHEMA, binding=binding, status='READY' if snapshot else 'INCONCLUSIVE',
            reason='PRE_EXISTING_BASELINE' if snapshot else 'BASELINE_CHECK_INCONCLUSIVE',
            snapshot=snapshot, created_at=self.now())
        key = self.integration.store.key(root)
        signed = {**value, 'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()}
        raw = encode(signed)
        if len(raw) > MAX_STATE_BYTES:
            value.update(status='INCONCLUSIVE', reason='BASELINE_CHECK_INCONCLUSIVE', snapshot=None)
            raw = encode({**value, 'signature': hmac.new(key, encode(value), hashlib.sha256).hexdigest()})
        atomic_bytes(self.path(root), raw)
        return self.status_value(value['status'],
            ('BASELINE_REESTABLISHED' if existed or reestablish else 'BASELINE_ESTABLISHED') if value['status'] == 'READY'
            else 'BASELINE_CHECK_INCONCLUSIVE')

    def remove(self, root):
        self.path(root).unlink(missing_ok=True)

    def capture_session(self, root, session_id, *, host='codex'):
        """Establish the same bounded comparison point for a global session.

        Capture, byte recheck and publication share the workspace lock. This is
        a comparison projection, never a remediation or security receipt.
        """
        if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 500:
            raise ValueError('Invalid baseline session')
        from .hook_runtime import HOSTS
        if host not in HOSTS:
            raise ValueError('Unsupported baseline host')
        return self._capture(root, session_id=session_id, host=host)

    def _capture(self, root, *, session_id=None, host='codex'):
        from .hook_runtime import (HookCoordinator, HookSnapshot, MAX_FILES, MAX_BYTES,
            capture_snapshot, safe_path, validate_state, _git)
        from .target import TargetDetector, IGNORED
        core = self.coordinator or HookCoordinator()
        if core.store.directory.absolute().is_relative_to(root):
            raise ValueError('Baseline state must be outside workspace')
        def inventory(key):
            names = sorted({safe_path(n.decode('utf-8')) for n in
                _git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').split(b'\0') if n})
            names = [n for n in names if not set(Path(n).parts) & IGNORED]
            if len(names) > MAX_FILES:
                raise ValueError('Baseline file budget exceeded')
            files = TargetDetector(max_files=MAX_FILES).detect(root, names).files
            digest = hmac.new(key, b'workspace-baseline-inventory-v1', hashlib.sha256)
            size = 0
            for name in files:
                no_links(root / name)
                digest.update(encode(name))
                with (root / name).open('rb') as stream:
                    consumed = 0
                    while chunk := stream.read(65536):
                        size += len(chunk); consumed += len(chunk)
                        if size > MAX_BYTES or consumed > 1_000_000:
                            raise ValueError('Baseline content budget exceeded')
                        digest.update(chunk)
            return digest.hexdigest(), files
        with core.store.lock(root, wait_seconds=2) as locked:
            if not locked:
                raise ValueError('Baseline scan busy')
            key = core.store.key(root)
            if session_id is not None:
                # Reconnect/duplicate SessionStart must not overwrite the last
                # processed pre-edit comparison point with post-edit bytes.
                previous, _ = core.store.load(core.store.path(root, host, session_id))
                if previous and (previous['workspace_id'], previous['host'], previous['session_id']) == (
                        identity(os.path.normcase(str(root))), host, identity(session_id)):
                    return previous
            captured = capture_snapshot(root, key)
            dirty_digest, dirty_files = captured
            full_digest, scope = inventory(key)
            result = dict(status='NO_CHANGES', coverage='NONE', execution_state='NO_CHANGES',
                scan_id=None, capabilities={}, scanner_runs=[], execution={'scanner_run': False})
            observation = core._scan_scope(result, root, scope, baseline=True)
            after_capture = capture_snapshot(root, key)
            if (after_capture[0] != dirty_digest or after_capture.file_digests != captured.file_digests
                    or inventory(key) != (full_digest, scope)):
                raise ValueError('Baseline source changed')
            # Empty workspace is a proven empty comparison point. For nonempty
            # scope require every requested quick capability, never partial proof.
            if scope and (result['status'] != 'SCANNED' or result['coverage'] not in {'FULL', 'SCOPED'}
                    or any(v not in {'EXECUTED', 'NOT_APPLICABLE'} for v in result['capabilities'].values())):
                raise ValueError('Baseline coverage insufficient')
            delta = dict(new=0, persisting=0, resolved=0, additional_occurrences=0, removed_occurrences=0, families=[])
            summary = {k: result[k] for k in ('coverage', 'execution_state', 'capabilities', 'scanner_runs')}
            summary.update(status='PRE_EXISTING_BASELINE', last_check_status=result['status'], delta=delta)
            snapshot = validate_state(asdict(HookSnapshot('hook-v1', identity(os.path.normcase(str(root))), host,
                identity(session_id if session_id is not None else 'setup-seed'), dirty_digest, dirty_files,
                observation['families'], result['scan_id'], self.now(), summary, captured.file_digests)))
            if session_id is not None:
                core.store.save(core.store.path(root, host, session_id), snapshot)
            return snapshot
