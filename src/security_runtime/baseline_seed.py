"""Signed setup comparison points. No trust bypass, source or remediation storage."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import math
import os
import subprocess
from pathlib import Path
import time

from ._version import __version__
from .hook_state import HookStateStore, MAX_STATE_BYTES, atomic_bytes, identity, no_links
from .progress import ScanCancelled
from .bootstrap_diagnostics import BaselinePreparationError

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

        Capture and publication use short workspace locks. The slow scanner
        runs outside that lock; byte/version checks fence publication. This is
        a comparison projection, never a remediation or security receipt.
        """
        if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 500:
            raise ValueError('Invalid baseline session')
        from .hook_runtime import HOSTS
        if host not in HOSTS:
            raise ValueError('Unsupported baseline host')
        return self._capture(root, session_id=session_id, host=host)

    def existing_session(self, root, session_id, *, host='codex'):
        """Read the original comparison point, without locking, scans or writes.

        Atomic state publication permits a bounded read before the workspace
        lock. A busy check must not prevent reconnecting to an existing session.
        This never imports another session or constructs a post-edit baseline.
        """
        if self.coordinator is None:
            return None
        core = self.coordinator
        if core.store.directory.absolute().is_relative_to(root):
            raise ValueError('Baseline state must be outside workspace')
        previous, _ = core.store.load(core.store.path(root, host, session_id))
        if previous and (previous['workspace_id'], previous['host'], previous['session_id']) == (
                identity(os.path.normcase(str(root))), host, identity(session_id)):
            return previous
        return None

    def _capture(self, root, *, session_id=None, host='codex'):
        from .hook_runtime import (HookCoordinator, HookSnapshot, MAX_FILES, MAX_BYTES,
            capture_snapshot, safe_path, validate_state, _git)
        from .target import TargetDetector, IGNORED
        core = self.coordinator or HookCoordinator()
        if core.store.directory.absolute().is_relative_to(root):
            raise ValueError('Baseline state must be outside workspace')
        if session_id is not None:
            previous = self.existing_session(root, session_id, host=host)
            if previous is not None:
                return previous
        def inventory(key):
            try:
                raw = _git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z')
            except (ValueError, subprocess.TimeoutExpired) as exc:
                raise BaselinePreparationError('BASELINE_GIT_SNAPSHOT_UNAVAILABLE') from exc
            names = sorted({safe_path(n.decode('utf-8')) for n in raw.split(b'\0') if n})
            names = [n for n in names if not set(Path(n).parts) & IGNORED]
            if len(names) > MAX_FILES:
                raise BaselinePreparationError('BASELINE_FILE_BUDGET_EXCEEDED')
            files = TargetDetector(max_files=MAX_FILES).detect(root, names, select_scan_targets=True).files
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
                            raise BaselinePreparationError('BASELINE_CONTENT_BUDGET_EXCEEDED')
                        digest.update(chunk)
            return digest.hexdigest(), files
        with core.store.lock(root, wait_seconds=2) as locked:
            if not locked:
                raise BaselinePreparationError('BASELINE_BUSY')
            key = core.store.key(root)
            if session_id is not None:
                # Reconnect/duplicate SessionStart must not overwrite the last
                # processed pre-edit comparison point with post-edit bytes.
                previous = self.existing_session(root, session_id, host=host)
                if previous is not None:
                    return previous
            captured = capture_snapshot(root, key)
            self.target_selection = getattr(captured, 'target_selection', None)
            dirty_digest, dirty_files = captured
            full_digest, scope = inventory(key)
        # Initial scanning must not monopolize the edit/task state lock for its
        # entire duration. A task can capture its own pre-edit bytes meanwhile.
        # This worker may publish only if those original bytes still match.
        result = dict(status='NO_CHANGES', coverage='NONE', execution_state='NO_CHANGES',
            scan_id=None, capabilities={}, scanner_runs=[], execution={'scanner_run': False})
        observation = core._scan_scope(result, root, scope, baseline=True)
        with core.store.lock(root, wait_seconds=2) as locked:
            if not locked:
                raise BaselinePreparationError('BASELINE_BUSY')
            if session_id is not None:
                # Another valid writer may already have published/processed
                # this session. Preserve its point instead of overwriting it.
                previous = self.existing_session(root, session_id, host=host)
                if previous is not None:
                    return previous
            if core.store.key(root) != key:
                raise BaselinePreparationError('BASELINE_SOURCE_CHANGED')
            after_capture = capture_snapshot(root, key)
            if (after_capture[0] != dirty_digest or after_capture.file_digests != captured.file_digests
                    or inventory(key) != (full_digest, scope)):
                raise BaselinePreparationError('BASELINE_SOURCE_CHANGED')
            # A comparison point can retain explicit unsupported-code gaps.
            # Failed/missing engine evidence still prevents publication; no
            # partial coverage is upgraded into security proof.
            from .baseline_coverage import comparison_usable, unproven_files
            if scope and not comparison_usable(result, observation):
                raise BaselinePreparationError('BASELINE_COVERAGE_INSUFFICIENT')
            delta = dict(new=0, persisting=0, resolved=0, additional_occurrences=0, removed_occurrences=0, families=[])
            summary = {k: result[k] for k in ('coverage', 'execution_state', 'capabilities', 'scanner_runs')}
            summary.update(status='PRE_EXISTING_BASELINE', last_check_status=result['status'], delta=delta)
            snapshot = validate_state(asdict(HookSnapshot('hook-v1', identity(os.path.normcase(str(root))), host,
                identity(session_id if session_id is not None else 'setup-seed'), dirty_digest, dirty_files,
                observation['families'], result['scan_id'], self.now(), summary, captured.file_digests,
                unproven_files(observation))))
            if session_id is not None:
                core.store.save(core.store.path(root, host, session_id), snapshot)
            return snapshot
