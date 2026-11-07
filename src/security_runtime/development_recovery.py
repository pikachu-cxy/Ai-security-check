"""Recover an existing native edit batch, outside the normal scan/Stop path."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import subprocess
import time

from .development_check import DevelopmentCheckService, DevelopmentCheckStore, owner_key, legacy_guard
from .user_config import batch_config
from .performance_trace import timed


def eligible(row):
    activities = [row.get('stop_activity', {}), *row.get('stop_activity_previous', ())]
    return (row.get('effective_config') and batch_config(row)['development']['stop_fallback']['enabled']
        and any(a.get('turn') and row['dirty_seq'] > a.get('base_seq', row['dirty_seq']) for a in activities))


@timed('recovery.handoff')
def resume(hooks, root, owner, *, launcher=None, _ref=None, _depth=0):
    """Only inspect the signed focus of this owner; never inventory projects."""
    if owner.get('host') != 'codex':
        return None
    store = DevelopmentCheckStore(hooks, root)
    if not store.path.exists():
        return None
    focus = store.read('focus:' + owner_key(owner))
    if not focus:
        return None
    row = store.load(_ref or focus['check_ref'], owner)
    if row.get('previous_closeout_ref') and _depth < 8:
        previous = resume(hooks, root, owner, launcher=launcher,
                          _ref=row['previous_closeout_ref'], _depth=_depth+1)
        if previous:
            return previous
    if not eligible(row) or legacy_guard(hooks, root, owner) is not None:
        return None
    from .development_stop import saved_handoff, incomplete_notice
    saved = saved_handoff(hooks, root, owner, row)
    if saved:
        return saved
    import_pending = row.get('scan_id') and row.get('risk_import_status') == 'UNAVAILABLE'
    if (row['dirty_seq'] <= row['scanned_seq'] and not import_pending) or row['state'] == 'FAILED':
        return None
    # Lease the recovery launcher, not the scan. The existing worker still owns
    # scan admission, retries and atomic publication. Concurrent reconnects merge.
    key = 'recovery:' + row['check_ref']
    ticket = secrets.token_hex(32)
    with store.transaction() as db:
        current = store._get(db, row['check_ref'])
        old = store._get(db, key) or {}
        if current['dirty_seq'] != row['dirty_seq']:
            return None
        attempts = old.get('attempts', 0) if old.get('seq') == row['dirty_seq'] else 0
        terminal = old.get('seq') == row['dirty_seq'] and (old.get('status') == 'RECOVERY_FAILED' or attempts >= 3)
        launch = not terminal and old.get('lease_until', 0) <= store.now()
        if launch:
            store._put(db, key, dict(kind='recovery', ticket=ticket, seq=row['dirty_seq'],
                lease_until=store.now()+120, status='QUEUED', attempts=attempts+1, requested_at=store.now()))
    if launch:
        try:
            (launcher or launch_recovery)(hooks, root, row['check_ref'], ticket)
        except OSError:
            with store.transaction() as db:
                request = store._get(db, key)
                if request and request['ticket'] == ticket:
                    store._put(db, key, dict(request, lease_until=0, status='START_FAILED'))
            reason = 'RECOVERY_START_FAILED'
        else:
            reason = 'RECOVERY_PENDING'
    else:
        reason = 'RECOVERY_FAILED' if terminal else 'RECOVERY_PENDING'
    service = DevelopmentCheckService(None, hooks, owner=owner, scan_path_provider=row['scan_path'])
    return incomplete_notice(service, root, row['check_ref'], row['dirty_seq'], row, reason=reason)


def launch_recovery(hooks, root, ref, ticket):
    from .background_preparation import runtime_command
    argv = runtime_command()
    if '-m' in argv and '-I' not in argv:
        argv.insert(1, '-I')
    argv += ['development-recover', '--workspace', str(root), '--hooks', str(hooks.directory),
             '--check-ref', ref, '--ticket', ticket]
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, close_fds=True, **options)


@timed('recovery.resume')
def run(root, hooks_path, ref, ticket):
    from .hook_state import HookStateStore
    from .development_scheduler import recover_once
    hooks = HookStateStore(Path(hooks_path))
    store = DevelopmentCheckStore(hooks, root)
    key = 'recovery:' + ref
    request = store.read(key)
    if (not request or not secrets.compare_digest(request.get('ticket', ''), ticket)
            or request['lease_until'] <= store.now()):
        return 2
    row = store.load(ref)
    if not eligible(row) or row['dirty_seq'] != request['seq'] or legacy_guard(hooks, root, row['owner']):
        return 2
    service = DevelopmentCheckService(None, hooks, owner=row['owner'], scan_path_provider=row['scan_path'])
    status = 'RESUMED'
    try:
        if row.get('scan_id') and row.get('risk_import_status') == 'UNAVAILABLE':
            from .development_risks import DevelopmentRisks
            DevelopmentRisks(service, root, ref).sync_scanner()
        if not row['finish_requested']:
            service.finish(root, ref, recovery_seq=request['seq'])
        # Keep only this exception-path process alive while a submitted worker
        # needs supervision. It survives the original MCP/command Hook process.
        deadline = time.monotonic()+110
        while time.monotonic() < deadline:
            current = store.load(ref, row['owner'])
            if current['dirty_seq'] != request['seq'] or current['state'] not in {'QUEUED', 'RUNNING'}:
                break
            recover_once(hooks, root)
            time.sleep(1)
    except (OSError, ValueError):
        status = 'RECOVERY_FAILED'
    finally:
        with store.transaction() as db:
            current = store._get(db, key)
            if current and current['ticket'] == ticket:
                store._put(db, key, dict(current, lease_until=0, status=status,
                    attempts=0 if status == 'RESUMED' else current.get('attempts', 1), completed_at=store.now()))
    return 0 if status == 'RESUMED' else 2
