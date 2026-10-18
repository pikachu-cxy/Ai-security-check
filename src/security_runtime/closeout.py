"""One offline Runtime closeout plan shared by Hook and ordinary MCP calls."""
from __future__ import annotations

from dataclasses import asdict
import os
import sqlite3
from pathlib import Path
from time import perf_counter

from .closeout_state import CloseoutStateStore, digest
from .hook_state import HookStateStore, identity
from .hook_runtime import safe_path, capture_snapshot, incremental_scope
from .risk_closure import RiskClosureService, family_row
from .secret_coverage import digest as file_digest
from .target import TargetDetector
from .verification import VerificationService
from .verification_policy import local_recheck
from .workspace import WorkspaceResolver

MAX_FILES = 1000
MAX_BYTES = 20_000_000
MAX_ATTEMPTS = 3


class CloseoutService:
    def __init__(self, runtime, hooks=None):
        self.runtime = runtime
        self.hooks = hooks or HookStateStore(runtime.store.path.parent / 'hooks')
        self.closures = RiskClosureService(self.hooks)
        from .build_identity import build_identity
        self.build = build_identity()

    def _root(self, workspace):
        return WorkspaceResolver().resolve(workspace, allow_non_git_explicit=True).path

    def _store(self, root):
        return CloseoutStateStore(self.hooks.workspace_directory(root) / 'closeout.db', lambda: self._read_key(root))

    def _read_key(self, root):
        from .hook_state import no_links
        path = self.hooks.workspace_directory(root) / 'snapshot.key'
        no_links(path)
        key = path.read_bytes()
        if len(key) != 32:
            raise ValueError('Closeout key cannot be verified')
        return key

    def _workspace(self, root):
        return identity(os.path.normcase(str(root)))

    def _source_revisions(self, root, scope):
        from .target import DEPENDENCIES
        # Match the Core provider's dependency context without reading .env or
        # arbitrary project documents. Missing targets remain explicit entries.
        context = {p.name for p in root.iterdir() if p.is_file() and (p.name in DEPENDENCIES or p.name == 'Dockerfile')}
        names = sorted(set(scope) | context)
        if len(names) > MAX_FILES + 100:
            raise ValueError('Closeout scope budget exceeded')
        total, revisions = 0, {}
        for name in names:
            safe_path(name)
            if Path(name).name.startswith('.env'):
                raise ValueError('Environment files are outside this closeout request')
            path = root / name
            from .hook_state import no_links
            no_links(path)
            if not path.is_file():
                revisions[name] = 'MISSING'
                continue
            total += path.stat().st_size
            if total > MAX_BYTES:
                raise ValueError('Closeout content budget exceeded')
            revisions[name] = file_digest(path)
        return revisions

    def _revision(self, root, scope):
        return digest(self.hooks.key(root), self._source_revisions(root, scope))

    def _plan_facts(self, root, scope, members, deferred, exclusions=()):
        # No code/config changes can reuse an older provider plan.
        from .rulepacks import RulePackManager
        plan = {'scope': scope, 'members': members, 'deferred': deferred,
            'build': self.build['build_id'], 'rules': RulePackManager().resolve().checksum,
            'credential_protection_present': [(root / name).exists() for name in ('.gitleaks.toml', '.gitleaksignore')] +
                [bool(os.getenv(name)) for name in ('GITLEAKS_CONFIG', 'GITLEAKS_CONFIG_TOML')],
            'providers': [a.name for a in self.runtime.registry.adapters]}
        if exclusions:
            plan['scope_exclusions'] = exclusions
        return plan

    def _plan(self, root, scope, members, deferred, exclusions=()):
        return digest(self.hooks.key(root), self._plan_facts(root, scope, members, deferred, exclusions))

    def prepare(self, workspace, files=None, *, host=None, session=None, source_scan_id=None,
                source='MANUAL_CLOSEOUT', pending=None):
        root = self._root(workspace)
        self.hooks.key(root)  # Preparation is a write; status reads never create keys.
        families, deferred = {}, []
        if host and session:
            state, _ = self.hooks.load(self.hooks.path(root, host, session))
            if state:
                families, _ = self.closures.overlay(root, state['families'], state['last_result']['delta'])
                source_scan_id = state['last_scan_id']
                deferred = list(state['last_result'].get('deferred_code_providers', []))
            pending = self.hooks.pending_activity(root, host, session)
        scan = self.runtime.store.get_scan(source_scan_id) if source_scan_id else None
        if scan:
            if Path(scan['target_profile']['path']).resolve() != root:
                raise ValueError('Source scan does not belong to this workspace')
            deferred = sorted(set(deferred) | set(scan.get('rule_coverage', {}).get('deferred_providers', [])))
        automatic_scope = files is None
        if automatic_scope:
            if host and session:
                if WorkspaceResolver().resolve(root, allow_non_git_explicit=True).is_git:
                    captured = capture_snapshot(root, self.hooks.key(root))
                else:
                    from .global_workspace import source_snapshot
                    captured = source_snapshot(root, self.hooks.key(root))
                before = state.get('file_digests') if state else None
                changed = ({name for name in set(before) | set(captured.file_digests)
                            if before.get(name) != captured.file_digests.get(name)}
                           if before is not None else None)
                # Recheck the actual preceding scan, current byte changes and
                # original findings, not every file staged before this task.
                # Missing scan evidence retains the legacy conservative scope.
                checked = (scan.get('scan_context', {}).get('input_files', scan['target_profile']['files'])
                           if scan else state.get('changed_files', []) if state else [])
                files = incremental_scope(state, captured[1], changed, checked_files=checked)
                files = sorted(set(files) | {f['file_path'] for f in families.values()})
            elif scan:
                files = scan.get('scan_context', {}).get('input_files', scan['target_profile']['files'])
            else:
                raise ValueError('Explicit files or a source scan are required')
        if not isinstance(files, list) or len(files) > MAX_FILES:
            raise ValueError('Closeout scope budget exceeded')
        scope = sorted({safe_path(name) for name in files})
        exclusions = []
        if automatic_scope:
            # Git snapshots include environment files. Keep the closeout's
            # existing boundary, but make that limitation explicit instead of
            # aborting every Stop before its completion record can be saved.
            from .hook_state import no_links
            for name in scope:
                if Path(name).name.startswith('.env'):
                    no_links(root / name)
                    exclusions.append({'file_path': name,
                                       'reason': 'ENVIRONMENT_FILE_OUTSIDE_CLOSEOUT_SCOPE'})
            excluded_paths = {row['file_path'] for row in exclusions}
            scope = [name for name in scope if name not in excluded_paths]
        else:
            excluded_paths = set()
        if not families and scan:
            # Manual closeouts also retain every original Secret detector.
            from .risk_closure import original_family
            families = {equivalence_key(row): original_family(row) for row in scan['findings']
                        if row['category'] == 'secret' and row['file_path'] in set(scope) | excluded_paths}
        members = [family_row(f) for f in families.values()
                   if f['category'] == 'secret' and f['file_path'] not in excluded_paths]
        excluded_recheck = [{'file_path': f['file_path'], 'rule_id': f['rule_id'],
                             'detector': f['scanner_sources'],
                             'reason': 'ENVIRONMENT_FILE_OUTSIDE_CLOSEOUT_SCOPE'}
                            for f in families.values()
                            if f['category'] == 'secret' and f['file_path'] in excluded_paths]
        revision = self._revision(root, scope)
        plan = self._plan(root, scope, members, deferred, exclusions)
        session_key = identity(host + '\0' + session) if host and session else None
        details = dict(members=members, source=source, host=host, session=session,
                       session_key=session_key, pending_sequence=pending,
                       scope_exclusions=exclusions, excluded_recheck=excluded_recheck)
        store = self._store(root)
        previous = store.latest(self._workspace(root), session_key) if session_key else None
        if previous and previous['status'] in {'PENDING', 'RUNNING', 'NEEDS_RETRY'}:
            job = store.revise(previous['closeout_ref'], self._workspace(root), scope, revision, plan, details)
        elif (previous and previous['prepared_revision'] == revision and previous['plan_fingerprint'] == plan
              and pending is None):
            job = previous
        else:
            job = store.prepare(self._workspace(root), scope, revision, plan, source_scan_id=source_scan_id,
                                deferred=deferred, details=details)
        result = self._present(root, job)
        from .background_preparation import PreparationStore, current_preparation
        preparation = current_preparation()
        if preparation['status'] in {'QUEUED', 'PREPARING', 'RESUMING'} and not (job['status'] == 'COMPLETED' and result['current_version']):
            try:
                queued = PreparationStore().enqueue(root, job['closeout_ref'], self.hooks,
                    self.build['build_id'], self.runtime.store.path.parent, job['generation'])
                result['waiting_for_preparation'] = queued and not preparation.get('ready')
                result['background_registered'] = queued
            except (ValueError, OSError, sqlite3.DatabaseError):
                result['background_registered'] = False
        return result

    def _present(self, root, job):
        current = (self._revision(root, job['scope_files']) == job['prepared_revision'] and
                   self._plan(root, job['scope_files'], job['details']['members'], job['deferred_providers'],
                              job['details'].get('scope_exclusions', ())) == job['plan_fingerprint'])
        details = job['details']
        pending = self.hooks.pending_activity(root, details['host'], details['session']) if details.get('session_key') else None
        pending_new = pending is not None and pending != details['pending_sequence']
        current = current and not pending_new
        if job.get('receipt'):
            current = current and job['receipt']['generation'] == job['generation'] and job['receipt']['current_version']
        resolved = {r['finding_id'] for r in (job.get('receipt') or {}).get('risk_verification', [])
                    if current and r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED'}
        from .background_preparation import current_preparation
        preparation = current_preparation()
        return {k: job[k] for k in ('closeout_ref', 'generation', 'status', 'coverage', 'attempts', 'reason', 'receipt')} | {
            'background_preparation': preparation,
            'workspace': str(root), 'current_version': current, 'pending_new_events': pending_new,
            'source': job['details']['source'], 'scope_files': job['scope_files'],
            'scope_exclusions': details.get('scope_exclusions', []),
            'excluded_recheck': details.get('excluded_recheck', []),
            'deferred_providers': job['deferred_providers'],
            'pending_deferred_providers': job['deferred_providers'] if job['status'] != 'COMPLETED' or not current else [],
            'original_recheck_scope': [{'file_path': m['file_path'], 'detector': m['scanner_sources'],
                                 'rule_id': m['technical_details']['rule_id']} for m in job['details']['members']],
            'pending_recheck': [{'file_path': m['file_path'], 'rule_id': m['technical_details']['rule_id'],
                                 'detector': m['scanner_sources']} for m in details['members'] if m['id'] not in resolved] +
                               details.get('excluded_recheck', []),
            'execution_plan': {'tool': 'run_closeout_check', 'arguments': {
                'closeout_ref': job['closeout_ref'], 'workspace_path': str(root)}},
            'repair_authority': 'NONE', 'historical_scans': 'UNCHANGED'}

    def get(self, ref, workspace):
        root = self._root(workspace)
        job = self._store(root).get(ref, self._workspace(root))
        if job is None:
            raise ValueError('Closeout does not belong to this workspace')
        return self._present(root, job)

    def run(self, ref, workspace):
        root = self._root(workspace)
        store = self._store(root)
        job = store.get(ref, self._workspace(root))
        if job is None:
            raise ValueError('Closeout does not belong to this workspace')
        if self.hooks.lock_held(root):
            return self._present(root, job) | {'status': 'BUSY', 'reason': 'WORKSPACE_LOCK_BUSY'}
        from .closeout_persistence import drain as drain_persistence
        recovered = drain_persistence(self, root, ref)
        if recovered is not None:
            result = self._present(root, recovered['job'])
            accepted = recovered['state'] == 'APPLIED' and result['current_version']
            return result | {'persistence_recovery': {k: v for k, v in recovered.items() if k != 'job'},
                'recovered': True, 'scanner_run': False, 'execution_accepted': accepted,
                'source_result_saved': True,
                'risk_status': 'CONFIRMED_CLOSED' if accepted and
                    (result.get('receipt') or {}).get('risk_fix_complete') else 'UNCONFIRMED_OR_PRESENT'}
        if (job.get('receipt') or {}).get('persistence_sync', {}).get('state') == 'PENDING':
            raise ValueError('Closeout persistence source cannot be found')
        from .background_preparation import current_preparation, PreparationStore, preparation_message
        preparation = current_preparation()
        if preparation['status'] in {'QUEUED', 'PREPARING'} and not preparation.get('ready'):
            try:
                registered = PreparationStore().enqueue(root, ref, self.hooks, self.build['build_id'], self.runtime.store.path.parent, job['generation'])
            except (ValueError, OSError, sqlite3.DatabaseError):
                registered = False
            return self._present(root, job) | {'waiting_for_preparation': True, 'background_registered': registered,
                'reason': 'WAITING_FOR_SCAN_PREPARATION', 'automatic_retry': False,
                'user_feedback': {'message': preparation_message(preparation) + ' 缺失项保留待检；准备完成后接续原任务。', 'choices': []}}
        details = job['details']
        if details.get('session_key'):
            pending = self.hooks.pending_activity(root, details['host'], details['session'])
            if pending is not None and pending != details['pending_sequence']:
                revised = self.prepare(root, host=details['host'], session=details['session'], source=details['source'])
                if revised['closeout_ref'] != ref:
                    return self.run(revised['closeout_ref'], root) | {'supersedes': ref}
                job = store.get(ref, self._workspace(root))
        # Byte capture and provider execution are outside the workspace lock.
        # The signed job/attempt ownership is claimed separately below.
        versions = self._source_revisions(root, job['scope_files'])
        revision = digest(self.hooks.key(root), versions)
        exclusions = job['details'].get('scope_exclusions', [])
        plan_facts = self._plan_facts(root, job['scope_files'], job['details']['members'], job['deferred_providers'], exclusions)
        plan = digest(self.hooks.key(root), plan_facts)
        from .scan_attempt import ScanAttemptStore, ScanAttemptExecution, source_binding
        attempts = ScanAttemptStore(self.hooks, root)
        if self.hooks.lock_held(root):
            return self._present(root, job) | {'status': 'BUSY', 'reason': 'WORKSPACE_LOCK_BUSY'}
        attempts.recover_cleanup(limit=2)
        waiting = perf_counter()
        with self.hooks.lock(root) as acquired:
            lock_wait_ms = round((perf_counter()-waiting)*1000, 3)
            if not acquired:
                return self._present(root, job) | {'status': 'BUSY', 'reason': 'WORKSPACE_LOCK_BUSY'}
            latest = store.get(ref, self._workspace(root))
            if latest['generation'] != job['generation']:
                return self._present(root, latest) | {'execution_accepted': False, 'reason': 'SOURCE_OR_EVENT_CHANGED'}
            job = latest
            if job['attempts'] >= MAX_ATTEMPTS and job['status'] != 'COMPLETED':
                return self._present(root, job) | {'reason': 'CLOSEOUT_BUDGET_EXHAUSTED', 'automatic_retry': False}
            activity_rows = self.closures.activity_snapshot(root)
            activity_epoch = digest(b'activity-epoch', activity_rows)
            closure_version = self.closures.version(root)
            from .closeout_persistence import hook_revision
            details = job['details']
            hook_state, corrupt = (self.hooks.load(self.hooks.path(root, details['host'], details['session']))
                if details.get('session_key') else (None, False))
            if corrupt:
                raise ValueError('Closeout session cannot be verified')
            hook_binding = hook_revision(self._read_key(root), hook_state)
            lease = attempts.claim('CLOSEOUT', ref, source_binding(dict(revision=revision, plan=plan)))
            if lease is None:
                return self._present(root, job) | {'status': 'BUSY', 'reason': 'WORKSPACE_SCAN_ACTIVE', 'execution_accepted': False}
            try:
                job, owner = store.claim(ref, self._workspace(root), revision, plan, recover=False)
            except BaseException:
                attempts.finish(lease, outcome='FAILED')
                raise
            if owner is None:
                attempts.finish(lease, outcome='CANCELLED')
                return self._present(root, job) | {'reused': True}
        started = perf_counter()
        members = job['details']['members']
        observations = {}
        def validate_input(view):
            view.assert_intact()
            rules = [binding.identity for binding in view.request.bindings if binding.kind == 'RULES']
            return (self._source_revisions(view.execution_root, job['scope_files']) == versions
                and all(value == plan_facts['rules'] for value in rules))
        def verify_input(view, scan):
            verify_started = perf_counter()
            observations['results'] = VerificationService(self.runtime.registry).verify_many(root, members,
                {'target_profile': {'files': [m['file_path'] for m in members]}},
                input_view=view, progress=execution)
            observations['verify_ms'] = round((perf_counter()-verify_started)*1000, 3)
            observations['input_applicability'] = execution.applicability(view).state
        execution = ScanAttemptExecution(attempts, lease, validator=validate_input, after_scan=verify_input)
        scan_id, outcome = None, 'FAILED'
        committed_receipt_hash = None
        try:
            from .dependency_inputs import is_dependency_input
            from .scan_input import scoped_request
            with local_recheck():
                scan = self.runtime.scan(root, mode='quick', request=scoped_request(root, job['scope_files'],
                    dependency_changes=[n for n in job['scope_files'] if is_dependency_input(n)]), execution=execution)
            scan_id = scan.scan_id
            results = observations['results']
            after = self._revision(root, job['scope_files'])
            current_plan = self._plan(root, job['scope_files'], members, job['deferred_providers'], exclusions)
            details = job['details']
            executed = {r.scanner for r in scan.scanner_runs if str(r.status) in {'SUCCESS', 'NOT_APPLICABLE'}}
            failed = (any(str(r.status) not in {'SUCCESS', 'NOT_APPLICABLE'} for r in scan.scanner_runs) or
                      not set(job['deferred_providers']) <= executed)
            with self.hooks.lock(root) as acquired:
                if not acquired:
                    return self._present(root, store.get(ref, self._workspace(root))) | {
                        'status': 'BUSY', 'reason': 'WORKSPACE_LOCK_BUSY', 'execution_accepted': False}
                latest = store.get(ref, self._workspace(root))
                pending_now = (self.hooks.pending_activity(root, details['host'], details['session'])
                               if details.get('session_key') else None)
                fenced = (attempts.is_current(lease, execution.input_id) and
                    latest['generation'] == job['generation'] and latest['lease_owner'] == owner and
                    latest['lease_until'] is not None and store.now() < latest['lease_until'])
                fresh = (fenced and after == revision and current_plan == plan and
                    observations['input_applicability'] == 'CURRENT' and
                    pending_now == details['pending_sequence'] and self.closures.generation(root) == activity_epoch)
                if not fenced:
                    outcome = 'STALE'
                    return self._present(root, latest) | {'execution_accepted': False,
                        'reason': 'SCAN_ATTEMPT_SUPERSEDED', 'risk_status': 'UNCONFIRMED_OR_PRESENT'}
                status = 'COMPLETED' if fresh and not failed else 'NEEDS_RETRY'
                coverage = str(scan.coverage) if fresh else 'UNKNOWN'
                if exclusions and coverage in {'FULL', 'SCOPED'}:
                    coverage = 'PARTIAL'
                receipt = {'contract': 'closeout-receipt-v1', 'generation': job['generation'],
                    'execution_origin': 'BACKGROUND_PREPARATION_MCP' if os.getenv('SECURITY_RUNTIME_BACKGROUND_RESUME') == '1' else 'HOST_MCP',
                    'closeout_ref': ref, 'source': details['source'], 'scope_revision_before': revision,
                    'scope_revision_after': after, 'current_version': fresh, 'scan_id': scan_id,
                    'scan_hash': digest(self.hooks.key(root), self.runtime.store.get_scan(scan_id)),
                    'plan_fingerprint': plan, 'build_identity': self.build,
                    'scan_attempt': dict(execution.receipt, publication='ACCEPTED' if fresh else 'STALE'),
                    'check_completed': status == 'COMPLETED', 'coverage': coverage,
                    'scope_exclusions': exclusions,
                    'risk_verification': results, 'timing_ms': {'closeout': round((perf_counter()-started)*1000, 3),
                        'closure_confirmation': observations['verify_ms'], 'workspace_lock_wait': lock_wait_ms,
                        'user_prompt_latency': None},
                    'credential_closure_complete': bool(results) and fresh and not exclusions and all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in results),
                    'risk_fix_scope': 'ORIGINAL_CREDENTIAL_RULE_FILE_ONLY',
                    'risk_fix_complete': bool(results) and fresh and not exclusions and not scan.findings and all(r['verification_status'] == 'SCANNER_VERIFIED_RESOLVED' for r in results)}
                reason = None if status == 'COMPLETED' else 'SOURCE_OR_EVENT_CHANGED' if not fresh else 'PROVIDER_INCOMPLETE'
                from .closeout_persistence import make_effect
                persistence = make_effect(job, receipt, status=status, coverage=coverage, reason=reason,
                    versions=versions, activity_rows=activity_rows, closure_version=closure_version,
                    hook_binding=hook_binding, lease=lease.__dict__, key=self._read_key(root)) if fresh else None
                saved, accepted = store.finish(ref, self._workspace(root), job['generation'], owner,
                    status=status, coverage=coverage, reason=reason, receipt=receipt, scan_id=scan_id,
                    persistence=persistence)
                if accepted:
                    committed_receipt_hash = digest(self._read_key(root), saved['receipt'])
                still_current = store.get(ref, self._workspace(root))['generation'] == job['generation']
            if accepted and fresh and still_current:
                recovered = drain_persistence(self, root, ref)
                saved = recovered['job']
                own_receipt = ((saved.get('receipt') or {}).get('persistence_effect_id') == persistence['event_id'])
                accepted = own_receipt and recovered['state'] == 'APPLIED'
                fresh = accepted and saved['receipt']['current_version']
                still_current = saved['generation'] == job['generation']
            outcome = 'COMPLETED' if fresh and accepted and not failed else 'STALE' if not fresh else 'FAILED'
            presented = self._present(root, saved)
            fresh = fresh and presented['current_version']
            from .hook_user_feedback import secret_verification_feedback
            feedback = secret_verification_feedback(results) if fresh and accepted and still_current else {
                'message': '检查未完成：补查期间发生了新的改动或事件，旧结果不能确认当前版本的风险关闭。', 'choices': []}
            if (saved.get('receipt') or {}).get('persistence_sync', {}).get('state') == 'PENDING':
                feedback = {'message': '原检查结果已保存，风险关闭事实仍待同步；沿原收尾任务恢复即可，不需要重新扫描。', 'choices': []}
            if failed:
                feedback['message'] += '\n收尾检查未完成：仍有失败或缺少执行回执的检查，待检任务已保留。'
            if scan.coverage != 'FULL':
                feedback['message'] += '\n本次检查的代码覆盖仍为部分或受限范围；Vue/TypeScript 等未完整覆盖的代码需另行检查。凭据关闭结论只适用于取得完整证明的原规则与当前文件版本。'
            if exclusions:
                names = '、'.join(row['file_path'] for row in exclusions[:10])
                feedback['message'] += ('\n以下环境配置文件未纳入本次结束检查：' + names +
                    (f' 等 {len(exclusions)} 个文件' if len(exclusions) > 10 else '') +
                    '。这些文件中的原有风险保持未确认；检查完成不代表项目已无风险。')
            return presented | {'user_feedback': feedback,
                'execution_accepted': accepted, 'code_coverage': scan.rule_coverage,
                'source_result_saved': saved.get('receipt') is not None,
                'risk_status': 'CONFIRMED_CLOSED' if fresh and accepted and receipt['risk_fix_complete'] else 'UNCONFIRMED_OR_PRESENT'}
        except Exception as error:
            from .progress import ScanCancelled
            cancelled = isinstance(error, ScanCancelled)
            outcome = 'CANCELLED' if cancelled else 'FAILED'
            with self.hooks.lock(root) as acquired:
                if acquired:
                    saved, _ = store.finish(ref, self._workspace(root), job['generation'], owner,
                        status='NEEDS_RETRY', coverage='UNKNOWN', reason='SCAN_ATTEMPT_CANCELLED' if cancelled else 'CLOSEOUT_EXECUTION_INCOMPLETE', scan_id=scan_id)
                    if committed_receipt_hash is not None:
                        saved = store.incomplete_persistence(ref, self._workspace(root), job['generation'],
                            expected_receipt_hash=committed_receipt_hash)
                else:
                    saved = store.get(ref, self._workspace(root))
            return self._present(root, saved) | {'execution_accepted': False, 'risk_status': 'UNCONFIRMED_OR_PRESENT'}
        finally:
            with self.hooks.lock(root, wait_seconds=2) as acquired:
                if acquired:
                    attempts.finish(lease, input_id=execution.input_id, scan_id=scan_id, outcome=outcome)

    def stop(self, workspace, host, session, active):
        """Observe existing state only. A chat ending is not a development task.

        Explicit closeouts remain resumable; Stop neither prepares nor dispatches
        them. In particular, pending edits must not create a new model turn.
        """
        root = self._root(workspace)
        store = self._store(root)
        previous = store.latest(self._workspace(root), identity(host + '\0' + session))
        pending = self.hooks.pending_activity(root, host, session) is not None
        return {'status': 'ALLOW_STOP_PENDING' if pending or (previous and previous['status'] != 'COMPLETED') else 'ALLOW_STOP',
                'closeout_ref': previous['closeout_ref'] if previous else None,
                'check_source': 'QUIET_STOP_OBSERVATION', 'scanner_run': False}


from .equivalence import equivalence_key
