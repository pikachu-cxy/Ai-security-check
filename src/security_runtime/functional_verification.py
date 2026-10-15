"""Separate post-remediation functional evidence, never security/production truth."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import time
import weakref

from .functional_execution import Unavailable, TIMEOUT, TOTAL_TIMEOUT, ISOLATION_VERSION
from .functional_verifiers import FunctionalVerifierRegistry, VERSION
from .hook_state import atomic_bytes, identity, no_links
from .functional_host import FunctionalExecutionReport
from .functional_feedback import result_feedback

MAX_FILES = 200
MAX_BYTES = 2_000_000
MAX_FILE = 512_000
MAX_PLANS = 16
PLAN_TTL = 900
MAX_CACHE = 32
JAVAC_SOURCE_POLICY = 'javac-leading-utf8-bom-v1'


def snapshot(root, key, destination=None):
    """All project files, including ignored files; exclude only root Git state.

    A transient projection is deleted after execution. Only keyed hashes persist.
    Links, junctions, special files and an exceeded budget fail closed.
    """
    no_links(root)
    mac=hmac.new(key,b'functional-workspace-v1',hashlib.sha256)
    count=total=entries=0
    def visit(directory):
        nonlocal count,total,entries
        for path in sorted(directory.iterdir()):
            if directory == root and path.name == '.git': continue
            entries+=1
            if entries>400: raise ValueError('WORKSPACE_BUDGET_EXCEEDED')
            no_links(path)
            name=path.relative_to(root).as_posix()
            if path.is_dir():
                mac.update(b'D'+name.encode()); visit(path); continue
            if not path.is_file(): raise ValueError('SPECIAL_FILE_REJECTED')
            size=path.stat().st_size
            if size>MAX_FILE: raise ValueError('WORKSPACE_BUDGET_EXCEEDED')
            data=path.read_bytes()
            total+=len(data); count+=1
            if count>MAX_FILES or total>MAX_BYTES or len(data)>MAX_FILE:
                raise ValueError('WORKSPACE_BUDGET_EXCEEDED')
            mac.update(json.dumps(name).encode()); mac.update(len(data).to_bytes(8,'big')); mac.update(data)
            if destination:
                target=destination/name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data)
                target.chmod(path.stat().st_mode & 0o777)
    visit(root)
    return mac.hexdigest()


def result(status, steps=(), *, security='SCANNER_VERIFIED_RESOLVED', reason=None, reused=False):
    kinds={s['kind'] for s in steps if s['status']=='PASSED'}
    coverage='BUILD_AND_TEST' if {'BUILD','TEST'}<=kinds else '_AND_'.join(sorted(kinds)) or 'NONE'
    overall={'PASSED':'SECURITY_AND_FUNCTIONALLY_VERIFIED',
             'PARTIAL':'SECURITY_VERIFIED_FUNCTION_PARTIAL',
             'FAILED':'SECURITY_VERIFIED_FUNCTION_FAILED'}.get(status,'SECURITY_VERIFIED_FUNCTION_UNKNOWN')
    if security != 'SCANNER_VERIFIED_RESOLVED': overall='SECURITY_NOT_VERIFIED'
    return result_feedback(dict(security_verification={'status':security},
                functional_verification=dict(status=status,coverage=coverage,steps=list(steps),
                    baseline='UNKNOWN',regression_attribution='NOT_PROVEN',reason_code=reason,reused=reused),
                overall_status=overall, action='REVIEW_REQUIRED' if status=='FAILED' else 'NONE',
                production_correctness='UNKNOWN',
                guidance=('安全问题已消除，但功能验证失败。无可信修复前基线，不能证明由本次修复造成；'
                          '需要人工检查，不自动恢复漏洞代码、修改失败测试或循环重试。' if status=='FAILED' else
                          '安全验证与功能验证独立；结果仅覆盖列出的本地验证，不证明生产业务正确或 SAFE_TO_SHIP。')))


class FunctionalVerificationService:
    def __init__(self, remediation, *, registry=None, executor=None):
        self.remediation=remediation
        self.registry=registry or FunctionalVerifierRegistry()
        # Production MCP delegates execution to the coding host. The explicit
        # executor injection retains the original internal regression contract.
        self.executor=executor
        self.plans={}
        weakref.finalize(self, self._cleanup_rows, self.plans)

    @staticmethod
    def _cleanup_rows(rows):
        for row in rows.values():
            FunctionalVerificationService._cleanup(row)

    @staticmethod
    def _host_result(status, steps=(), *, reason=None, reused=False):
        out = result(status, steps, reason=reason, reused=reused)
        out['status'] = {'PASSED': 'FUNCTIONAL_VERIFIED', 'FAILED': 'FUNCTIONAL_FAILED',
                         'PARTIAL': 'FUNCTIONAL_PARTIAL'}.get(status, 'FUNCTIONAL_INCONCLUSIVE')
        if status == 'NOT_AVAILABLE':
            out['status'] = 'SECURITY_VERIFIED_FUNCTION_UNKNOWN'
        out['functional_verification']['evidence_source'] = 'UNTRUSTED_HOST_EXECUTION_REPORT'
        if steps and all(s['kind'] == 'COMPILE' for s in steps):
            out['functional_verification']['coverage'] = 'COMPILE_ONLY' if status == 'PASSED' else 'NONE'
        if steps and all(s.get('provider') == 'javac' for s in steps):
            out['functional_verification'].update(
                source_handling=steps[0]['source_handling'], source_modified=False)
        return result_feedback(out)

    @staticmethod
    def _artifact_inventory(path):
        count = total = 0
        def visit(directory):
            nonlocal count, total
            no_links(directory)
            for item in directory.iterdir():
                count += 1
                if count > 800:
                    raise ValueError('ARTIFACT_ENTRY_BUDGET')
                no_links(item)
                if not item.resolve().is_relative_to(path.resolve()):
                    raise ValueError('ARTIFACT_CONTAINMENT')
                if item.is_dir():
                    visit(item)
                elif item.is_file():
                    total += item.stat().st_size
                    if total > 50_000_000:
                        raise ValueError('ARTIFACT_BYTES_BUDGET')
                else:
                    raise ValueError('ARTIFACT_SPECIAL_FILE')
        visit(path)

    @staticmethod
    def _cleanup(row):
        path = row.get('artifact_directory')
        if path is None or not path.exists():
            return True
        try:
            # Only this plan's freshly allocated external directory is removed.
            # Reject junctions/links before any recursive deletion on Windows.
            if (path.parent.resolve() != Path(tempfile.gettempdir()).resolve() or
                    not path.name.startswith('asr-host-functional-')):
                return False
            FunctionalVerificationService._artifact_inventory(path)
            shutil.rmtree(path)
            return True
        except (OSError, ValueError):
            return False

    def _expire_host_plans(self):
        for token, row in list(self.plans.items()):
            if time.monotonic() - row['created'] >= PLAN_TTL:
                self._cleanup(row)
                self.plans.pop(token)

    @staticmethod
    def _host_cache_id(root, before, base, receipt):
        # Old javac results were obtained without BOM handling. Do not reuse
        # those failures, or invalidate unrelated providers' existing caches.
        policy = JAVAC_SOURCE_POLICY if 'javac' in base['detected_stack'] else None
        return identity(json.dumps([str(root), before, base['config_hash'],
                                    receipt['token_hash'], 'host-native-functional-v1',
                                    *([policy] if policy else []),
                                    *([receipt['binding']] if 'binding' in receipt else [])], sort_keys=True))

    def _receipt_read(self, ref, task_ref, root):
        read = getattr(self.remediation, 'functional_receipt_diagnostics', None)
        if callable(read):
            return read(ref, task_ref, root)
        # Retain explicit injected legacy/test providers. Production always uses
        # the signed current proof diagnostic reader, not Host assertions.
        receipt = self.remediation.functional_receipt(ref, task_ref, root)
        return dict(receipt=receipt, security_status='SCANNER_VERIFIED_RESOLVED' if receipt else 'NOT_VERIFIED',
                    reason_code=None if receipt else 'SECURITY_RECEIPT_UNAVAILABLE')

    @staticmethod
    def _receipt_rejected(diagnostic, ref=None, task_ref=None, root=None):
        out = result('INCONCLUSIVE', security=diagnostic['security_status'],
                     reason='SECURITY_RECEIPT_REQUIRED_REFRESH')
        out.update(status='FUNCTIONAL_INCONCLUSIVE',
                   next_action='REFRESH_CONTEXT_REQUIRED_DO_NOT_SWITCH_OBJECT')
        out['security_verification'].update(current_snapshot_valid=False,
            receipt_validation=dict(status='REFRESH_REQUIRED', reason_code=diagnostic['reason_code']))
        out['functional_verification']['receipt_reason_code'] = diagnostic['reason_code']
        binding = diagnostic.get('binding')
        if binding:
            out['security_verification']['receipt_binding'] = binding
            out['remediation_stage'] = 'CLOSED'
        # A missing old-format binding requires an actual original scanner recheck,
        # never a fabricated token. Other mismatches cannot switch tasks/episodes.
        if diagnostic['reason_code'] == 'RESOLVED_RECEIPT_BINDING_REQUIRED':
            out['next_action'] = 'VERIFY_TASK_FIX_WITH_ORIGINAL_REFERENCES_THEN_RETRY'
            if ref is not None and task_ref is not None and root is not None:
                out['handoff'] = {'tool': 'verify_task_fix', 'arguments': {
                    'remediation_ref': ref, 'task_ref': task_ref, 'workspace_path': str(root)}}
        elif diagnostic['reason_code'] == 'SECURITY_STATE_BUSY':
            out['next_action'] = 'RETRY_PREPARE_AFTER_STATE_COMMIT'
        return out

    @staticmethod
    def _javac_sources(root, steps):
        """Read only bounded targets; normalize only one leading UTF-8 BOM.

        Never change user files or normalize unknown encodings. The returned
        bytes exist only during planning and in the owned temporary projection.
        """
        sources, normalized = {}, []
        for step in steps:
            if step.provider != 'javac':
                continue
            for name in step.target_files:
                path = root / name
                no_links(path)
                if not path.resolve().is_relative_to(root) or path.stat().st_size > MAX_FILE:
                    raise ValueError('JAVAC_SOURCE_REJECTED')
                data = path.read_bytes()
                if len(data) > MAX_FILE:
                    raise ValueError('JAVAC_SOURCE_REJECTED')
                has_bom = data.startswith(b'\xef\xbb\xbf')
                content = data[3:] if has_bom else data
                try:
                    content.decode('utf-8', errors='strict')
                except UnicodeDecodeError:
                    raise ValueError('JAVAC_SOURCE_ENCODING_UNSUPPORTED') from None
                if b'\x00' in content or content.startswith(b'\xef\xbb\xbf'):
                    raise ValueError('JAVAC_SOURCE_ENCODING_UNSUPPORTED')
                sources[name] = content
                if has_bom:
                    normalized.append(name)
        return sources, normalized

    def _prepare_host(self, ref, task_ref, workspace, *, bound_workspace):
        try:
            root = self.root(workspace, bound_workspace)
            # Serialize the resolved-state handoff with its existing writer.
            with self.remediation.state.lock(root, wait_seconds=.25) as locked:
                if not locked:
                    return self._receipt_rejected(dict(security_status='NOT_CHECKED',
                                                       reason_code='SECURITY_STATE_BUSY'))
                return self._prepare_host_locked(ref, task_ref, root, bound_workspace=bound_workspace)
        except Exception:
            return self._receipt_rejected(dict(security_status='NOT_CHECKED',
                                               reason_code='WORKSPACE_CLAIM_REJECTED'))

    def _prepare_host_locked(self, ref, task_ref, workspace, *, bound_workspace):
        security = 'NOT_VERIFIED'
        row = None
        try:
            root = self.root(workspace, bound_workspace)
            diagnostic = self._receipt_read(ref, task_ref, root)
            receipt = diagnostic['receipt']
            if receipt is None:
                return self._receipt_rejected(diagnostic, ref, task_ref, root)
            security = 'SCANNER_VERIFIED_RESOLVED'
            key = receipt['key']
            before = snapshot(root, key)
            steps = self.registry.detect(root, target_files=receipt['target_files'])
            if not steps:
                return self._host_result('NOT_AVAILABLE', reason='NO_EXISTING_LOCAL_VERIFIER')
            if len(steps) > 9:
                raise ValueError('PLAN_BUDGET_EXCEEDED')
            base = self.registry.plan(root, steps, key)
            if snapshot(root, key) != before or self.remediation.functional_receipt(ref, task_ref, root) is None:
                return self._host_result('INCONCLUSIVE', reason='WORKSPACE_CHANGED_REFRESH')
            if any(s.executable is None for s in steps):
                return self._host_result('NOT_AVAILABLE', reason='LOCAL_TOOL_UNAVAILABLE')
            try:
                sources, normalized = self._javac_sources(root, steps)
            except ValueError:
                return self._host_result('INCONCLUSIVE', reason='JAVAC_SOURCE_ENCODING_UNSUPPORTED')
            _, cache = self._cache(root, key)
            cached = cache.get(self._host_cache_id(root, before, base, receipt))
            if cached and cached['result']['functional_verification']['status'] in {'PASSED', 'FAILED', 'PARTIAL'}:
                out = cached['result']
                return result_feedback(dict(out, functional_verification=dict(out['functional_verification'], reused=True),
                            next_action='VERIFY_TASK_FIX_WITH_ORIGINAL_REFERENCES',
                            handoff={'tool': 'verify_task_fix', 'arguments': {
                        'remediation_ref': ref, 'task_ref': task_ref, 'workspace_path': str(root)}}))
            self._expire_host_plans()
            if len(self.plans) >= MAX_PLANS:
                return self._host_result('INCONCLUSIVE', reason='PLAN_BUDGET_EXCEEDED')
            token = 'functional-v1.' + secrets.token_hex(32)
            row = dict(created=time.monotonic(), root=root, ref=ref, task_ref=task_ref,
                       base=base, steps=steps, receipt=receipt, snapshot_digest=before)
            output = Path(tempfile.mkdtemp(prefix='asr-host-functional-')).resolve()
            row['artifact_directory'] = output
            if output.is_relative_to(root):
                raise ValueError('OUTPUT_DIRECTORY_INSIDE_WORKSPACE')
            working = root
            source_handling = 'TEMPORARY_BOM_NORMALIZATION' if normalized else 'ORIGINAL'
            if normalized:
                # Preserve the target paths/package declarations. Compile only
                # these copies, including unchanged targets of a mixed scope.
                working = output / 'sources'
                working.mkdir()
                for name, data in sources.items():
                    target = working / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                row['projection_directory'] = working
                row['projection_files'] = {name:
                    hmac.new(key, data, hashlib.sha256).hexdigest()
                    for name, data in sources.items()}
            if any(s.provider != 'javac' for s in steps):
                # Reuse the original bounded transient projection; it is data,
                # not a new command runner/sandbox. Target project stays intact.
                working = output / 'workspace'
                working.mkdir()
                if snapshot(root, key, working) != before:
                    raise ValueError('WORKSPACE_CHANGED_REFRESH')
                row['projection_directory'] = working
                row['projection_files'] = {p.relative_to(working).as_posix():
                    hmac.new(key, p.read_bytes(), hashlib.sha256).hexdigest()
                    for p in working.rglob('*') if p.is_file()}
            public_steps = []
            for step in steps:
                argv = step.argv()
                if step.provider == 'javac':
                    (output / 'classes').mkdir()
                    (output / 'empty').mkdir()
                    argv += ['-classpath', str(output / 'empty'), '-sourcepath', str(output / 'empty'),
                             '-d', str(output / 'classes'), *step.target_files]
                public_steps.append(dict(step.public(), argv=argv, working_directory=str(working),
                    target_files=list(receipt['target_files']),
                    scope='REMEDIATION_FILES_ONLY' if step.provider == 'javac' else 'EXISTING_PROJECT_VERIFIER',
                    timeout_seconds=TIMEOUT, max_output_bytes=65536,
                    requires_project_code_review=step.provider != 'javac',
                    unset_environment=['JDK_JAVAC_OPTIONS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH'],
                    environment={'PIP_NO_INDEX': '1', 'GOPROXY': 'off', 'GOSUMDB': 'off',
                                 'GOTOOLCHAIN': 'local', 'npm_config_offline': 'true',
                                 'npm_config_ignore_scripts': 'true', 'PYTHONDONTWRITEBYTECODE': '1'}))
                if step.provider == 'javac':
                    public_steps[-1].update(source_handling=source_handling, source_modified=False,
                                            normalized_target_files=normalized)
            if snapshot(root, key) != before or self.remediation.functional_receipt(ref, task_ref, root) is None:
                self._cleanup(row)
                return self._host_result('INCONCLUSIVE', reason='WORKSPACE_CHANGED_REFRESH')
            plan = dict(version='host-native-functional-v1', detected_stack=base['detected_stack'],
                        execution_owner='AI_CODING_HOST', runtime_executes_commands=False,
                        workspace=str(root), target_files=list(receipt['target_files']), steps=public_steps,
                        total_timeout_seconds=TOTAL_TIMEOUT, network_allowed=False,
                        max_artifact_entries=800, max_artifact_bytes=50_000_000,
                        expected_result_contract=FunctionalExecutionReport.model_json_schema(),
                        result_text_policy='REDACTED_SUMMARIES_ONLY_NO_SOURCE_OR_SECRET',
                        cleanup_owner='RUNTIME_FOR_PLAN_TEMP_DIRECTORY',
                        temporary_projection=working != root,
                        instruction='Use the host native execution API with these exact argv/cwd and limits. '
                        'Deny network; review existing scripts/wrappers/configuration before running them. '
                        'If these requirements cannot be enforced, report NOT_AVAILABLE; do not install/download '
                        'dependencies, invent commands, widen scope or retry. Return only bounded redacted summaries.')
            if sources:
                plan.update(source_handling=source_handling, source_modified=False,
                            normalized_target_files=normalized, source_policy=JAVAC_SOURCE_POLICY)
            if 'binding' in receipt:
                plan['security_receipt'] = dict(receipt['binding'], resolved_scan_id=receipt['resolved_scan_id'],
                                               snapshot_digest=receipt['snapshot_digest'])
            plan['plan_digest'] = hmac.new(key, json.dumps(plan, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            row['plan'] = plan
            self.plans[token] = row
            out = self._host_result('PLANNED')
            out.update(status='FUNCTIONAL_VERIFICATION_READY', plan=plan, functional_ref=token,
                       remediation_stage=receipt.get('stage', 'CLOSED'),
                       next_action='HOST_EXECUTE_PLAN_THEN_REPORT',
                       handoff={'tool': 'run_functional_verification', 'arguments': {'functional_ref': token},
                                'execution_result_required': True})
            out['functional_verification'].update(evidence_source='NOT_EXECUTED', coverage='NONE')
            if 'binding' in receipt:
                out['security_verification'].update(receipt_validation={'status': 'VALID', 'reason_code': None},
                                                   receipt_binding=plan['security_receipt'])
            if sources:
                out['functional_verification'].update(source_handling=source_handling, source_modified=False)
            return out
        except Exception:
            if row:
                self._cleanup(row)
            return result('INCONCLUSIVE', security=security, reason='FUNCTIONAL_PLAN_REJECTED_REFRESH')

    def _accept_host(self, functional_ref, report, *, bound_workspace):
        row = self.plans.get(functional_ref) if isinstance(functional_ref, str) else None
        if row is None:
            return result('INCONCLUSIVE', security='NOT_VERIFIED', reason='FUNCTIONAL_PLAN_EXPIRED_REFRESH')
        try:
            root = self.root(row['root'], bound_workspace)
        except Exception:
            return result('INCONCLUSIVE', security='NOT_VERIFIED', reason='WORKSPACE_CLAIM_REJECTED')
        if time.monotonic() - row['created'] >= PLAN_TTL:
            self._cleanup(row)
            return self._host_result('INCONCLUSIVE', reason='FUNCTIONAL_PLAN_EXPIRED_REFRESH')
        with self.remediation.state.lock(root) as locked:
            if not locked:
                return self._host_result('INCONCLUSIVE', reason='FUNCTIONAL_BUSY')
            try:
                diagnostic = self._receipt_read(row['ref'], row['task_ref'], root)
                receipt = diagnostic['receipt']
                if receipt is None:
                    out = self._receipt_rejected(diagnostic, row['ref'], row['task_ref'], root)
                    self._cleanup(row)
                    return out
                if receipt.get('binding') != row['receipt'].get('binding'):
                    self._cleanup(row)
                    return self._receipt_rejected(dict(security_status='SCANNER_VERIFIED_RESOLVED',
                        reason_code='SECURITY_PROOF_CHANGED', binding=receipt.get('binding')))
                key = receipt['key']
                before = snapshot(root, key)
                steps = self.registry.detect(root, target_files=receipt['target_files'])
                base = self.registry.plan(root, steps, key)
                if before != row['snapshot_digest'] or base['config_hash'] != row['base']['config_hash']:
                    self._cleanup(row)
                    return self._host_result('INCONCLUSIVE', reason='WORKSPACE_OR_PLAN_CHANGED_REFRESH')
                if report is None:
                    if 'completed' in row:
                        old = row['completed']
                        return result_feedback(dict(old, functional_verification=dict(old['functional_verification'], reused=True)))
                    return dict(self._host_result('PLANNED'), status='FUNCTIONAL_VERIFICATION_READY',
                                next_action='HOST_EXECUTE_PLAN_THEN_REPORT', plan=row['plan'],
                                functional_ref=functional_ref)
                if not isinstance(report, FunctionalExecutionReport):
                    report = FunctionalExecutionReport.model_validate(report)
                if report.plan_digest != row['plan']['plan_digest']:
                    return self._host_result('INCONCLUSIVE', reason='HOST_PLAN_BINDING_MISMATCH')
                if 'completed' in row:
                    # Exact duplicate submission is idempotent; changed claims
                    # never replace a completed result or authorize another run.
                    if hmac.new(key, report.model_dump_json().encode(), hashlib.sha256).hexdigest() != row['accepted_report_hash']:
                        return self._host_result('INCONCLUSIVE', reason='HOST_RESULT_ALREADY_CONSUMED')
                    old = row['completed']
                    return result_feedback(dict(old, functional_verification=dict(old['functional_verification'], reused=True)))
                wanted = [s.command_id for s in steps]
                supplied = [s.command_id for s in report.steps]
                if supplied != wanted[:len(supplied)]:
                    return self._host_result('INCONCLUSIVE', reason='HOST_STEP_SCOPE_MISMATCH')
                observations = []
                for step, observed in zip(steps, report.steps):
                    text = (observed.stdout_summary + '\n' + observed.stderr_summary).encode()
                    state, reason = 'INCONCLUSIVE', 'HOST_EXECUTION_UNKNOWN'
                    if observed.execution_status == 'NOT_AVAILABLE':
                        state, reason = 'NOT_AVAILABLE', 'HOST_EXECUTION_UNAVAILABLE'
                    elif observed.execution_status == 'COMPLETED' and observed.exit_code is not None:
                        if observed.exit_code < 0:
                            reason = 'PROCESS_SIGNAL'
                        elif observed.exit_code == 0:
                            state, reason = 'PASSED', 'HOST_COMMAND_PASSED'
                        else:
                            state, reason = 'FAILED', 'HOST_COMMAND_FAILED'
                        if step.provider == 'python' and observed.exit_code == 5:
                            state, reason = 'NOT_AVAILABLE', 'NO_TESTS_COLLECTED'
                        elif observed.exit_code != 0 and any(marker in text.lower() for marker in (
                                b'offline mode', b'cannot find module', b'no module named pytest',
                                b'pluginresolutionexception', b'dependencyresolutionexception')):
                            state, reason = 'NOT_AVAILABLE', 'LOCAL_DEPENDENCIES_UNAVAILABLE'
                        if (b'No tests were executed!' in text or b':test NO-SOURCE' in text or
                                (step.provider == 'go' and b'[no test files]' in text)):
                            state, reason = 'NOT_AVAILABLE', 'NO_TESTS_COLLECTED'
                    elif observed.execution_status != 'COMPLETED':
                        reason = 'HOST_' + observed.execution_status
                    if observed.duration_ms > TIMEOUT * 1000:
                        state, reason = 'INCONCLUSIVE', 'HOST_TIMEOUT_BUDGET_EXCEEDED'
                    if observed.execution_status != 'NOT_AVAILABLE' and report.network_access != 'DENIED':
                        state, reason = 'INCONCLUSIVE', 'HOST_NETWORK_BOUNDARY_UNPROVEN'
                    if observed.execution_status != 'NOT_AVAILABLE' and step.provider != 'javac' and not report.project_code_reviewed:
                        state, reason = 'INCONCLUSIVE', 'HOST_PROJECT_CODE_REVIEW_REQUIRED'
                    observations.append(dict(kind=step.kind, provider=step.provider, command_id=step.command_id,
                        status=state, reason_code=reason, exit_code=observed.exit_code,
                        duration_ms=observed.duration_ms, output_hash=hmac.new(key, text, hashlib.sha256).hexdigest()))
                    if step.provider == 'javac':
                        observations[-1].update(source_handling=row['plan']['source_handling'], source_modified=False)
                if any(o['status'] != 'PASSED' for o in observations[:-1]):
                    return self._host_result('INCONCLUSIVE', reason='HOST_RAN_AFTER_NONPASS_STEP')
                states = {s['status'] for s in observations}
                if 'FAILED' in states:
                    status = 'FAILED'
                elif 'INCONCLUSIVE' in states:
                    status = 'INCONCLUSIVE'
                elif 'PASSED' in states and 'NOT_AVAILABLE' in states:
                    status = 'PARTIAL'
                elif len(observations) != len(steps) and states == {'PASSED'}:
                    status = 'INCONCLUSIVE'
                elif states == {'PASSED'}:
                    status = 'PASSED' if any(s.kind in {'TEST', 'TYPECHECK', 'COMPILE'} for s in steps) else 'PARTIAL'
                else:
                    status = 'NOT_AVAILABLE'
                if sum(o.get('duration_ms', 0) for o in observations) > TOTAL_TIMEOUT * 1000:
                    return self._host_result('INCONCLUSIVE', reason='HOST_TOTAL_TIMEOUT_BUDGET_EXCEEDED')
                for step in steps[len(observations):]:
                    observations.append(dict(kind=step.kind, provider=step.provider, command_id=step.command_id,
                                             status='NOT_RUN', reason_code='PRIOR_STEP_NOT_PASSED'))
                if snapshot(root, key) != before or self.remediation.functional_receipt(row['ref'], row['task_ref'], root) is None:
                    return self._host_result('INCONCLUSIVE', reason='WORKSPACE_CHANGED_DURING_VERIFICATION')
                self._artifact_inventory(row['artifact_directory'])
                if 'projection_directory' in row:
                    for name, expected in row['projection_files'].items():
                        path = row['projection_directory'] / name
                        no_links(path)
                        if (not path.is_file() or path.stat().st_size > MAX_FILE or
                                hmac.new(key, path.read_bytes(), hashlib.sha256).hexdigest() != expected):
                            self._cleanup(row)
                            return self._host_result('INCONCLUSIVE', reason='HOST_MODIFIED_VERIFIER_INPUT')
                out = self._host_result(status, observations)
                if 'binding' in receipt:
                    out['security_verification'].update(receipt_validation={'status': 'VALID', 'reason_code': None},
                                                       receipt_binding=row['plan']['security_receipt'])
                out['functional_verification']['cleanup_complete'] = self._cleanup(row)
                if not out['functional_verification']['cleanup_complete']:
                    out = self._host_result('INCONCLUSIVE', observations, reason='ARTIFACT_CLEANUP_REQUIRED')
                out['functional_verification']['duration_ms'] = sum(o.get('duration_ms', 0) for o in observations)
                path, cache = self._cache(root, key)
                cache_id = self._host_cache_id(root, before, base, receipt)
                cache[cache_id] = dict(result=out, snapshot_digest=before, config_hash=base['config_hash'])
                if len(cache) > MAX_CACHE:
                    cache.pop(next(iter(cache)))
                encoded = json.dumps(cache, sort_keys=True, separators=(',', ':')).encode()
                data = json.dumps({'records': cache, 'mac': hmac.new(key, encoded, hashlib.sha256).hexdigest()}).encode()
                if len(data) > 262144:
                    return self._host_result('INCONCLUSIVE', reason='AUDIT_BUDGET_EXCEEDED')
                atomic_bytes(path, data)
                # No stdout/stderr, model text or source retained in memory either.
                row['accepted_report_hash'] = hmac.new(key, report.model_dump_json().encode(), hashlib.sha256).hexdigest()
                row['completed'] = out
                return out
            except Exception:
                self._cleanup(row)
                return self._host_result('INCONCLUSIVE', reason='HOST_RESULT_REJECTED_REFRESH')

    def finalize(self, ref, task_ref, root, security_result):
        """Attach matching functional evidence without overwriting scanner facts."""
        if security_result.get('verification_status') != 'SCANNER_VERIFIED_RESOLVED':
            return security_result
        try:
            diagnostic = self._receipt_read(ref, task_ref, root)
            receipt = diagnostic['receipt']
            if receipt is None:
                out = self._receipt_rejected(diagnostic, ref, task_ref, root)
                # This is the Runtime's own scanner result, not a Host claim.
                # A later receipt read failure cannot erase that established fact
                # or confer authority for a changed/current episode.
                out['security_verification']['status'] = 'SCANNER_VERIFIED_RESOLVED'
            else:
                before = snapshot(root, receipt['key'])
                steps = self.registry.detect(root, target_files=receipt['target_files'])
                base = self.registry.plan(root, steps, receipt['key'])
                _, cache = self._cache(root, receipt['key'])
                cached = cache.get(self._host_cache_id(root, before, base, receipt))
                out = cached['result'] if cached else self._host_result('NOT_VERIFIED', reason='FUNCTIONAL_RESULT_REQUIRED')
            merged = dict(security_result, **{k: v for k, v in out.items() if k != 'status'})
            merged.update(functional_status=out['status'],
                          remediation_stage=receipt.get('stage', 'CLOSED') if receipt else 'CLOSED')
            return result_feedback(merged)
        except Exception:
            out = self._host_result('INCONCLUSIVE', reason='FUNCTIONAL_RESULT_REJECTED_REFRESH')
            out['security_verification']['status'] = 'SCANNER_VERIFIED_RESOLVED'
            return dict(security_result, **{k: v for k, v in out.items() if k != 'status'},
                        functional_status=out['status'])

    @staticmethod
    def root(claim, bound):
        if not isinstance(claim,(str,Path)) or not isinstance(bound,(str,Path)):
            raise ValueError('WORKSPACE_BINDING_REQUIRED')
        path=Path(claim); binding=Path(bound)
        if (not path.is_absolute() or '..' in path.parts or str(path).startswith(('\\\\','//')) or
                any(ord(c)<32 for c in str(path)) or len(str(path))>4096):
            raise ValueError('WORKSPACE_CLAIM_REJECTED')
        no_links(path); no_links(binding)
        if path.resolve()!=binding.resolve(): raise ValueError('WORKSPACE_CLAIM_REJECTED')
        return path.resolve()

    def prepare(self, ref, task_ref, workspace, *, bound_workspace):
        if self.executor is None:
            return self._prepare_host(ref, task_ref, workspace, bound_workspace=bound_workspace)
        security='NOT_VERIFIED'
        try:
            root=self.root(workspace,bound_workspace)
            receipt=self.remediation.functional_receipt(ref,task_ref,root)
            if receipt is None: return result('INCONCLUSIVE',security='NOT_VERIFIED',reason='SECURITY_RECEIPT_REQUIRED_REFRESH')
            security='SCANNER_VERIFIED_RESOLVED'
            key=receipt['key']
            before=snapshot(root,key)
            steps=self.registry.detect(root)
            if len(steps)>9: raise ValueError('PLAN_BUDGET_EXCEEDED')
            plan=self.registry.plan(root,steps,key)
            after=snapshot(root,key)
            if before!=after or self.remediation.functional_receipt(ref,task_ref,root) is None:
                return result('INCONCLUSIVE',reason='WORKSPACE_CHANGED_REFRESH')
            if not steps: return result('NOT_AVAILABLE',reason='NO_EXISTING_LOCAL_VERIFIER')
            reason=self.executor.availability()
            plan.update(workspace_id=identity(os.path.normcase(str(root))),snapshot_digest=before,
                        execution_available=reason is None,unavailable_reason=reason)
            for token, row in list(self.plans.items()):
                if time.monotonic()-row['created']>=PLAN_TTL: self.plans.pop(token)
            if len(self.plans)>=MAX_PLANS: return result('INCONCLUSIVE',reason='PLAN_BUDGET_EXCEEDED')
            token='functional-v1.'+secrets.token_hex(32)
            self.plans[token]=dict(created=time.monotonic(),root=root,ref=ref,task_ref=task_ref,
                                   plan=plan,steps=steps,receipt=receipt)
            return dict(status='PLANNED',plan=plan,functional_ref=token,
                        handoff={'tool':'run_functional_verification','arguments':{'functional_ref':token}},
                        security_verification={'status':'SCANNER_VERIFIED_RESOLVED'})
        except Exception:
            return result('INCONCLUSIVE',security=security,reason='FUNCTIONAL_PLAN_REJECTED_REFRESH')

    def _cache(self, root, key):
        directory=self.remediation.state.workspace_directory(root)
        path=directory/'functional-cache'
        no_links(path)
        if not path.exists(): return path,{}
        if path.stat().st_size>262144: raise ValueError('CACHE_BUDGET_EXCEEDED')
        envelope=json.loads(path.read_bytes())
        encoded=json.dumps(envelope['records'],sort_keys=True,separators=(',',':')).encode()
        if (len(envelope['records'])>MAX_CACHE or
                not hmac.compare_digest(envelope['mac'],hmac.new(key,encoded,hashlib.sha256).hexdigest())):
            raise ValueError('UNTRUSTED_CACHE')
        return path,envelope['records']

    def run(self, functional_ref, *, bound_workspace, execution_result=None):
        if self.executor is None:
            return self._accept_host(functional_ref, execution_result, bound_workspace=bound_workspace)
        security='NOT_VERIFIED'
        row=self.plans.get(functional_ref) if isinstance(functional_ref,str) else None
        if row is None or time.monotonic()-row['created']>=PLAN_TTL:
            return result('INCONCLUSIVE',security='NOT_VERIFIED',reason='FUNCTIONAL_PLAN_EXPIRED_REFRESH')
        try:
            root=self.root(row['root'],bound_workspace)
            # Same workspace lock as remediation. No concurrent fix/functional run.
            with self.remediation.state.lock(root) as locked:
                if not locked: return result('INCONCLUSIVE',reason='FUNCTIONAL_BUSY')
                receipt=self.remediation.functional_receipt(row['ref'],row['task_ref'],root)
                if receipt is None: return result('INCONCLUSIVE',security='NOT_VERIFIED',reason='SECURITY_RECEIPT_REQUIRED_REFRESH')
                security='SCANNER_VERIFIED_RESOLVED'
                key=receipt['key']; before=snapshot(root,key)
                steps=self.registry.detect(root)
                plan=self.registry.plan(root,steps,key)
                if before!=row['plan']['snapshot_digest'] or plan['config_hash']!=row['plan']['config_hash']:
                    return result('INCONCLUSIVE',reason='WORKSPACE_OR_PLAN_CHANGED_REFRESH')
                cache_id=identity(json.dumps([str(root),before,plan,receipt['token_hash'],ISOLATION_VERSION],sort_keys=True))
                path,cache=self._cache(root,key)
                if cache_id in cache:
                    out=cache[cache_id]['result']
                    return result_feedback(dict(out,functional_verification=dict(out['functional_verification'],reused=True)))
                reason=self.executor.availability()
                if reason:
                    return result('NOT_AVAILABLE',[dict(kind=s.kind,provider=s.provider,command_id=s.command_id,
                                  status='NOT_RUN',reason_code=reason) for s in steps],reason=reason)
                observations=[]
                started=time.time()
                deadline=time.monotonic()+TOTAL_TIMEOUT
                with tempfile.TemporaryDirectory(prefix='asr-functional-') as temporary:
                    copy=Path(temporary)/'workspace'; copy.mkdir()
                    if snapshot(root,key,copy)!=before: return result('INCONCLUSIVE',reason='WORKSPACE_CHANGED_REFRESH')
                    for step in steps:
                        item={k:v for k,v in step.public().items() if k in {'kind','provider','command_id'}}
                        begin=time.time()
                        item.update(started_at_epoch=begin)
                        try:
                            if not step.executable: raise Unavailable('LOCAL_TOOL_UNAVAILABLE')
                            remaining=deadline-time.monotonic()
                            if remaining<=0:
                                observed=dict(exit_code=None,output=b'',reason='TOTAL_TIMEOUT',duration_ms=0)
                            else: observed=self.executor.run(copy,step,timeout=min(TIMEOUT,remaining))
                            private=observed['output']
                            item.update(exit_code=observed['exit_code'],duration_ms=observed['duration_ms'],
                                output_hash=hmac.new(key,private,hashlib.sha256).hexdigest())
                            if observed['reason']:
                                item.update(status='INCONCLUSIVE',reason_code=observed['reason'])
                            elif observed['exit_code'] is not None and observed['exit_code']<0:
                                item.update(status='INCONCLUSIVE',reason_code='PROCESS_SIGNAL')
                            elif step.kind=='TEST' and (b'No tests were executed!' in private or b':test NO-SOURCE' in private):
                                item.update(status='NOT_AVAILABLE',reason_code='NO_TESTS_COLLECTED')
                            elif observed['exit_code']==0:
                                item.update(status='PASSED',reason_code='LOCAL_COMMAND_PASSED')
                            elif any(marker in private.lower() for marker in
                                     (b'offline mode',b'cannot find module',b'no module named pytest',
                                      b'pluginresolutionexception',b'dependencyresolutionexception')):
                                item.update(status='NOT_AVAILABLE',reason_code='LOCAL_DEPENDENCIES_UNAVAILABLE')
                            elif step.provider=='python' and observed['exit_code']==5:
                                item.update(status='NOT_AVAILABLE',reason_code='NO_TESTS_COLLECTED')
                            elif b'bwrap:' in private:
                                item.update(status='INCONCLUSIVE',reason_code='SANDBOX_START_FAILED')
                            else: item.update(status='FAILED',reason_code='LOCAL_COMMAND_FAILED')
                        except Unavailable:
                            item.update(status='NOT_AVAILABLE',reason_code='ISOLATED_LOCAL_TOOL_UNAVAILABLE')
                        except Exception:
                            item.update(status='INCONCLUSIVE',reason_code='PROCESS_EXECUTION_ERROR')
                        item['ended_at_epoch']=time.time()
                        observations.append(item)
                        # No follow-up commands after failure/unknown, no retry loop.
                        if item['status']!='PASSED': break
                if snapshot(root,key)!=before or self.remediation.functional_receipt(row['ref'],row['task_ref'],root) is None:
                    return result('INCONCLUSIVE',reason='WORKSPACE_CHANGED_DURING_VERIFICATION')
                states={s['status'] for s in observations}
                if 'FAILED' in states: status='FAILED'
                elif 'INCONCLUSIVE' in states: status='INCONCLUSIVE'
                elif states=={'PASSED'} and len(observations)==len(steps):
                    # Build alone or lint alone is useful partial evidence.
                    status='PASSED' if any(s['kind'] in {'TEST','TYPECHECK'} for s in observations) else 'PARTIAL'
                elif 'PASSED' in states: status='PARTIAL'
                else: status='NOT_AVAILABLE'
                for step in steps[len(observations):]:
                    observations.append(dict(kind=step.kind,provider=step.provider,command_id=step.command_id,
                                             status='NOT_RUN',reason_code='PRIOR_STEP_NOT_PASSED'))
                out=result(status,observations)
                out['functional_verification']['duration_ms']=round((time.time()-started)*1000)
                cache[cache_id]=dict(snapshot_digest=before,config_hash=plan['config_hash'],
                                    started_at_epoch=started,ended_at_epoch=time.time(),result=out)
                if len(cache)>MAX_CACHE: cache.pop(next(iter(cache)))
                encoded=json.dumps(cache,sort_keys=True,separators=(',',':')).encode()
                data=json.dumps({'records':cache,'mac':hmac.new(key,encoded,hashlib.sha256).hexdigest()}).encode()
                if len(data)>262144: return result('INCONCLUSIVE',reason='AUDIT_BUDGET_EXCEEDED')
                atomic_bytes(path,data)
                return out
        except Exception:
            return result('INCONCLUSIVE',security=security,reason='FUNCTIONAL_VERIFICATION_REJECTED_REFRESH')
