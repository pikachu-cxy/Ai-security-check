"""Separate post-remediation functional evidence, never security/production truth."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

from .functional_execution import LocalSandbox, Unavailable, TIMEOUT, TOTAL_TIMEOUT, ISOLATION_VERSION
from .functional_verifiers import FunctionalVerifierRegistry, VERSION
from .hook_state import atomic_bytes, identity, no_links

MAX_FILES = 200
MAX_BYTES = 2_000_000
MAX_FILE = 512_000
MAX_PLANS = 16
PLAN_TTL = 900
MAX_CACHE = 32


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
    return dict(security_verification={'status':security},
                functional_verification=dict(status=status,coverage=coverage,steps=list(steps),
                    baseline='UNKNOWN',regression_attribution='NOT_PROVEN',reason_code=reason,reused=reused),
                overall_status=overall, action='REVIEW_REQUIRED' if status=='FAILED' else 'NONE',
                production_correctness='UNKNOWN',
                guidance=('安全问题已消除，但功能验证失败。无可信修复前基线，不能证明由本次修复造成；'
                          '需要人工检查，不自动恢复漏洞代码、修改失败测试或循环重试。' if status=='FAILED' else
                          '安全验证与功能验证独立；结果仅覆盖列出的本地验证，不证明生产业务正确或 SAFE_TO_SHIP。'))


class FunctionalVerificationService:
    def __init__(self, remediation, *, registry=None, executor=None):
        self.remediation=remediation
        self.registry=registry or FunctionalVerifierRegistry()
        self.executor=executor or LocalSandbox()
        self.plans={}

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

    def run(self, functional_ref, *, bound_workspace):
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
                    return dict(out,functional_verification=dict(out['functional_verification'],reused=True))
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
