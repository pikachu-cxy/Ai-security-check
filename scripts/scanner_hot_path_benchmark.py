"""Actual managed engines only. No artificial execution delay or timing result."""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
import time
import threading
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from remediation_episode_acceptance import SAFE, UNSAFE


def run(samples):
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry, SemgrepAdapter, GitleaksAdapter
    from security_runtime.toolchain import ToolManager, ToolSource
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.storage import SQLiteStore
    from security_runtime.verification import VerificationService
    import security_runtime.scanners as scanners
    import security_runtime.toolchain as tools
    measured=[]; operations=[]; guard=threading.Lock()
    def wrap(target, name, label):
        original=getattr(target,name)
        def timed(*a,**kw):
            started=time.perf_counter()
            try: return original(*a,**kw)
            finally:
                with guard: operations.append({'phase':label,'ms':round((time.perf_counter()-started)*1000,3)})
        setattr(target,name,timed)
    wrap(ToolManager,'_check','engine_integrity_and_version')
    wrap(ToolManager,'_version','version_probe')
    # Staticmethod binding must remain unchanged.
    original=RulePackManager._validate
    def validate(*a,**kw):
        started=time.perf_counter()
        try: return original(*a,**kw)
        finally:
            with guard: operations.append({'phase':'rule_pack_validation','ms':round((time.perf_counter()-started)*1000,3)})
    RulePackManager._validate=staticmethod(validate)
    original_execute=scanners._execute
    def execute(args,*a,**kw):
        started=time.perf_counter();process=original_execute(args,*a,**kw)
        phase='semgrep_invocation' if 'scan' in args else 'gitleaks_invocation'
        entry={'phase':phase,'ms':round((time.perf_counter()-started)*1000,3)}
        if phase=='semgrep_invocation':
            data=json.loads(process.stdout)
            entry['confirmed_rules']=len(data.get('time',{}).get('rules',[]))
            entry['scanned_files']=len(data.get('paths',{}).get('scanned',[]))
            # Do not persist engine stdout, source snippets, paths, errors or secret.
            entry['engine_time_keys']=sorted(data.get('time',{}))
            entry['engine_reported_total_seconds']=data.get('time',{}).get('total_time')
            profiling=data.get('time',{}).get('profiling_times',{})
            entry['engine_reported_profiling_seconds']={k:v for k,v in profiling.items()
                if k in ('config_time','core_time','ignores_time','total_time') and isinstance(v,(int,float))}
        with guard: operations.append(entry)
        return process
    scanners._execute=execute
    with tempfile.TemporaryDirectory(prefix='asr-perf-') as directory:
        root=Path(directory)/'project';root.mkdir()
        subprocess.run(['git','init',str(root)],check=True,capture_output=True)
        target='src/main/java/demo/CodeModeTlsService.java'
        path=root/target;path.parent.mkdir(parents=True)
        manager=ToolManager()
        for name in ('semgrep','gitleaks'):
            resolved=manager.ensure(name,offline=True)
            assert resolved.source==ToolSource.MANAGED and resolved.status=='READY',(name,resolved.status)
        runtime=SecurityRuntime(ScannerRegistry([SemgrepAdapter(manager),GitleaksAdapter(manager)],
                               tool_manager=manager,fallback_adapters=[]), SQLiteStore(Path(directory)/'scan.db'))
        verifier=VerificationService(runtime.registry)
        for index in range(samples):
            for phase,source in (('safe_edit',SAFE),('risk_edit',UNSAFE)):
                path.write_text(source,encoding='utf-8');operations.clear();started=time.perf_counter()
                from security_runtime.scan_input import scoped_request
                result=runtime.scan(root,'quick',request=scoped_request(root,(target,)))
                assert result.capability_results['CODE_SAST']=='EXECUTED'
                measured.append({'sample':index,'phase':phase,'wall_ms':round((time.perf_counter()-started)*1000,3),
                    'files':result.rule_coverage['total_files'],'rules':result.rule_coverage['total_selected'],
                    'operations':list(operations),'diagnostics':getattr(result,'scanner_diagnostics',{})})
            row=next(f for f in result.to_dict()['findings'] if f['technical_details'].get('rule_id')=='ai-security.java.trust-all-hostname')
            path.write_text(SAFE,encoding='utf-8');operations.clear();started=time.perf_counter()
            checked=verifier.verify_many(root,[row],result.to_dict())[0]
            assert checked['verification_status']=='SCANNER_VERIFIED_RESOLVED',checked['reason']
            assert checked['runtime_observed_execution']['engine_process_observed']
            measured.append({'sample':index,'phase':'security_rescan','wall_ms':round((time.perf_counter()-started)*1000,3),
                             'operations':list(operations),'runs':checked['scanner_runs']})
    return {'status':'PASS','kind':'ACTUAL_MANAGED_SCANNER','samples':measured,
            'medians_ms':{phase:round(statistics.median(row['wall_ms'] for row in measured if row['phase']==phase),3)
                          for phase in ('safe_edit','risk_edit','security_rescan')},
            'network':False,'model':False,'daemon':False,'source_persisted':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--samples',type=int,default=3)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    assert 1<=args.samples<=10
    os.environ['SECURITY_RUNTIME_OFFLINE']='1'
    result=run(args.samples);args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result['medians_ms']))
