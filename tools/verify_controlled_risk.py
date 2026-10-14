"""Artificially injected risk in an authorized real-project projection.

Only Runtime/scanners run. The injected/fixed application code is never run.
Explicit repair choice belongs to this delegated acceptance scenario; it does
not authorize repairs in any actual installation or user project.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile
import uuid
import security_runtime.runtime as runtime_module
import security_runtime.task_security as task_module
from security_runtime._version import __version__

from security_runtime.task_security import TaskSecurityService, digest_value
from security_runtime.hook_state import HookStateStore
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry
from security_runtime.storage import SQLiteStore, ReadOnlySQLiteStore
from security_runtime.toolchain import ToolManager
from security_runtime.security_summary import SecuritySummaryService
from security_runtime.task_fix import TaskFixService
from security_runtime.verification_policy import local_recheck

RULE = 'ai-security.python.unsafe-yaml'
RISK = b'\n# ARTIFICIALLY INJECTED ACCEPTANCE FIXTURE: NEVER EXECUTE\ndef controlled_acceptance_deserialize(payload):\n    import yaml\n    return yaml.unsafe_load(payload)\n'
FIXED = RISK.replace(b'yaml.unsafe_load', b'yaml.safe_load')


def require(value, message):
    if not value: raise ValueError(message)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--archive',type=Path,required=True)
    ap.add_argument('--work',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--expected-runtime-version',required=True)
    ap.add_argument('--expected-task-source-sha256',required=True)
    args = ap.parse_args()
    require(not args.output.exists(),'Use a new output file; old success cannot be reused')
    source_root=Path(runtime_module.__file__).resolve().parent
    source_hashes={p.relative_to(source_root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(source_root.rglob('*.py'))}
    require(__version__ == args.expected_runtime_version,'Loaded Runtime version mismatch')
    require(hashlib.sha256(Path(task_module.__file__).read_bytes()).hexdigest()==args.expected_task_source_sha256,
            'Loaded task source hash mismatch')
    work = args.work.resolve(); work.mkdir(parents=True,exist_ok=False)
    root = work/'project'; root.mkdir()
    os.environ['SECURITY_RUNTIME_OFFLINE']='1'
    os.environ['SECURITY_RUNTIME_DATA_DIR']=str(work/'data')
    os.environ['SECURITY_RUNTIME_GITLEAKS_PATH']=str(Path.home()/'AppData/Local/AI-Security-Runtime/tools/gitleaks/8.30.0/gitleaks.exe')
    with zipfile.ZipFile(args.archive) as z:
        for name in z.namelist():
            if name.endswith('/') or not name.startswith('src/security_runtime/'): continue
            path=root/name
            require(path.resolve().is_relative_to(root),'Archive escape')
            path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(z.read(name))
    for cmd in (['git','init','-q',str(root)],['git','-C',str(root),'add','.'],
        ['git','-C',str(root),'-c','user.name=Controlled acceptance','-c','user.email=acceptance@example.invalid','commit','-qm','Fixed real-project source']):
        subprocess.run(cmd,check=True,capture_output=True,timeout=30)
    store = SQLiteStore(work/'scans.db')
    hooks = HookStateStore(work/'hooks')
    registry = ScannerRegistry(tool_manager=ToolManager())
    runtime = SecurityRuntime(registry,store)
    tasks = TaskSecurityService(runtime,hooks)
    path=root/'src/security_runtime/task_security.py'; original=path.read_bytes()
    report=dict(project='pikachu-cxy/Ai-security-check',commit='755e411c4383003a5da54330890fb49c6f96c967',
        status='RUNNING',run_id=uuid.uuid4().hex,started_at_utc=datetime.now(timezone.utc).isoformat(),
        runtime_identity=dict(version=__version__,source_root=str(source_root),
            source_sha256=source_hashes,package_python_sha256=digest_value(source_hashes),
            task_source_sha256=hashlib.sha256(Path(task_module.__file__).read_bytes()).hexdigest(),
            expected_version=args.expected_runtime_version,expected_task_source_sha256=args.expected_task_source_sha256),
        artificial_injection=True, application_executed=False, model_review='NOT_RUN',
        archive_sha256=hashlib.sha256(args.archive.read_bytes()).hexdigest(),
        choice_authorization='Delegated request explicitly authorizes controlled injection, explicit repair choice, and verification in isolated copy only')
    def save(): args.output.write_text(json.dumps(report,indent=2,ensure_ascii=False,default=str),encoding='utf-8')
    ref=tasks.begin(root,'controlled-real-engine-risk')['task_ref']
    path.write_bytes(original+RISK)
    with local_recheck(): finish=tasks.finish(root,ref)
    record=tasks.load(root,ref)
    report.update(task_ref=ref,unsafe_finish=finish,unsafe_static=record['static'],
        baseline_hashes=digest_value(record['baseline']['hashes']),unsafe_hashes=digest_value(record['end']['hashes']))
    save()
    require(finish['status']=='READY','Unsafe scan not ready')
    require(record['static']['status']=='COMPLETED' and record['static']['coverage'] in {'FULL','SCOPED'},'Unsafe coverage failed')
    found=[f for f in record['static']['findings'] if f.get('technical_details',{}).get('rule_id')==RULE]
    require(len(found)==1 and 'semgrep' in found[0]['scanner_sources'],'Injected risk not detected by real Semgrep')
    summary=SecuritySummaryService(ReadOnlySQLiteStore(store.path),hooks).get(str(root),record['static']['scan_id'],details=True)
    candidate=next(t for t in summary['tasks'] if any(m['finding_id']==found[0]['id'] for m in t['members']))
    fix=TaskFixService(store,registry)
    preparation=fix.prepare(candidate['task_ref'],root)
    report['fix_preparation']=preparation; save()
    require(preparation['status']=='READY_FOR_HOST_FIX','Repair preparation not ready')
    require(preparation['authorization_requirements']['user_consent_required'],'Preparation must not infer repair consent')
    report['explicit_choice']=dict(choice='修复',approved=True,
        trust='HOST_REPORTED_CONTROLLED_SCENARIO_CHOICE',task_ref=candidate['task_ref'],finding_id=found[0]['id'],
        scope='Only the artificial function in this isolated sample',
        source='Explicit delegated positive-acceptance instruction; not an actual desktop click')
    save()  # Record the explicit choice before any repair write.
    require(report['explicit_choice']['approved'] is True,'No repair choice')
    path.write_bytes(original+FIXED)
    with local_recheck(): verification=fix.verify(candidate['task_ref'],root,
        host_reported_execution={'patch_applied':True,'target_build':False,'tests_run':False})
    report['verification']=verification; save()
    require(verification['status']=='SCANNER_VERIFIED_RESOLVED','Original risk not verified resolved')
    require(verification['runtime_observed_execution']['scanner_recheck'] is True,'No real recheck')
    with local_recheck(): safe_finish=tasks.finish(root,ref)
    safe_record=tasks.load(root,ref)
    report.update(safe_finish=safe_finish,safe_static=safe_record['static'],
        safe_hashes=digest_value(safe_record['end']['hashes']), final_file_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        outcome='SCANNER_VERIFIED_RESOLVED_SCOPED_ONLY',full_security_acceptance=False)
    require(not any(f.get('technical_details',{}).get('rule_id')==RULE for f in safe_record['static']['findings']),'Risk remained after repair')
    require(safe_record['static']['status']=='COMPLETED' and safe_record['static']['coverage'] in {'FULL','SCOPED'},'Fixed coverage failed')
    report.update(status='SUCCESS',finished_at_utc=datetime.now(timezone.utc).isoformat())
    save()
    print('Artificially injected risk -> explicit isolated repair choice -> real originating scanner verified resolution')


if __name__=='__main__': main()
