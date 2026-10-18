"""Cache contracts use deterministic providers; performance gates use real tools."""
import json
import os
from pathlib import Path
import shutil
from dataclasses import replace
import pytest
import yaml

from security_runtime.models import ScanContext,ScanMode,RunStatus
from security_runtime.rulepacks import RulePackManager,BundledRulePackProvider
from security_runtime.scanners import SemgrepAdapter,ScannerRegistry
from security_runtime.toolchain import ToolManager,ResolvedTool,ToolStatus
from security_runtime.processes import ProcessResult
from security_runtime.scanner_observation import observation,metadata
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.verification import VerificationService

RULE='ai-security.java.trust-all-hostname'


@pytest.fixture
def engine(tmp_path,monkeypatch):
    root=tmp_path/'project';root.mkdir();path=root/'A.java';path.write_text('class A {}')
    pack=tmp_path/'rules';shutil.copytree(RulePackManager().resolve().path,pack)
    adapter=SemgrepAdapter(rule_packs=RulePackManager(BundledRulePackProvider(pack)))
    # A deterministic mocked engine still has real bytes/package identity. This
    # fixture proves contracts, never actual Semgrep behavior or performance.
    binary = tmp_path/'fixture-engine/runtime/Scripts/semgrep.exe'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'synthetic mocked engine command')
    package = binary.parent.parent/'Lib/site-packages/semgrep'
    package.mkdir(parents=True)
    (package/'__init__.py').write_bytes(b'# deterministic provider fixture')
    monkeypatch.setattr(adapter.tool_manager,'ensure',lambda *a,**k:
                        ResolvedTool('semgrep','1.178.0',str(binary),None,ToolStatus.READY))
    calls=[];failure={'mode':None}
    def execute(argv,cwd,timeout):
        from security_runtime.verification_policy import scanner_process_observed
        scanner_process_observed()
        config=yaml.safe_load(Path(argv[argv.index('--config')+1]).read_text())
        ids=[r['id'] for r in config['rules']]
        targets=argv[argv.index('--no-git-ignore')+1:]
        calls.append((ids,targets))
        if failure['mode']=='failure': return ProcessResult(2,'','',1)
        found=[]
        for target in targets:
            if RULE in ids and 'setHostnameVerifier' in (Path(cwd)/target).read_text():
                rule=next(r for r in config['rules'] if r['id']==RULE)
                found.append({'check_id':RULE,'path':target,'start':{'line':1},'end':{'line':1},
                              'extra':{'severity':'ERROR','message':'TLS','metadata':rule['metadata']}})
        payload={'results':found,'paths':{'scanned':targets},'time':{'rules':ids},'errors':[]}
        if failure['mode']=='incomplete': payload['time']['rules']=[]
        return ProcessResult(0,json.dumps(payload),'',1)
    monkeypatch.setattr('security_runtime.scanners._execute',execute)
    return root,path,pack,adapter,calls,failure


def context(root): return ScanContext(str(root),ScanMode.QUICK,('A.java',))


def scan(engine):
    root,_,_,adapter,_,_=engine
    from security_runtime.findings import FindingNormalizer
    return adapter.scan(context(root),FindingNormalizer(root))


def test_rule_plan_cache_is_fresh_evidence_not_scanner_result(engine):
    root,_,_,adapter,calls,_=engine
    first=adapter.plan_rules(None,context(root));first.observe({'time':{'rules':[RULE]},'paths':{'scanned':['A.java']}},('A.java',))
    second=adapter.plan_rules(None,context(root))
    assert second.planning_diagnostics['rule_plan_cache']=='HIT'
    assert not second.confirmed_rules and not second.scanned_files
    assert second is not first
    scan(engine);scan(engine)
    assert len(calls)==2


def test_source_change_invalidates_plan_even_restored_mtime(engine):
    root,path,_,adapter,_,_=engine
    adapter.plan_rules(None,context(root));stat=path.stat()
    path.write_text('class B {}');os.utime(path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
    assert adapter.plan_rules(None,context(root)).planning_diagnostics['rule_plan_cache']=='MISS'


def test_workspace_scope_isolation(engine,tmp_path):
    root,_,_,adapter,_,_=engine
    other=tmp_path/'other';other.mkdir();(other/'A.java').write_text('class A {}')
    adapter.plan_rules(None,context(root))
    assert adapter.plan_rules(None,context(other)).planning_diagnostics['rule_plan_cache']=='MISS'


def test_profile_language_change_replans(engine):
    root,_,_,adapter,_,_=engine
    adapter.plan_rules(None,context(root));(root/'A.py').write_text('x = 1')
    plan=adapter.plan_rules(None,replace(context(root),files=('A.py',)))
    assert plan.detected_languages==('python',) and plan.planning_diagnostics['rule_plan_cache']=='MISS'
    assert not any(r.language=='java' for r in plan.rules)


@pytest.mark.parametrize('input_name',['java/trust-all-hostname.yml','catalog.json','LICENSE'])
def test_rule_and_metadata_content_invalidation(engine,input_name):
    root,_,pack,adapter,_,_=engine
    first=adapter.plan_rules(None,context(root));file=pack/input_name
    file.write_bytes(file.read_bytes()+b'\n')
    next_plan=adapter.plan_rules(None,context(root))
    assert next_plan.planning_diagnostics['rule_pack_cache']=='MISS'
    # LICENSE is not part of rule execution checksum, but must be revalidated.
    if input_name!='LICENSE': assert next_plan.pack.checksum!=first.pack.checksum


def test_invalid_rules_cannot_hit_old_validated_pack(engine):
    root,_,pack,adapter,_,_=engine
    adapter.plan_rules(None,context(root));(pack/'java/trust-all-hostname.yml').write_text('invalid: config')
    with pytest.raises(ValueError): adapter.plan_rules(None,context(root))


def test_stale_prepared_plan_rejected_before_scan(engine):
    root,_,pack,adapter,calls,_=engine
    plan=adapter.plan_rules(None,context(root))
    file=pack/'java/trust-all-hostname.yml';file.write_bytes(file.read_bytes()+b'\n')
    from security_runtime.findings import FindingNormalizer
    _,run=adapter.scan(replace(context(root),rule_plan=plan),FindingNormalizer(root))
    assert run.status==RunStatus.FAILED and not calls


@pytest.mark.parametrize('mode',['failure','incomplete'])
def test_failed_or_incomplete_execution_never_pollutes_next_proof(engine,mode):
    _,_,_,_,calls,failure=engine
    failure['mode']=mode;_,run=scan(engine)
    assert run.rule_coverage['status']!='EXECUTED'
    failure['mode']=None;_,run=scan(engine)
    assert run.rule_coverage['status']=='EXECUTED' and len(calls)==2


def test_security_rescan_one_original_rule_one_file_fresh_each_time(engine):
    root,path,_,adapter,calls,_=engine
    path.write_text('class A { void f() { connection.setHostnameVerifier((h,s)->true); } }')
    runtime=SecurityRuntime(ScannerRegistry([adapter],fallback_adapters=[]),SQLiteStore(root.parent/'scan.db'))
    original=runtime.scan(root,'release').to_dict()
    row=next(f for f in original['findings'] if f['technical_details']['rule_id']==RULE)
    initial_rule_count=len(calls[-1][0]);assert initial_rule_count>1
    path.write_text('class A {}')
    service=VerificationService(runtime.registry)
    for _ in range(2):
        checked=service.verify_many(root,[row],original)[0]
        assert checked['verification_status']=='SCANNER_VERIFIED_RESOLVED'
        assert checked['runtime_observed_execution']['engine_process_observed']
        assert calls[-1]==([RULE],['A.java'])
        assert checked['scanner_runs'][0]['scanner_diagnostics']['scope']['scanner_results_reused'] is False
    assert len(calls)==3


def test_missing_original_rule_cannot_authorize_resolution(engine):
    root,path,_,adapter,calls,_=engine
    path.write_text('setHostnameVerifier')
    runtime=SecurityRuntime(ScannerRegistry([adapter],fallback_adapters=[]),SQLiteStore(root.parent/'scan.db'))
    original=runtime.scan(root,'release').to_dict();row=original['findings'][0]
    row['technical_details']['rule_id']='missing-original-rule';path.write_text('class A {}')
    checked=VerificationService(runtime.registry).verify_many(root,[row],original)[0]
    assert checked['verification_status']=='INCONCLUSIVE' and len(calls)==1


def test_plan_and_configuration_cache_bounded_and_object_recreation_reuses(engine):
    root,_,_,adapter,_,_=engine
    for i in range(20):
        (root/'A.java').write_text(f'class A {{ int i={i}; }}')
        adapter.plan_rules(None,context(root))
    assert len(adapter._plan_cache)<=16
    restarted=SemgrepAdapter(rule_packs=adapter.rule_packs)
    assert restarted.plan_rules(None,context(root)).planning_diagnostics['rule_plan_cache']=='HIT'


@pytest.fixture
def probe(tmp_path,monkeypatch):
    path=tmp_path/'gitleaks';path.write_bytes(b'engine-v1')
    manager=ToolManager(tmp_path/'tools');calls=[];answer={'value':'8.30.0','code':0}
    def process(argv,**kwargs):
        calls.append(argv)
        return ProcessResult(answer['code'],answer['value'],'',1)
    monkeypatch.setattr('security_runtime.toolchain.run_process',process)
    return manager,path,calls,answer


def test_capability_cache_hit_without_version_subprocess(probe):
    manager,path,calls,_=probe
    assert manager._version('gitleaks',path)=='8.30.0'
    with observation('workspace') as first: manager._version('gitleaks',path)
    with observation('workspace') as second: manager._version('gitleaks',path)
    assert second['cache']['version_probe']=='HIT' and len(calls)==2
    assert second['counts']=={} and 'workspace' not in metadata(second)


def test_capability_file_content_invalidation(probe):
    manager,path,calls,_=probe
    manager._version('gitleaks',path);stat=path.stat();path.write_bytes(b'engine-v2')
    os.utime(path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
    manager._version('gitleaks',path);assert len(calls)==2


def test_capability_environment_config_invalidation(probe,monkeypatch):
    manager,path,calls,_=probe
    manager._version('gitleaks',path);monkeypatch.setenv('SCANNER_TEST_OPTION','changed')
    manager._version('gitleaks',path);assert len(calls)==2


def test_scanner_expected_version_invalidation(probe):
    manager,path,calls,answer=probe
    manager._version('gitleaks',path);manager.versions['gitleaks']='9.0.0';answer['value']='9.0.0'
    assert manager._version('gitleaks',path)=='9.0.0' and len(calls)==2


def test_capability_workspace_isolation(probe):
    manager,path,calls,_=probe
    with observation('workspace-a'): manager._version('gitleaks',path)
    with observation('workspace-b'): manager._version('gitleaks',path)
    assert len(calls)==2


def test_recreated_manager_retains_capability(probe,monkeypatch,tmp_path):
    manager,path,calls,_=probe
    manager._version('gitleaks',path)
    ToolManager(tmp_path/'tools')._version('gitleaks',path)
    assert len(calls)==1


@pytest.mark.parametrize('failed_output',['','unrecognized version','9.99.0'])
def test_failed_or_mismatched_version_never_cached(probe,failed_output):
    manager,path,calls,answer=probe
    answer['value']=failed_output
    manager._version('gitleaks',path);manager._version('gitleaks',path)
    assert len(calls)==2 and not manager._version_cache


def test_python_engine_helper_change_invalidates_version(probe,tmp_path):
    manager,_,calls,answer=probe;answer['value']='1.178.0'
    runtime=tmp_path/'python';path=runtime/'Scripts/semgrep.exe';path.parent.mkdir(parents=True);path.write_bytes(b'launcher')
    package=runtime/'Lib/site-packages/semgrep';package.mkdir(parents=True)
    helper=package/'__VERSION__.py';helper.write_bytes(b'1.178.0')
    manager._version('semgrep',path);manager._version('semgrep',path)
    assert len(calls)==1
    helper.write_bytes(b'1.179.0');manager._version('semgrep',path)
    assert len(calls)==2


def test_diagnostics_never_contains_source_or_raw_output(engine):
    _,path,_,_,_,_=engine
    secret='do-not-persist-private-content';path.write_text('class A {} // '+secret)
    _,run=scan(engine)
    assert secret not in json.dumps(run.scanner_diagnostics)
    assert run.scanner_diagnostics['timing_ms']['actual_scanner_execution'] is None
    assert 'stdout' not in json.dumps(run.scanner_diagnostics)
