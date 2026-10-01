"""Provider contracts, policy, normalization and offline lifecycle; no remote queries."""
import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime.capabilities import Capability
from security_runtime.cli import doctor, main, render
from security_runtime.dependency_fallback import should_fallback, dependency_status
from security_runtime.findings import FindingNormalizer, deduplicate
from security_runtime.models import ScanContext, ScanMode, ScannerRun
from security_runtime.osv import OSVDependencyAdapter
from security_runtime.processes import ProcessResult, OutputLimitError
from security_runtime.progress import ProgressReporter
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry, TrivyAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus


@pytest.fixture(autouse=True)
def explicit_test_network_mode(monkeypatch):
    # Online-mode native output/coverage cases mock every process and download.
    # Offline cases explicitly set 1. Do not inherit a runner's global mode.
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','0')


@pytest.mark.parametrize('code',['MAVEN_RATE_LIMITED','NETWORK_TIMEOUT','DNS_RESOLUTION_FAILED','PROXY_CONNECTION_FAILED','HTTP_5XX','DEPENDENCY_RESOLUTION_FAILED','ENGINE_UNAVAILABLE','OFFLINE_MODE'])
def test_eligible_failures(code):
    assert should_fallback(ScannerRun('trivy-vuln','','FAILED',1,error_code=code))


@pytest.mark.parametrize('code',['CHECKSUM_MISMATCH','SECURITY_BOUNDARY_VIOLATION','INVARIANT_VIOLATION','CONFIG_CORRUPTED','SCANNER_OUTPUT_OR_CONFIG_ERROR','LOCAL_IO_ERROR','OUTPUT_LIMIT_EXCEEDED','TLS_ERROR','SCANNER_FAILED','PROCESS_TIMEOUT','HTTP_401','HTTP_403','HTTP_404'])
def test_no_fallback_for_integrity_config_or_unknown_failure(code):
    assert not should_fallback(ScannerRun('trivy-vuln','','UNAVAILABLE',1,error_code=code))


@pytest.mark.parametrize('status',['SUCCESS','NOT_APPLICABLE','NOT_COVERED','SKIPPED'])
def test_no_fallback_for_non_failure(status):
    assert not should_fallback(ScannerRun('trivy-vuln','',status,1,error_code='MAVEN_RATE_LIMITED'))


class Adapter:
    filter_changed_lines=False
    def __init__(self,name,cap,*,status='SUCCESS',code='',contract='FULL',role='PRIMARY'):
        self.name=self.scanner_id=self.engine_id=name
        self.capabilities=frozenset({cap})
        self.status,self.code,self.contract,self.provider_role=status,code,contract,role
        self.calls=0
    def supports(self,profile,context): return True
    def scan(self,context,normalizer):
        self.calls+=1
        return [],ScannerRun(self.name,'mock',self.status,1,error_code=self.code,coverage_contract=self.contract)


def runtime_fixture(tmp_path,*,primary='FAILED',code='MAVEN_RATE_LIMITED',fallback='SUCCESS',contract='FULL'):
    (tmp_path/'App.java').write_text('class App {}')
    (tmp_path/'pom.xml').write_text('<project/>')
    (tmp_path/'application.yml').write_text('name: test')
    trivy=Adapter('trivy-vuln',Capability.DEPENDENCY_VULN,status=primary,code=code)
    osv=Adapter('osv-scanner',Capability.DEPENDENCY_VULN,status=fallback,contract=contract,role='FALLBACK')
    providers=[Adapter('code',Capability.CODE_SAST),Adapter('gitleaks',Capability.SECRET_SCAN),trivy,Adapter('trivy-misconfig',Capability.IAC_MISCONFIG)]
    runtime=SecurityRuntime(ScannerRegistry(providers,fallback_adapters=[osv]),SQLiteStore(tmp_path/'.security-runtime/test.db'))
    return runtime,trivy,osv


@pytest.mark.parametrize('contract,expected,overall',[('FULL','EXECUTED','COMPLETED'),('PARTIAL','PARTIAL','PARTIAL')])
def test_fallback_contract_storage_json_mcp_human(tmp_path,contract,expected,overall):
    from security_runtime.mcp_server import _agent_result
    runtime,trivy,osv=runtime_fixture(tmp_path,contract=contract)
    events=[]
    result=runtime.scan(tmp_path,'release',progress=ProgressReporter(events.append))
    assert trivy.calls==osv.calls==1
    assert result.capability_results['DEPENDENCY_VULN']==expected
    assert result.status==overall
    assert result.capability_results['SECRET_SCAN']==result.capability_results['IAC_MISCONFIG']=='EXECUTED'
    detail=result.capability_details['DEPENDENCY_VULN']
    assert detail['active_provider']=='osv-scanner' and detail['provider_role']=='FALLBACK'
    assert detail['primary_status']=='FAILED' and detail['primary_error_code']=='MAVEN_RATE_LIMITED'
    assert next(r for r in result.scanner_runs if r.scanner=='trivy-vuln').status=='FAILED'
    stored=runtime.store.get_scan(result.scan_id)
    assert stored['capability_details']==_agent_result(result)['capability_details']==result.to_dict()['capability_details']
    assert 'osv-scanner 回退' in render(result)
    assert ('trivy-vuln' in render(result)) == (contract=='PARTIAL')
    assert 'trivy-vuln' in render(result,verbose=True)
    assert any(e.event_type=='FALLBACK_SELECTED' for e in events)


@pytest.mark.parametrize('status,code',[('SUCCESS',''),('FAILED','CHECKSUM_MISMATCH'),('FAILED','CONFIG_CORRUPTED'),('FAILED','SCANNER_FAILED')])
def test_runtime_does_not_prepare_unneeded_fallback(tmp_path,status,code):
    runtime,_,osv=runtime_fixture(tmp_path,primary=status,code=code)
    result=runtime.scan(tmp_path,'release')
    assert osv.calls==0
    assert all(r.scanner!='osv-scanner' for r in result.scanner_runs)


@pytest.mark.parametrize('status,expected',[('FAILED','FAILED'),('TIMEOUT','FAILED'),('UNAVAILABLE','FAILED')])
def test_failed_fallback_does_not_mask_primary_or_findings(tmp_path,status,expected):
    runtime,_,osv=runtime_fixture(tmp_path,fallback=status)
    result=runtime.scan(tmp_path,'release')
    assert osv.calls==1 and result.capability_results['DEPENDENCY_VULN']==expected
    assert len([r for r in result.scanner_runs if Capability.DEPENDENCY_VULN in r.capabilities])==2


def native_fixture(tmp_path,name='package-lock.json'):
    (tmp_path/name).write_text('<project/>' if name=='pom.xml' else '{}')
    manager=ToolManager(root=tmp_path/'managed')
    manager.ensure=lambda tool: ResolvedTool(tool,'2.6.0','osv-scanner',None,ToolStatus.READY)
    adapter=OSVDependencyAdapter(manager)
    context=ScanContext(str(tmp_path),ScanMode.RELEASE,(name,))
    return manager,adapter,context,FindingNormalizer(tmp_path)


def inventory(name='package-lock.json'):
    return {'results':[{'source':{'path':name,'type':'lockfile'},'packages':[{'package':{'name':'demo','version':'1.0','ecosystem':'npm'},'vulnerabilities':[]}]}]}


@pytest.mark.parametrize('name,expected',[('package-lock.json','FULL'),('pnpm-lock.yaml','FULL'),('pom.xml','PARTIAL'),('requirements.txt','PARTIAL'),('go.mod','PARTIAL')])
def test_native_success_contract_and_safe_scope(tmp_path,name,expected):
    _,adapter,context,n=native_fixture(tmp_path,name)
    (tmp_path/'App.java').write_text('do not copy source')
    (tmp_path/'osv-scanner.toml').write_text('ignore malicious config')
    seen=[]
    def execute(args,**kwargs):
        scope=Path(kwargs['cwd'])
        seen.append(sorted(p.name for p in scope.rglob('*') if p.is_file()))
        assert '--no-call-analysis=all' in args and '--experimental-no-default-plugins' in args
        assert '--experimental-plugins=lockfile' in args and '--data-source=deps.dev' in args
        assert not any('download-offline' in arg or arg in {'fix','mvn','gradle','npm','pip'} for arg in args)
        return ProcessResult(0,json.dumps(inventory(name)),'',1)
    with patch('security_runtime.osv.run_process',side_effect=execute):
        findings,run=adapter.scan(context,n)
    assert not findings and run.status=='SUCCESS' and run.coverage_contract==expected
    assert seen==[[name,'runtime-osv.toml'] if name < 'runtime-osv.toml' else ['runtime-osv.toml',name]]


@pytest.mark.parametrize('raw,stderr,expected',[({'results':[]},'','PARTIAL'),(inventory(),'WARN resolution incomplete','PARTIAL'),(inventory(),'','FULL')])
def test_missing_inventory_or_native_warning_withholds_full(tmp_path,raw,stderr,expected):
    _,adapter,context,n=native_fixture(tmp_path)
    with patch('security_runtime.osv.run_process',return_value=ProcessResult(0,json.dumps(raw),stderr,1)):
        _,run=adapter.scan(context,n)
    assert run.status=='SUCCESS' and run.coverage_contract==expected


@pytest.mark.parametrize('raw',['not JSON',json.dumps({}),json.dumps({'results':[{'source':{'path':'../outside.lock'}}]})])
def test_malformed_or_outside_output_fails_closed(tmp_path,raw):
    _,adapter,context,n=native_fixture(tmp_path)
    with patch('security_runtime.osv.run_process',return_value=ProcessResult(0,raw,'',1)):
        found,run=adapter.scan(context,n)
    assert not found and run.status=='FAILED' and run.coverage_contract=='NONE'


@pytest.mark.parametrize('exception,code',[(TimeoutError(),'PROCESS_TIMEOUT'),(OutputLimitError(),'OUTPUT_LIMIT_EXCEEDED')])
def test_native_timeout_output_limit(tmp_path,exception,code):
    _,adapter,context,n=native_fixture(tmp_path)
    with patch('security_runtime.osv.run_process',side_effect=exception):
        found,run=adapter.scan(context,n)
    assert not found and run.error_code==code and run.coverage_contract=='NONE'


def test_offline_reuses_installed_engine_and_local_data_without_network_flags(tmp_path,monkeypatch):
    manager,adapter,context,n=native_fixture(tmp_path)
    db=manager.root/'data/osv/osv-scalibr/npm/all.zip';db.parent.mkdir(parents=True);db.touch()
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    def execute(args,**kwargs):
        assert '--offline' in args and '--no-resolve' in args
        assert '--download-offline-databases' not in args
        assert kwargs['env']['OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY']==str(manager.root/'data/osv')
        return ProcessResult(0,json.dumps(inventory()),'',1)
    with patch('security_runtime.osv.run_process',side_effect=execute),patch('urllib.request.urlopen',side_effect=AssertionError('network attempted')):
        _,run=adapter.scan(context,n)
    assert run.status=='SUCCESS' and run.coverage_contract=='FULL'


def test_offline_installed_without_database_never_queries(tmp_path,monkeypatch):
    _,adapter,context,n=native_fixture(tmp_path)
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    with patch('security_runtime.osv.run_process',side_effect=AssertionError('network attempted')):
        found,run=adapter.scan(context,n)
    assert not found and run.status=='UNAVAILABLE' and run.error_code=='OFFLINE_MODE'


def test_normalized_aliases_match_trivy_without_merging_packages_versions_manifests(tmp_path):
    n=FindingNormalizer(tmp_path)
    args=dict(package='org.demo:lib',version='1.0',ecosystem='Maven',manifest='pom.xml',severity='HIGH')
    osv=n.dependency(scanner='osv-scanner',vulnerability_id='GHSA-abcd',aliases=['CVE-2026-1234'],source='OSV',**args)
    trivy=n.dependency(scanner='trivy-vuln',vulnerability_id='CVE-2026-1234',source='Trivy',**args)
    merged=deduplicate([osv,trivy])
    assert len(merged)==1 and merged[0].scanner_sources==['osv-scanner','trivy-vuln']
    for key,value in [('package','org.demo:other'),('version','2.0'),('manifest','nested/pom.xml')]:
        other=n.dependency(scanner='trivy-vuln',vulnerability_id='CVE-2026-1234',**(args|{key:value}))
        assert other.fingerprint!=osv.fingerprint
    assert osv.technical_details['canonical_vulnerability_id']=='CVE-2026-1234'


def test_osv_vulnerability_normalization_and_unknown_severity(tmp_path):
    data=inventory()
    data['results'][0]['packages'][0]['vulnerabilities']=[{'id':'GHSA-demo','aliases':['CVE-2026-1234'],'summary':'demo issue','database_specific':{'severity':'MODERATE'},'severity':[{'type':'CVSS_V3','score':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}]}]
    found=OSVDependencyAdapter(ToolManager(root=tmp_path/'managed')).normalize(data,FindingNormalizer(tmp_path))
    assert found[0].severity=='MEDIUM' and found[0].technical_details['source']=='OSV'
    assert found[0].technical_details['package_version']=='1.0'
    assert found[0].technical_details['installed_version']=='1.0'
    assert found[0].technical_details['severity_vectors'][0]['type']=='CVSS_V3'


def test_full_provider_satisfies_contract_but_partial_does_not():
    primary=ScannerRun('trivy-vuln','','FAILED',1)
    fallback=ScannerRun('osv-scanner','','SUCCESS',1,coverage_contract='FULL')
    assert dependency_status([primary,fallback])=='EXECUTED'
    fallback.coverage_contract='PARTIAL'
    assert dependency_status([primary,fallback])=='PARTIAL'


def test_primary_install_all_and_doctor_do_not_require_osv(tmp_path,capsys):
    (tmp_path/'App.java').write_text('class App {}')
    manager=ToolManager(root=tmp_path/'managed')
    calls=[]
    manager.ensure=lambda name: calls.append(name) or ResolvedTool(name,'mock',name,None,ToolStatus.READY)
    manager.prepare_trivy_database=lambda path: ToolStatus.READY
    manager.statuses=lambda: {name:ResolvedTool(name,'mock','',None,ToolStatus.MISSING if name=='osv-scanner' else ToolStatus.READY) for name in manager.versions}
    manager.database_status=lambda:ToolStatus.READY
    with patch('security_runtime.cli.ToolManager',return_value=manager):
        assert main(['tools','install','--all'])==0
        assert 'osv-scanner' not in calls
        assert doctor(tmp_path,json_output=True)==0
    output=capsys.readouterr().out
    report=json.loads(output[output.index('{'):])
    assert report['status']=='ready'
    assert report['optional_providers'][0]['status']=='ON_DEMAND'
    assert report['optional_providers'][0]['engine_status']=='MISSING'


@pytest.mark.parametrize('platform,arch',[('windows','x64'),('linux','x64'),('macos','x64'),('macos','arm64')])
def test_osv_pinned_official_platform_manifest(tmp_path,platform,arch):
    manager=ToolManager(root=tmp_path/'managed')
    with patch('security_runtime.toolchain.platform_key',return_value=(platform,arch)):
        manifest=manager.manifest('osv-scanner')
    assert manifest.version=='2.6.0' and manifest.archive_type=='binary'
    assert len(manifest.sha256)==64 and manifest.download_url.startswith('https://github.com/google/osv-scanner/releases/download/v2.6.0/')
    assert manifest.license_metadata.license_spdx=='Apache-2.0'


def test_tools_status_labels_optional_fallback(tmp_path,capsys):
    manager=ToolManager(root=tmp_path/'managed')
    manager.statuses=lambda:{'osv-scanner':ResolvedTool('osv-scanner','','',None,ToolStatus.MISSING)}
    with patch('security_runtime.cli.ToolManager',return_value=manager):
        assert main(['tools','status'])==0
    assert 'ON_DEMAND / FALLBACK (MISSING)' in capsys.readouterr().out


def test_managed_binary_checksum_is_enforced(tmp_path):
    from dataclasses import replace
    import hashlib
    manager=ToolManager(root=tmp_path/'managed')
    manifest=replace(manager.manifest('osv-scanner'),sha256=hashlib.sha256(b'test-binary').hexdigest())
    def download(manifest,path): path.write_bytes(b'unverified')
    with patch.object(manager.provider,'download',side_effect=download):
        with pytest.raises(ValueError,match='checksum'):
            manager._install_binary(manifest)
    assert not manager.managed_path('osv-scanner').exists()


def test_osv_download_timeout_has_existing_redacted_diagnostics(tmp_path,monkeypatch):
    from urllib.error import URLError
    from security_runtime.diagnostics import DiagnosticError
    manager=ToolManager(root=tmp_path/'managed')
    monkeypatch.setenv('HTTPS_PROXY','http://user:PRIVATE_VALUE@proxy.test:1234')
    with patch('urllib.request.urlopen',side_effect=URLError(TimeoutError('PRIVATE_VALUE'))):
        with pytest.raises(DiagnosticError) as caught:
            manager.provider.download(manager.manifest('osv-scanner'),tmp_path/'asset')
    assert caught.value.diagnostic.error_code=='NETWORK_TIMEOUT'
    assert caught.value.diagnostic.source=='github.com'
    assert caught.value.diagnostic.https_proxy=='configured'
    assert 'PRIVATE_VALUE' not in json.dumps(caught.value.diagnostic.to_dict())


def test_native_fallback_phase_events_and_stderr_renderer(tmp_path):
    from security_runtime.cli_progress import CLIProgressRenderer
    from security_runtime.progress import progress_context
    _,adapter,context,n=native_fixture(tmp_path)
    stream=io.StringIO()
    renderer=CLIProgressRenderer(stream,delay=0,tty=False)
    events=[]
    def sink(event):
        events.append(event.event_type)
        renderer(event)
    with progress_context(ProgressReporter(sink)),patch('security_runtime.osv.run_process',return_value=ProcessResult(0,json.dumps(inventory()),'',1)):
        adapter.scan(context,n)
    phases=[event for event in events if event.startswith('FALLBACK_')]
    assert phases==['FALLBACK_PREPARING','FALLBACK_RUNNING','FALLBACK_COMPLETED']
    assert '正在准备依赖回退' in stream.getvalue() and '依赖回退完成' in stream.getvalue()


def test_tool_configuration_corruption_does_not_trigger_fallback(tmp_path,monkeypatch):
    manager=ToolManager(root=tmp_path/'managed')
    config=tmp_path/'invalid.toml';config.write_text('[tools.trivy invalid')
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG',str(config))
    with patch.object(manager.provider,'download',side_effect=AssertionError('download attempted')):
        resolved=manager.ensure('trivy')
    assert resolved.status=='BROKEN' and resolved.diagnostic.error_code=='CONFIG_CORRUPTED'
    assert not should_fallback(ScannerRun('trivy-vuln','','UNAVAILABLE',1,**resolved.diagnostic.to_dict()))


def test_provider_roles_are_explicit():
    from security_runtime.models import ProviderRole
    assert set(ProviderRole)=={'PRIMARY','FALLBACK','SUPPLEMENTAL','USER_PROVIDED'}


def test_fallback_role_is_never_selected_for_parallel_primary_planning(tmp_path):
    from security_runtime.planner import ScannerPlanner
    from security_runtime.models import TargetProfile
    adapter=Adapter('osv-scanner',Capability.DEPENDENCY_VULN,role='FALLBACK')
    registry=ScannerRegistry([TrivyAdapter(),adapter])
    context=ScanContext(str(tmp_path),ScanMode.RELEASE,('pom.xml',))
    _,selected=ScannerPlanner(registry).plan(TargetProfile(str(tmp_path),ecosystems=['maven']),context)
    assert [scanner.name for scanner in selected]==['trivy-vuln']


def test_local_maven_parent_cannot_escape_snapshot(tmp_path):
    _,adapter,context,n=native_fixture(tmp_path,'pom.xml')
    (tmp_path/'pom.xml').write_text('<project><parent><relativePath>../../outside.xml</relativePath></parent></project>')
    with patch('security_runtime.osv.run_process',side_effect=AssertionError('native scanner called')):
        found,run=adapter.scan(context,n)
    assert not found and run.error_code=='SECURITY_BOUNDARY_VIOLATION'


def test_implicit_root_parent_lookup_is_disabled_without_touching_target(tmp_path):
    _,adapter,context,n=native_fixture(tmp_path,'pom.xml')
    original='<project><parent><groupId>example</groupId></parent></project>'
    (tmp_path/'pom.xml').write_text(original)
    def execute(args,**kwargs):
        import xml.etree.ElementTree as ET
        copied=ET.parse(Path(kwargs['cwd'])/'pom.xml').getroot()
        assert copied.find('parent/relativePath') is not None
        return ProcessResult(0,json.dumps(inventory('pom.xml')),'',1)
    with patch('security_runtime.osv.run_process',side_effect=execute):
        _,run=adapter.scan(context,n)
    assert run.status=='SUCCESS' and run.coverage_contract=='PARTIAL'
    assert (tmp_path/'pom.xml').read_text()==original


def test_missing_osv_offline_never_downloads_or_executes(tmp_path,monkeypatch):
    (tmp_path/'package-lock.json').write_text('{}')
    manager=ToolManager(root=tmp_path/'managed')
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    monkeypatch.delenv('SECURITY_RUNTIME_OSV_SCANNER_PATH',raising=False)
    monkeypatch.setattr('security_runtime.toolchain.shutil.which',lambda name:None)
    context=ScanContext(str(tmp_path),ScanMode.RELEASE,('package-lock.json',))
    with patch.object(manager.provider,'download',side_effect=AssertionError('download attempted')),patch('security_runtime.osv.run_process',side_effect=AssertionError('scanner called')):
        found,run=OSVDependencyAdapter(manager).scan(context,FindingNormalizer(tmp_path))
    assert not found and run.status=='UNAVAILABLE' and run.error_code=='OFFLINE_MODE'


def test_malformed_pom_is_scanner_config_failure(tmp_path):
    _,adapter,context,n=native_fixture(tmp_path,'pom.xml')
    (tmp_path/'pom.xml').write_text('<project>')
    with patch('security_runtime.osv.run_process',side_effect=AssertionError('native called')):
        found,run=adapter.scan(context,n)
    assert not found and run.status=='FAILED' and run.error_code=='SCANNER_OUTPUT_OR_CONFIG_ERROR'


def test_osv_error_redacts_remote_credentials(tmp_path,monkeypatch):
    _,adapter,context,n=native_fixture(tmp_path)
    monkeypatch.setenv('HTTPS_PROXY','http://user:PRIVATE_PROXY@proxy.test:8080')
    stderr='GET https://user:PRIVATE_URL@api.osv.dev/query?token=PRIVATE_QUERY: 503 Service Unavailable\nAuthorization: Bearer PRIVATE_AUTH'
    with patch('security_runtime.osv.run_process',return_value=ProcessResult(127,'',stderr,1)):
        _,run=adapter.scan(context,n)
    assert run.error_code=='HTTP_5XX' and run.source=='api.osv.dev' and run.https_proxy=='configured'
    assert 'PRIVATE_' not in json.dumps(run.__dict__)


def test_trivy_offline_scan_does_not_resolve_remote_dependencies(tmp_path,monkeypatch):
    (tmp_path/'pom.xml').write_text('<project/>')
    manager=ToolManager(root=tmp_path/'managed')
    manager.ensure=lambda name:ResolvedTool(name,'mock','trivy',None,ToolStatus.READY)
    manager.prepare_trivy_database=lambda binary:ToolStatus.READY
    monkeypatch.setenv('SECURITY_RUNTIME_OFFLINE','1')
    def execute(args,cwd,timeout):
        assert '--offline-scan' in args and args[args.index('--scanners')+1]=='vuln'
        return ProcessResult(0,json.dumps({'Results':[]}), '',1)
    with patch('security_runtime.scanners._execute',side_effect=execute):
        _,run=TrivyAdapter(manager).scan(ScanContext(str(tmp_path),ScanMode.RELEASE,('pom.xml',)),FindingNormalizer(tmp_path))
    assert run.status=='SUCCESS' and run.coverage_contract=='PARTIAL'
