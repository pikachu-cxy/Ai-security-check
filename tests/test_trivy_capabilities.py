import json
import pytest
from pathlib import Path
from unittest.mock import patch

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessResult
from security_runtime.scanners import TrivyAdapter, TrivyMisconfigAdapter
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus


@pytest.mark.parametrize('prefix', ['', 'apps/web/'])
@pytest.mark.parametrize('packages', [[], [{'Name': 'lodash', 'Version': '4.17.21'}]])
def test_npm_manifest_and_lock_are_one_unit(tmp_path, prefix, packages):
    manifest, lock = prefix + 'package.json', prefix + 'package-lock.json'
    context = ScanContext(str(tmp_path), ScanMode.QUICK, (manifest, lock))
    data = {'Results': [{'Target': lock, 'Type': 'npm', 'Packages': packages}]}
    result = TrivyAdapter._dependency_inventory(data, context, 1)
    assert result['coverage'] == 'FULL' and result['notes'] == []
    assert result['inventory']['planned_manifests'] == 1
    assert result['inventory']['confirmed_manifests'] == 1
    assert result['inventory']['paired_manifests'] == {manifest: lock}


def test_npm_pair_does_not_cover_another_directory_or_missing_report(tmp_path):
    context = ScanContext(str(tmp_path), ScanMode.QUICK,
        ('a/package.json', 'a/package-lock.json', 'b/package.json'))
    data = {'Results': [{'Target': 'a/package-lock.json', 'Type': 'npm',
                         'Packages': [{'Name': 'lodash', 'Version': '4.17.21'}]}]}
    result = TrivyAdapter._dependency_inventory(data, context, 1)
    assert result['coverage'] == 'PARTIAL'
    assert result['inventory']['unconfirmed_manifests'] == ['b/package.json']
    result = TrivyAdapter._dependency_inventory({'Results': []}, context, 1)
    assert result['coverage'] == 'PARTIAL'
    assert result['inventory']['confirmed_manifests'] == 0


def test_quick_trivy_npm_success_is_complete_without_database_fingerprint(tmp_path, monkeypatch):
    for name in ('package.json', 'package-lock.json'):
        (tmp_path/name).write_text('{}')
    manager = ToolManager(root=tmp_path/'managed')
    manager.ensure = lambda name, **kwargs: ResolvedTool(name, 'mock', 'trivy', None, ToolStatus.READY)
    manager.prepare_trivy_database = lambda *args, **kwargs: ToolStatus.READY
    manager.database_freshness = lambda: {'status': 'FRESH'}
    manager.execution_data_identity = lambda *args, **kwargs: pytest.fail('DB fingerprint requested')
    def execute(args, cwd, timeout):
        assert '--offline-scan' in args
        return ProcessResult(0, json.dumps({'Results': [{'Target': 'package-lock.json',
            'Type': 'npm', 'Packages': [{'Name': 'lodash', 'Version': '4.17.21'}]}]}), '', 1)
    with patch('security_runtime.scanners._execute', side_effect=execute):
        _, run = TrivyAdapter(manager).scan(ScanContext(str(tmp_path), ScanMode.QUICK,
            ('package.json', 'package-lock.json')), FindingNormalizer(tmp_path))
    assert run.status == 'SUCCESS' and run.coverage_contract == 'FULL', (run.error_code, run.error_summary, run.scanner_diagnostics)
    assert run.coverage_notes == []


def test_default_registry_disables_osv_fallback(tmp_path):
    from security_runtime.scanners import ScannerRegistry
    registry = ScannerRegistry(tool_manager=ToolManager(root=tmp_path/'managed'))
    assert registry.fallback_adapters == []
    assert 'trivy-vuln' in {adapter.name for adapter in registry.adapters}


def test_independent_checks_and_iac_scope(tmp_path):
    (tmp_path/'pom.xml').write_text('<project/>')
    (tmp_path/'Dockerfile').write_text('FROM alpine:3.20\nUSER root\n')
    (tmp_path/'App.java').write_text('class App {}')
    manager=ToolManager(root=tmp_path/'managed')
    manager.ensure=lambda name: ResolvedTool(name,'mock','trivy',None,ToolStatus.READY)
    context=ScanContext(str(tmp_path),ScanMode.RELEASE,('pom.xml','Dockerfile','App.java'))
    scopes=[]
    def execute(args,cwd,timeout):
        scopes.append((args[args.index('--scanners')+1], sorted(p.name for p in Path(cwd).rglob('*') if p.is_file())))
        return ProcessResult(0,json.dumps({'Results':[]}), '',1)
    with patch.object(manager,'prepare_trivy_database',return_value=ToolStatus.READY) as db, patch('security_runtime.scanners._execute',side_effect=execute):
        _,iac=TrivyMisconfigAdapter(manager).scan(context,FindingNormalizer(tmp_path))
        assert iac.status=='SUCCESS' and not db.called
        _,vuln=TrivyAdapter(manager).scan(context,FindingNormalizer(tmp_path))
        assert vuln.status=='SUCCESS' and db.call_count==1
    assert scopes[0]==('misconfig',['Dockerfile'])
    assert scopes[1][0]=='vuln'
    assert TrivyAdapter(manager).required_engines()==TrivyMisconfigAdapter(manager).required_engines()==('trivy',)


def test_no_secret_or_unexecuted_capabilities(tmp_path):
    from security_runtime.capabilities import Capability
    vuln=TrivyAdapter(ToolManager(root=tmp_path/'managed'))
    iac=TrivyMisconfigAdapter(vuln.tool_manager)
    assert vuln.capabilities=={Capability.DEPENDENCY_VULN}
    assert iac.capabilities=={Capability.IAC_MISCONFIG}
    raw={'Results':[{'Target':'Dockerfile','Secrets':[{'Title':'secret'}],'Misconfigurations':[{'ID':'AVD-1'}],'Vulnerabilities':[{'VulnerabilityID':'CVE-1'}]}]}
    n=FindingNormalizer(tmp_path)
    assert [f.category for f in vuln.normalize(raw,n)]==['dependency']
    assert [f.category for f in iac.normalize(raw,n)]==['configuration']


def test_shared_engine_install_is_serialized(tmp_path):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    manager=ToolManager(root=tmp_path/'managed')
    active=maximum=0
    guard=threading.Lock()
    def transaction(name,**kwargs):
        nonlocal active,maximum
        with guard:
            active+=1
            maximum=max(maximum,active)
        time.sleep(.02)
        with guard:
            active-=1
        return ResolvedTool(name,'mock','trivy',None,ToolStatus.READY)
    with patch.object(manager,'_ensure',side_effect=transaction),ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(manager.ensure,['trivy','trivy']))
    assert maximum==1


def test_vulnerability_database_content_fingerprinting_is_off(tmp_path, monkeypatch):
    manager = ToolManager(root=tmp_path/'managed')
    def unexpected(*_args, **_kwargs):
        raise AssertionError('vulnerability database bytes must not be fingerprinted')
    monkeypatch.setattr('security_runtime.scanner_identity.content_identity', unexpected)
    assert manager.execution_data_identity('trivy', kind='vuln') is None
    assert manager.execution_data_identity('osv-scanner', ecosystems={'npm'}) is None


def test_misconfiguration_policy_bundle_content_binding_is_unchanged(tmp_path):
    manager = ToolManager(root=tmp_path/'managed')
    bundle = manager.trivy_cache_dir()/'checks'/'policy.rego'
    bundle.parent.mkdir(parents=True)
    bundle.write_text('first policy')
    first = manager.execution_data_identity('trivy', kind='misconfig')
    bundle.write_text('second policy')
    second = manager.execution_data_identity('trivy', kind='misconfig')
    assert first and second and first != second
