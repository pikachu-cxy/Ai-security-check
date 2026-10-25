"""429 fallback tests use fixture POMs and mocked Trivy output, never networks."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.maven_direct import declarations, MavenDirectAdapter
from security_runtime.models import ScanContext, ScanMode, ScannerRun
from security_runtime.processes import ProcessResult
from security_runtime.toolchain import ToolManager, ToolStatus, ResolvedTool


def write(root, text, name='pom.xml'):
    p = root/name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">'+text+'</project>')


def test_direct_dependencies_only_with_properties_and_management(tmp_path):
    write(tmp_path, '''<properties><log.version>1.2.3</log.version></properties>
    <dependencyManagement><dependencies>
      <dependency><groupId>org.demo</groupId><artifactId>used</artifactId><version>${log.version}</version></dependency>
      <dependency><groupId>org.demo</groupId><artifactId>not-used</artifactId><version>9.9</version></dependency>
    </dependencies></dependencyManagement>
    <dependencies>
      <dependency><groupId>org.demo</groupId><artifactId>used</artifactId></dependency>
      <dependency><groupId>org.demo</groupId><artifactId>missing</artifactId><version>${remote.version}</version></dependency>
    </dependencies>''')
    packages, unresolved, gaps = declarations(tmp_path, ['pom.xml'])
    assert packages == [dict(manifest='pom.xml', group='org.demo', artifact='used', version='1.2.3')]
    assert len(unresolved) == 1 and gaps == []


def test_local_parent_inheritance_does_not_fetch_remote_parent(tmp_path):
    write(tmp_path, '''<groupId>local</groupId><artifactId>parent</artifactId><version>1</version>
      <properties><lib.version>2.0</lib.version></properties>
      <dependencyManagement><dependencies><dependency><groupId>org.demo</groupId>
      <artifactId>lib</artifactId><version>${lib.version}</version></dependency></dependencies></dependencyManagement>''')
    write(tmp_path, '''<parent><groupId>local</groupId><artifactId>parent</artifactId><version>1</version></parent>
      <artifactId>child</artifactId><dependencies><dependency><groupId>org.demo</groupId>
      <artifactId>lib</artifactId></dependency></dependencies>''', 'child/pom.xml')
    packages, unresolved, gaps = declarations(tmp_path, ['pom.xml', 'child/pom.xml'])
    assert packages[0]['manifest'] == 'child/pom.xml' and packages[0]['version'] == '2.0'
    assert not unresolved and not gaps


@pytest.mark.parametrize('version', ['${undefined}', '[1,2)', 'LATEST', '1.0-SNAPSHOT'])
def test_unresolved_or_dynamic_versions_are_not_guessed(tmp_path, version):
    write(tmp_path, '<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>'+version+'</version></dependency></dependencies>')
    packages, unresolved, _ = declarations(tmp_path, ['pom.xml'])
    assert not packages and len(unresolved) == 1


def test_parent_escape_and_remote_bom_remain_gaps(tmp_path):
    write(tmp_path, '''<parent><groupId>remote</groupId><artifactId>parent</artifactId><version>1</version>
      <relativePath>../../outside.xml</relativePath></parent><dependencyManagement><dependencies>
      <dependency><groupId>remote</groupId><artifactId>bom</artifactId><version>1</version>
      <scope>import</scope></dependency></dependencies></dependencyManagement>''')
    packages, _, gaps = declarations(tmp_path, ['pom.xml'])
    assert not packages
    assert {g['reason'] for g in gaps} == {'LOCAL_PARENT_OUTSIDE_SCOPE', 'IMPORTED_BOM_NOT_RESOLVED'}


def test_dtd_rejected_without_external_resource_access(tmp_path):
    (tmp_path/'pom.xml').write_text('<!DOCTYPE x [<!ENTITY x SYSTEM "file:///private">]><project/>')
    with pytest.raises(ValueError, match='DTD'):
        declarations(tmp_path, ['pom.xml'])


def adapter(tmp_path):
    manager = ToolManager(root=tmp_path/'managed')
    calls = []
    def ensure(tool, **kw):
        calls.append((tool, kw))
        assert kw.get('offline') is True
        return ResolvedTool('trivy','0.74.0','mock-trivy',None,ToolStatus.READY)
    manager.ensure = ensure
    manager.prepare_trivy_database = lambda binary, **kw: ToolStatus.READY if kw.get('offline') is True else pytest.fail('online DB preparation')
    manager.database_freshness = lambda: dict(status='FRESH')
    return MavenDirectAdapter(manager), calls


def test_sbom_checks_direct_inventory_and_returns_original_manifest(tmp_path):
    write(tmp_path, '<dependencies><dependency><groupId>org.demo</groupId><artifactId>lib</artifactId><version>1.2.3</version></dependency></dependencies>')
    a, calls = adapter(tmp_path)
    context = ScanContext(str(tmp_path), ScanMode.RELEASE, ('pom.xml',))
    def execute(args, cwd, timeout):
        assert args[1] == 'sbom' and '--offline-scan' in args
        assert '--skip-db-update' in args and '--skip-java-db-update' in args
        assert '--disable-telemetry' in args and '--skip-version-check' in args
        assert 'fs' not in args and '--skip-check-update' not in args
        sbom = json.loads(Path(args[-1]).read_text())
        assert len(sbom['components']) == 1
        assert sbom['components'][0]['purl'] == 'pkg:maven/org.demo/lib@1.2.3'
        return ProcessResult(0, json.dumps(dict(Results=[dict(Type='pom',
            Packages=[dict(Name='org.demo:lib',Version='1.2.3')],
            Vulnerabilities=[dict(PkgName='org.demo:lib',InstalledVersion='1.2.3',
            VulnerabilityID='CVE-TEST-1',Severity='HIGH',FixedVersion='1.2.4')])])), '', 1)
    with patch('security_runtime.maven_direct._execute', side_effect=execute):
        findings, run = a.scan(context, FindingNormalizer(tmp_path))
    assert calls and len(findings) == 1 and findings[0].file_path == 'pom.xml'
    assert run.status == 'SUCCESS' and run.coverage_contract == 'PARTIAL'
    assert run.dependency_inventory['direct_dependencies_only'] is True
    assert run.dependency_inventory['complete_dependency_graph_attested'] is False
    assert run.dependency_inventory['scanner_confirmed_packages'] == 1
    assert '429' in run.coverage_notes[0]


def test_runtime_429_uses_direct_adapter_instead_of_remote_osv(tmp_path, monkeypatch):
    from security_runtime.capabilities import Capability
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry, TrivyAdapter
    from security_runtime.storage import SQLiteStore
    from test_dependency_fallback import Adapter
    write(tmp_path, '<dependencies/>')
    class Limited(TrivyAdapter):
        def scan(self, context, normalizer):
            return [], ScannerRun(self.name,'mock','FAILED',1,error_code='MAVEN_RATE_LIMITED')
    primary = Limited(ToolManager(root=tmp_path/'managed'))
    calls = []
    class Direct(Adapter):
        def __init__(self, manager):
            super().__init__('trivy-maven-direct',Capability.DEPENDENCY_VULN,contract='PARTIAL',role='FALLBACK')
        def scan(self, context, normalizer):
            calls.append('direct')
            return super().scan(context,normalizer)
    monkeypatch.setattr('security_runtime.maven_direct.MavenDirectAdapter',Direct)
    osv = Adapter('osv-scanner',Capability.DEPENDENCY_VULN,role='FALLBACK')
    runtime = SecurityRuntime(ScannerRegistry([primary],fallback_adapters=[osv]),SQLiteStore(tmp_path/'state/scans.db'))
    result = runtime.scan(tmp_path,'release')
    assert calls == ['direct'] and osv.calls == 0
    assert result.capability_results['DEPENDENCY_VULN'] == 'PARTIAL'
    assert result.capability_details['DEPENDENCY_VULN']['primary_error_code'] == 'MAVEN_RATE_LIMITED'
