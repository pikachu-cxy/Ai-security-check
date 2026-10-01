import json
from pathlib import Path
from unittest.mock import patch

from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode
from security_runtime.processes import ProcessResult
from security_runtime.scanners import TrivyAdapter, TrivyMisconfigAdapter
from security_runtime.toolchain import ToolManager, ResolvedTool, ToolStatus


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
