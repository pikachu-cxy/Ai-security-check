"""Product registration excludes retired models without rewriting old findings."""
import subprocess
import sys
from types import SimpleNamespace
import pytest
from security_runtime.scanners import ScannerRegistry, RETIRED_DATAFLOW_PROVIDERS


def test_default_registry_does_not_construct_or_import_retired_models():
    code='''
import sys
from security_runtime.scanners import ScannerRegistry
registry=ScannerRegistry()
assert {'opengrep','gitleaks','trivy-vuln'} <= {a.scanner_id for a in registry.adapters}
assert not {'native-dataflow','native-go-sql'} & {a.scanner_id for a in registry.adapters}
assert 'security_runtime.dataflow' not in sys.modules
assert 'security_runtime.go_sql' not in sys.modules
from security_runtime.scan_reuse import _known_adapters
_known_adapters()
assert 'security_runtime.dataflow' not in sys.modules
assert 'security_runtime.go_sql' not in sys.modules
'''
    subprocess.run([sys.executable,'-c',code],check=True)


@pytest.mark.parametrize('provider',sorted(RETIRED_DATAFLOW_PROVIDERS))
def test_explicit_and_fallback_registry_cannot_reenable(provider):
    retired=SimpleNamespace(name=provider,scanner_id=provider,engine_id=provider)
    registry=ScannerRegistry([retired],fallback_adapters=[retired])
    assert registry.adapters==[] and registry.fallback_adapters==[]


def test_history_display_keeps_retired_findings():
    from security_runtime.dashboard_records import enrich
    row=dict(workspace='/fixture',owner={'session':'s'},key='check')
    risk=dict(finding={'file_path':'app.py','scanner_sources':['native-dataflow']},decision='CONFIRMED',observations=[{'source':'SCANNER','scan_id':'old'}])
    result=enrich(dict(location='app.py'),row,risk,scope={'workspace_id':'w','project_id':'p'})
    assert result['scanner_sources']==['native-dataflow']
    assert result['confirmed_risk'] and result['scan_ids']==['old']
