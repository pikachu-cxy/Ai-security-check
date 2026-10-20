"""Explicit selections reach immutable provider inputs, never project discovery."""
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from security_runtime.capabilities import Capability
from security_runtime.explicit_scan import ExplicitScanBusy, run_explicit_scan
from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScannerRun
from security_runtime.progress import ProgressReporter
from security_runtime.runtime import SecurityRuntime
from security_runtime.scan_attempt import ScanAttemptLost, ScanAttemptStore, source_binding
from security_runtime.scan_freshness import summary
from security_runtime.scan_request import ScanInputError
from security_runtime.scanners import ScannerRegistry
from security_runtime.selected_scan import selected_request
from security_runtime.storage import ReadOnlySQLiteStore, SQLiteStore
from security_runtime.workspace_application import WorkspaceApplication


class SelectionReader:
    name = scanner_id = 'selection-reader'
    capabilities = frozenset({Capability.CODE_SAST, Capability.SECRET_SCAN,
                              Capability.IAC_MISCONFIG, Capability.DEPENDENCY_VULN})
    filter_changed_lines = True

    def __init__(self):
        self.calls = []
        self.callback = None

    def supports(self, profile, context):
        return bool(context.files)

    def scan(self, context, normalizer):
        root = Path(context.root)
        self.calls.append(dict(root=root, files=context.files, context=context.context_files,
            present=sorted(path.relative_to(root).as_posix() for path in root.rglob('*') if path.is_file()),
            contents={name:(root/name).read_bytes() for name in context.files}, mode=context.mode))
        if self.callback:
            self.callback(context)
        finding = normalizer.make(scanner=self.name, category='sql-injection', title='Fixture call',
            description='Deterministic provider contract fixture', severity='HIGH', confidence='MEDIUM',
            file_path=context.files[0], line=1, rule_id='fixture.selected')
        return [finding], ScannerRun(self.name, 'fixture', 'SUCCESS', 0)


@pytest.fixture
def selection(tmp_path, monkeypatch):
    root = tmp_path/'project'
    root.mkdir()
    (root/'demo.py').write_bytes(b'query(value)\n')
    (root/'other.py').write_text('unselected_sensitive_source()\n')
    (root/'package.json').write_text('{"name":"context-only"}')
    (root/'nested').mkdir()
    (root/'nested/main.tf').write_text('resource "fixture" "selected" {}\n')
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR',str(tmp_path/'private'))
    monkeypatch.delenv('SECURITY_RUNTIME_WORKSPACE',raising=False)
    monkeypatch.delenv('SECURITY_RUNTIME_GLOBAL',raising=False)
    store = SQLiteStore(tmp_path/'private/scans.db')
    hooks = HookStateStore(store.path.parent/'hooks')
    reader = SelectionReader()
    runtime = SecurityRuntime(ScannerRegistry([reader],fallback_adapters=[]),store)
    application = WorkspaceApplication(runtime,hooks,scan_path_provider=lambda:store.path)
    return root,runtime,hooks,reader,application


@pytest.mark.parametrize('git',[False,True])
def test_selected_file_is_the_only_source_and_full_rules_are_not_diff_filtered(selection,git):
    root,runtime,hooks,reader,application = selection
    if git:
        subprocess.run(['git','init','-q',str(root)],check=True)
        subprocess.run(['git','-C',str(root),'add','.'],check=True)
        subprocess.run(['git','-C',str(root),'-c','user.name=Fixture','-c',
            'user.email=fixture@example.invalid','commit','-qm','fixture'],check=True)
    result = application.scan_files(str(root),['demo.py'])
    assert len(reader.calls)==1
    call=reader.calls[0]
    assert call['files']==('demo.py',) and call['context']==('package.json',)
    assert call['present']==['demo.py','package.json']
    assert call['mode']=='feature' and call['root']!=root and not call['root'].exists()
    # Unchanged tracked files still produce findings: this is not a diff scan.
    assert [finding.file_path for finding in result.findings]==['demo.py']
    scope=result.scanner_diagnostics['selected_scope']
    assert scope['contract']=='selected-file-scan-v1'
    assert scope['requested_files']==scope['target_files']==['demo.py']
    assert scope['context_files']==['package.json']
    assert not scope['full_project'] and not scope['expanded_to_project']
    stored=runtime.store.get_scan(result.scan_id)
    assert stored['scan_context']['requested_scope']=='SELECTED_FILES'
    assert stored['scan_context']['input_files']==['demo.py']
    assert stored['scan_context']['context_files']==['package.json']
    freshness=summary(stored,ReadOnlySQLiteStore(runtime.store.path),root)
    assert not freshness['full_project_reusable']
    assert freshness['reuse_reason']=='NOT_WHOLE_PROJECT_SCAN'
    lane=ScanAttemptStore(hooks,root).read()
    assert lane['lane']['state']=='COMPLETED' and not lane['directories']
    assert not (hooks.workspace_directory(root)/'security-tasks.db').exists()


def test_multiple_files_keep_iac_in_the_requested_scope(selection):
    root,_,_,reader,application=selection
    result=application.scan_files(root,['demo.py','nested/main.tf'])
    assert set(reader.calls[0]['files'])=={'demo.py','nested/main.tf'}
    assert result.capability_results[Capability.IAC_MISCONFIG]=='EXECUTED'
    assert 'other.py' not in reader.calls[0]['present']


@pytest.mark.parametrize('files',[
    None,[],(),['demo.py']*101,'demo.py',{'demo.py'},['demo.py','demo.py'],
    ['../demo.py'],['nested/../demo.py'],['./demo.py'],['/demo.py'],
    ['C:/demo.py'],['C:\\demo.py'],['\\\\host\\share\\demo.py'],
    ['nested\\main.tf'],['*.py'],['demo?.py'],['[demo].py'],['nested/'],
    ['missing.py'],['nested'],[False],[''],['NUL.py'],
])
def test_invalid_selections_fail_before_scanner_or_lease(selection,files):
    root,_,hooks,reader,application=selection
    with pytest.raises(ScanInputError):
        application.scan_files(root,files)
    assert not reader.calls
    # Malformed requests do not create a scan attempt or claim the shared lane.
    assert not (hooks.workspace_directory(root)/'scan-attempt.state').exists()


def test_ignored_selected_file_is_rejected_instead_of_silently_dropped(selection):
    root,_,_,reader,application=selection
    (root/'dist').mkdir()
    (root/'dist/demo.py').write_text('query(value)\n')
    with pytest.raises(ScanInputError,match='SCAN_FILES_TARGET_EXCLUDED'):
        application.scan_files(root,['dist/demo.py'])
    assert not reader.calls


def test_unsupported_document_is_rejected_instead_of_reporting_no_changes(selection):
    root,_,_,reader,application=selection
    (root/'image.png').write_bytes(b'\x89PNG\r\n\x1a\nfixture')
    with pytest.raises(ScanInputError,match='SCAN_FILES_TARGET_UNSUPPORTED'):
        application.scan_files(root,['image.png'])
    assert not reader.calls


def test_disappearance_after_validation_cannot_become_a_successful_empty_scan(selection,monkeypatch):
    root,runtime,hooks,reader,application=selection
    original=runtime.scan
    def disappear(*args,**kwargs):
        (root/'demo.py').unlink()
        return original(*args,**kwargs)
    monkeypatch.setattr(runtime,'scan',disappear)
    with pytest.raises(ScanAttemptLost,match='SCAN_ATTEMPT_SOURCE_MISMATCH'):
        application.scan_files(root,['demo.py'])
    assert not reader.calls
    lane=ScanAttemptStore(hooks,root).read()
    assert lane['lane']['state']=='CANCELLED' and not lane['directories']


def test_symlink_selection_does_not_read_external_bytes(selection,tmp_path):
    root,_,_,reader,application=selection
    external=tmp_path/'external.py'
    external.write_text('outside_source()\n')
    try:
        (root/'linked.py').symlink_to(external)
    except OSError:
        pytest.skip('Platform does not permit unprivileged symbolic links')
    with pytest.raises(ScanInputError,match='SCAN_FILES_SELECTION_UNVERIFIABLE'):
        application.scan_files(root,['linked.py'])
    assert not reader.calls


def test_file_request_observes_the_same_lane_and_preserves_binding(selection):
    root,runtime,hooks,reader,_=selection
    root2=root.parent/'another'
    root2.mkdir()
    (root2/'demo.py').write_text('another()\n')
    application=WorkspaceApplication(runtime,hooks,binding=SimpleNamespace(root=str(root)),
        scan_path_provider=lambda:runtime.store.path)
    with pytest.raises(ValueError,match='outside this MCP connection'):
        application.scan_files(root2,['demo.py'])
    attempts=ScanAttemptStore(hooks,root)
    with hooks.lock(root) as acquired:
        assert acquired
        lease=attempts.claim('MANUAL','existing',source_binding({'contract':'fixture'}))
    assert lease is not None
    with pytest.raises(ExplicitScanBusy):
        application.scan_files(root,['demo.py'])
    assert not reader.calls and attempts.read()['lane']['state']=='ACTIVE'


def test_changes_during_selected_scan_are_stale_and_private_bytes_are_released(selection):
    root,_,hooks,reader,application=selection
    reader.callback=lambda _context:(root/'demo.py').write_text('changed()\n')
    result=application.scan_files(root,['demo.py'])
    assert result.status=='PARTIAL' and result.coverage=='UNKNOWN'
    assert reader.calls[0]['contents']['demo.py']==b'query(value)\n'
    assert result.scan_context['fixed_input']['applicability']=='STALE'
    assert result.scanner_diagnostics['execution_publication']['publication']=='STALE'
    assert not ScanAttemptStore(hooks,root).read()['directories']


def test_direct_selected_scan_rejects_diff_mode_and_staged_without_execution(selection):
    root,runtime,_,reader,_=selection
    with pytest.raises(ValueError,match='require feature mode'):
        run_explicit_scan(runtime,root,files=['demo.py'])
    with pytest.raises(ValueError,match='require feature mode'):
        run_explicit_scan(runtime,root,mode='feature',staged=True,files=['demo.py'])
    assert not reader.calls


def test_project_reuse_retains_scan_identity_and_does_not_claim_a_new_execution(selection,monkeypatch):
    from security_runtime import scan_reuse
    root,_,hooks,reader,application=selection
    original=dict(scan_id='historical-scan',findings=[dict(id='existing-finding')])
    receipt=dict(reused=True,reason_code='REVALIDATED')
    monkeypatch.setattr(scan_reuse,'try_reuse',lambda runtime,workspace,**kwargs:SimpleNamespace(
        reused=True,scan=original,receipt=receipt))
    events=[]
    result=application.scan_project(root,progress=ProgressReporter(events.append))
    assert result['scan_id']=='historical-scan' and result['findings']==original['findings']
    assert result['result_reuse']==receipt and 'result_reuse' not in original
    assert not reader.calls
    assert [event.event_type for event in events]==['SCAN_REUSE_CHECK_STARTED','SCAN_RESULT_REUSED']
    assert not (hooks.workspace_directory(root)/'scan-attempt.state').exists()


def test_force_rescan_bypasses_reuse_and_runs_the_project(selection,monkeypatch):
    from security_runtime import scan_reuse
    root,_,_,reader,application=selection
    monkeypatch.setattr(scan_reuse,'try_reuse',lambda *_args,**kwargs:pytest.fail('forced scan must bypass reuse'))
    result=application.scan_project(root,force_rescan=True)
    assert len(reader.calls)==1 and 'other.py' in reader.calls[0]['files']
    assert result.scanner_diagnostics['reuse_check']['reason_code']=='FORCE_RESCAN_REQUESTED'


def test_reuse_miss_runs_a_fresh_scan_and_keeps_the_explanation(selection,monkeypatch):
    from security_runtime import scan_reuse
    root,_,_,reader,application=selection
    receipt=dict(reused=False,reason_code='SOURCE_CHANGED')
    monkeypatch.setattr(scan_reuse,'try_reuse',lambda runtime,workspace,**kwargs:SimpleNamespace(
        reused=False,scan=None,receipt=receipt))
    result=application.scan_project(root)
    assert len(reader.calls)==1 and result.scan_id
    assert result.scanner_diagnostics['reuse_check']==receipt
