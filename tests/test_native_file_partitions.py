"""Actual fixed-input local scanning, durable retry and incomplete coverage."""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sqlite3

import pytest

from security_runtime.dynamic_function import NativeFunctionScanner, NativeFunctionRulePlan, RULE_ID
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanContext, ScannerRun
from security_runtime.native_file_partitions import NativeParts
from security_runtime.progress import ScanCancelled
from security_runtime.scan_input import capture_scan_input
from security_runtime.scan_request import ScanRequest, SourceKind


@pytest.fixture
def sample(tmp_path, monkeypatch):
    monkeypatch.setenv('SECURITY_RUNTIME_STATE_DIR', str(tmp_path/'runtime-state'))
    root = tmp_path/'source';root.mkdir()
    hooks = HookStateStore(tmp_path/'private')
    key = hooks.key(root)
    return SimpleNamespace(root=root, hooks=hooks, key=key, scanner=NativeFunctionScanner(),
        now=lambda:100.0, state=SimpleNamespace(hooks=hooks, root=root, now=lambda:100.0))


def files(sample, count, *, size=None):
    names = tuple('source_%04d.ts'%n for n in range(count))
    for name in names:
        sample.root.joinpath(name).write_text('const value = 1;\n' if size is None else ' '*size)
    sample.root.joinpath(names[-1]).write_text('new Function(expression);\n' if size is None else ' '*size)
    return names


@contextmanager
def captured(sample, names):
    request = ScanRequest(sample.root, 'release', SourceKind.WORKTREE, names,
                          bindings=sample.scanner.input_bindings())
    with capture_scan_input(request, identity_key=sample.key) as view:
        context = ScanContext(str(view.execution_root), 'release', names,
            logical_root=str(sample.root), input_view=view)
        plan = sample.scanner.plan_rules(None, context)
        yield replace(context, rule_plan=plan), FindingNormalizer(view.execution_root, identity_root=sample.root), plan


def scan(sample, names):
    with captured(sample, names) as (context, normalizer, plan):
        found, run = sample.scanner.scan(context, normalizer, partition_state=sample.state)
        return found, run, plan


def test_1001_actual_files_and_last_file_are_scanned_without_a_fixed_prefix(sample):
    names = files(sample,1001)
    found, run, plan = scan(sample,names)
    assert run.coverage_contract == 'FULL' and run.status == 'SUCCESS'
    assert len(plan.scanned_files) == 1001 and plan.errored_files == set()
    assert [f.file_path for f in found] == [names[-1]]
    assert run.scanner_diagnostics['partitions']['total'] == 4
    assert len(NativeParts(sample.hooks,sample.root,now=sample.now).rows()) == 4


def test_failed_middle_part_retries_only_that_part_and_merges_all_findings(sample,monkeypatch):
    names=files(sample,513)
    real=sample.scanner._scan_page
    attempted=[]
    def fail(context,normalizer):
        attempted.append(tuple(context.files))
        if context.files[0]==names[256]:
            return [],ScannerRun(sample.scanner.name,'1','FAILED',0,coverage_contract='NONE')
        return real(context,normalizer)
    with monkeypatch.context() as scoped:
        scoped.setattr(sample.scanner,'_scan_page',fail)
        _, first, _=scan(sample,names)
    assert first.coverage_contract=='PARTIAL' and len(attempted)==3
    assert len(NativeParts(sample.hooks,sample.root,now=sample.now).rows())==2
    attempted.clear()
    def observe(context,normalizer):
        attempted.append(tuple(context.files));return real(context,normalizer)
    monkeypatch.setattr(sample.scanner,'_scan_page',observe)
    found,current,plan=scan(sample,names)
    assert attempted==[names[256:512]]
    assert current.coverage_contract=='FULL' and plan.scanned_files==set(names)
    assert len(found)==1 and found[0].file_path==names[-1]
    assert current.scanner_diagnostics['partitions']['reused']==2
    assert current.scanner_diagnostics['partitions']['fresh']==1


def test_capacity_pause_keeps_prefix_and_retries_only_uncommitted_and_remaining_parts(sample,monkeypatch):
    names=files(sample,513)
    sample.root.joinpath(names[256]).write_text('eval(user_input);\n')
    with monkeypatch.context() as scoped:
        scoped.setattr(NativeParts,'max_rows',1)
        available, paused, _=scan(sample,names)
    store=NativeParts(sample.hooks,sample.root,now=sample.now)
    original=store.rows()
    assert len(original)==1 and paused.coverage_contract!='FULL'
    assert names[256] in {finding.file_path for finding in available}
    assert paused.error_code=='SCAN_PARTITION_WAITING_CAPACITY'
    attempted=[];real=sample.scanner._scan_page
    def observe(context,normalizer):
        attempted.append(tuple(context.files));return real(context,normalizer)
    monkeypatch.setattr(sample.scanner,'_scan_page',observe)
    _, current, _=scan(sample,names)
    assert current.coverage_contract=='FULL'
    assert attempted==[names[256:512],names[512:]]
    assert store.read(original[0]['key'])==original[0]


def test_real_sql_rollback_and_cancellation_leave_original_committed_facts(sample,monkeypatch):
    names=files(sample,513);real=sample.scanner._scan_page
    def cancel(context,normalizer):
        if context.files[0]==names[256]:raise ScanCancelled()
        return real(context,normalizer)
    with monkeypatch.context() as scoped:
        scoped.setattr(sample.scanner,'_scan_page',cancel)
        with pytest.raises(ScanCancelled):scan(sample,names)
    store=NativeParts(sample.hooks,sample.root,now=sample.now)
    original=store.rows();assert len(original)==1
    with sqlite3.connect(store.path) as db:
        db.execute("CREATE TRIGGER part_fault BEFORE INSERT ON records "
                   "BEGIN SELECT RAISE(ABORT, 'partition checkpoint failed'); END")
    _, paused, _=scan(sample,names)
    assert paused.coverage_contract!='FULL' and store.rows()==original
    with sqlite3.connect(store.path) as db:db.execute('DROP TRIGGER part_fault')
    _, complete, _=scan(sample,names)
    assert complete.coverage_contract=='FULL' and store.read(original[0]['key'])==original[0]


def test_changed_source_invalidates_all_old_parts_instead_of_mixing_versions(sample):
    names=files(sample,257)
    assert scan(sample,names)[1].coverage_contract=='FULL'
    sample.root.joinpath(names[0]).write_text('eval(user_input);\n')
    found,run,_=scan(sample,names)
    assert run.scanner_diagnostics['partitions']['reused']==0
    assert {f.file_path for f in found}=={names[0],names[-1]}


def test_actual_byte_budget_splits_large_finite_source_without_dropping_tail(sample):
    names=files(sample,9,size=999_000)
    _,run,plan=scan(sample,names)
    assert run.coverage_contract=='FULL' and plan.scanned_files==set(names)
    assert run.scanner_diagnostics['partitions']['total']==2


def test_bytes_actually_parsed_must_match_original_capture_even_if_view_is_restored(sample,monkeypatch):
    from security_runtime.local_evidence import WorkspaceReader
    names=files(sample,257);real=WorkspaceReader.read
    def wrong(reader,name,*args,**kwargs):
        raw,text=real(reader,name,*args,**kwargs)
        return (b'const safe = true;\n','const safe = true;\n') if name==names[-1] else (raw,text)
    with monkeypatch.context() as scoped:
        scoped.setattr(WorkspaceReader,'read',wrong)
        found,run,plan=scan(sample,names)
    assert run.coverage_contract=='PARTIAL' and names[-1] in plan.errored_files
    assert not found
    assert len(NativeParts(sample.hooks,sample.root,now=sample.now).rows())==1


def test_closed_view_and_mutable_index_cannot_change_capture_authority(sample):
    names=files(sample,1)
    with captured(sample,names) as (context,normalizer,plan):
        view=context.input_view
        with pytest.raises(TypeError):view.source_entries[names[0]]=view.manifest[0]
        raw=(view.execution_root/names[0]).read_bytes()
        view.assert_content(names[0],raw)
    with pytest.raises(ValueError,match='SCAN_INPUT_CLOSED'):view.assert_content(names[0],raw)


def test_unknown_subclass_keeps_one_atomic_scope(sample):
    names=files(sample,257);seen=[]
    class ProjectProvider(NativeFunctionScanner):
        def _scan_page(self,context,normalizer):
            seen.append(tuple(context.files))
            return [],ScannerRun(self.name,'1','SUCCESS',0)
    scanner=ProjectProvider()
    context=ScanContext(str(sample.root),'release',names)
    scanner.scan(context,FindingNormalizer(sample.root))
    assert seen==[names]


def test_closed_view_cannot_reuse_previously_saved_partitions(sample):
    names=files(sample,257)
    with captured(sample,names) as (context,normalizer,plan):
        assert sample.scanner.scan(context,normalizer,partition_state=sample.state)[1].coverage_contract=='FULL'
    fresh=replace(context,rule_plan=NativeFunctionRulePlan(plan.pack,names))
    assert sample.scanner.scan(fresh,normalizer,partition_state=sample.state)[1].coverage_contract!='FULL'


def test_corrupt_saved_partition_is_a_gap_not_permission_to_rebuild_progress(sample):
    names=files(sample,257);scan(sample,names)
    store=NativeParts(sample.hooks,sample.root,now=sample.now)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE records SET mac=? WHERE key=(SELECT key FROM records ORDER BY rowid LIMIT 1)",('0'*64,))
    before=store.path.read_bytes()
    _,run,_=scan(sample,names)
    assert run.coverage_contract!='FULL' and run.error_code=='SCAN_PARTITION_STATE_UNAVAILABLE'
    assert store.path.read_bytes()==before


def test_actual_runtime_retries_native_parts_keeps_project_provider_atomic_and_honors_force(sample,monkeypatch,tmp_path):
    from security_runtime.capabilities import Capability
    from security_runtime.explicit_scan import run_explicit_scan
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.storage import SQLiteStore
    names=files(sample,513);scopes=[]
    class ProjectProvider:
        name=scanner_id=engine_id='project-context-fixture'
        capabilities=frozenset({Capability.CODE_SAST})
        supported_languages=frozenset({'TypeScript'})
        supported_ecosystems=frozenset()
        def required_engines(self):return ()
        def supports(self,profile,context):return True
        def scan(self,context,normalizer):
            scopes.append(tuple(context.files))
            return [],ScannerRun(self.name,'1','SUCCESS',0,capabilities=tuple(self.capabilities))
    runtime=SecurityRuntime(ScannerRegistry([sample.scanner,ProjectProvider()],fallback_adapters=[]),
                            SQLiteStore(tmp_path/'scan-state'/'scans.db'))
    real=sample.scanner._scan_page;attempted=[]
    def failed(context,normalizer):
        if context.files[0]==names[256]:
            return [],ScannerRun(sample.scanner.name,'1','FAILED',0,coverage_contract='NONE')
        return real(context,normalizer)
    with monkeypatch.context() as scoped:
        scoped.setattr(sample.scanner,'_scan_page',failed)
        first=run_explicit_scan(runtime,sample.root,mode='release',hooks=sample.hooks)
    assert first.rule_coverage['status']=='PARTIAL'
    def observed(context,normalizer):
        attempted.append(tuple(context.files));return real(context,normalizer)
    monkeypatch.setattr(sample.scanner,'_scan_page',observed)
    current=run_explicit_scan(runtime,sample.root,mode='release',hooks=sample.hooks)
    assert attempted==[names[256:512]]
    assert current.rule_coverage['status']=='EXECUTED' and scopes==[names,names]
    attempted.clear()
    run_explicit_scan(runtime,sample.root,mode='release',hooks=sample.hooks,force_rescan=True)
    assert attempted==[names[:256],names[256:512],names[512:]]
    assert scopes==[names,names,names]
