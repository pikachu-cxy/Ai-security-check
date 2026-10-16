"""Cache freshness, reverse dependency expansion, and budget counterexamples."""
import ast
from dataclasses import replace
import os
from pathlib import Path

import pytest

from security_runtime import dataflow
from security_runtime.dataflow import BoundedDataflowScanner
from security_runtime.findings import FindingNormalizer
from security_runtime.flow_cache import FlowCache
from security_runtime import flow_cache
from security_runtime.flow_core import Analysis, Limit
from security_runtime.flow_python import PythonFlow
from security_runtime.models import ScanContext, ScanMode


ENTRY = '''from flask import request
from helper import read
def route(): return read(request.args.get('name'))
'''
UNSAFE = '''import io
def read(name): return io.open(name)
'''
SAFE = '''import io
def read(name): return io.open('ok')
'''


def write(root, **files):
    for name, text in files.items(): (root / name).write_text(text, encoding='utf-8')


def execute(root, scanner, files=('entry.py',), mode=ScanMode.RELEASE, normalizer=None):
    return scanner.scan(ScanContext(str(root), mode, files), normalizer or FindingNormalizer(root))


def signature(found):
    return {(f.file_path, f.line_start, f.category, tuple((s['file'],s['line'],s['kind'])
        for s in f.technical_details['dataflow_trace'])) for f in found}


def test_repeat_revalidates_sources_and_preserves_findings(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner()
    first, cold=execute(tmp_path,scanner)
    first[0].title='caller mutation must not enter cache'
    second, warm=execute(tmp_path,scanner)
    assert signature(first)==signature(second) and second[0].title!=first[0].title
    assert cold.scanner_diagnostics['cache_misses']==1
    assert warm.scanner_diagnostics['cache_hits']==1
    assert warm.scanner_diagnostics['abstract_steps']==0
    assert warm.scanner_diagnostics['reused_abstract_steps']>0
    assert second[0].technical_details['analysis_reuse']=='SOURCE_REVALIDATED_MEMORY_CACHE'
    assert warm.rule_coverage['verification_scope_complete'] is False


def test_same_size_and_mtime_helper_change_invalidates_result(tmp_path):
    a,b=UNSAFE.ljust(100),SAFE.ljust(100)
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':a})
    scanner=BoundedDataflowScanner()
    assert len(execute(tmp_path,scanner)[0])==1
    helper=tmp_path/'helper.py'; stamp=helper.stat()
    helper.write_text(b,encoding='utf-8');os.utime(helper,ns=(stamp.st_atime_ns,stamp.st_mtime_ns))
    found,run=execute(tmp_path,scanner)
    assert not found and run.scanner_diagnostics['cache_hits']==0
    assert run.scanner_diagnostics['parse_hits']>=1
    assert run.scanner_diagnostics['parse_misses']>=1


def test_previously_missing_module_appearing_invalidates_negative_result(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY})
    scanner=BoundedDataflowScanner()
    assert not execute(tmp_path,scanner)[0]
    write(tmp_path, **{'helper.py':UNSAFE})
    found,run=execute(tmp_path,scanner)
    assert len(found)==1 and run.scanner_diagnostics['cache_hits']==0


@pytest.mark.parametrize('package', [False,True])
def test_new_local_flask_shadow_invalidates_positive_result(tmp_path,package):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner();assert execute(tmp_path,scanner)[0]
    target=tmp_path/('flask/__init__.py' if package else 'flask.py')
    target.parent.mkdir(exist_ok=True)
    target.write_text('request = None\n',encoding='utf-8')
    found,run=execute(tmp_path,scanner)
    assert not found and run.scanner_diagnostics['cache_hits']==0


def test_deleted_helper_cannot_replay_a_cached_positive(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner();assert execute(tmp_path,scanner)[0]
    (tmp_path/'helper.py').unlink()
    found,run=execute(tmp_path,scanner)
    assert not found and run.scanner_diagnostics['cache_hits']==0


def test_feature_helper_change_revisits_a_previous_caller(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':SAFE})
    scanner=BoundedDataflowScanner();assert not execute(tmp_path,scanner)[0]
    write(tmp_path, **{'helper.py':UNSAFE})
    found,run=execute(tmp_path,scanner,('helper.py',),ScanMode.FEATURE)
    fresh,_=execute(tmp_path,BoundedDataflowScanner(cache=False),('entry.py','helper.py'))
    assert signature(found)==signature(fresh) and len(found)==1
    assert run.rule_coverage['requested_scope_files']==['helper.py']
    assert run.rule_coverage['scope_files']==['entry.py','helper.py']
    assert run.rule_coverage['incremental_prior_targets']==1
    assert run.rule_coverage['reverse_dependency_index']=='RETAINED_ANALYSES_ONLY'


def test_unrelated_feature_change_does_not_expand_to_old_callers(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE,'other.py':'x=1\n'})
    scanner=BoundedDataflowScanner();execute(tmp_path,scanner)
    _,run=execute(tmp_path,scanner,('other.py',),ScanMode.FEATURE)
    assert run.rule_coverage['scope_files']==['other.py']
    assert run.rule_coverage['incremental_prior_targets']==0


def test_rule_identity_change_invalidates_both_cache_levels(tmp_path,monkeypatch):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner();execute(tmp_path,scanner)
    original=dataflow.rule_pack()
    monkeypatch.setattr(dataflow,'rule_pack',lambda:replace(original,checksum='a'*64))
    _,run=execute(tmp_path,scanner)
    assert run.scanner_diagnostics['cache_hits']==0
    assert run.scanner_diagnostics['parse_hits']==0


def test_ast_cache_never_shares_mutable_trees():
    cache=FlowCache()
    first,hit=cache.parse(('one',),'x=1',ast.parse)
    first.body.clear()
    second,hit=cache.parse(('one',),'x=1',ast.parse)
    assert hit and len(second.body)==1


def test_cache_rebuilds_finding_identity_for_current_normalizer(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner()
    old,_=execute(tmp_path,scanner)
    new,run=execute(tmp_path,scanner,normalizer=FindingNormalizer(tmp_path,identity_root=tmp_path/'different'))
    assert run.scanner_diagnostics['cache_hits']==1 and new[0].id!=old[0].id


def test_expired_analysis_is_partial_and_never_cached(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner()
    found,run=scanner._scan(ScanContext(str(tmp_path),ScanMode.FEATURE,('entry.py',)),FindingNormalizer(tmp_path),-1)
    assert not found and run.status=='PARTIAL'
    assert not scanner.cache.results


def test_partial_parse_failure_is_not_cached(tmp_path):
    write(tmp_path, **{'entry.py':'def invalid(:\n'})
    scanner=BoundedDataflowScanner()
    _,run=execute(tmp_path,scanner)
    assert run.status=='PARTIAL' and not scanner.cache.results


def test_java_negative_resolution_probe_detects_sdk_shadow(tmp_path):
    source='''import javax.servlet.http.HttpServletRequest;
class Entry { void route(HttpServletRequest req) throws Exception {
 new java.io.FileReader(req.getParameter("file"));
} }'''
    write(tmp_path, **{'Entry.java':source})
    scanner=BoundedDataflowScanner(experimental=True)
    assert execute(tmp_path,scanner,('Entry.java',))[0]
    target=tmp_path/'java/io/FileReader.java';target.parent.mkdir(parents=True)
    target.write_text('package java.io; public class FileReader { public FileReader(String value) {} }',encoding='utf-8')
    found,run=execute(tmp_path,scanner,('Entry.java',))
    assert not found and run.scanner_diagnostics['cache_hits']==0


def test_result_cache_eviction_is_bounded():
    cache=FlowCache(entries=1)
    cache.put(('root','one'),{'hashes':{},'probes':{},'targets':('first.py',)})
    cache.put(('root','two'),{'hashes':{},'probes':{},'targets':('second.py',)})
    assert cache.get(('root','one')) is None and len(cache.results)==1


def test_cached_source_replaced_with_symlink_cannot_be_reused(tmp_path):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE,'elsewhere.py':UNSAFE})
    scanner=BoundedDataflowScanner();assert execute(tmp_path,scanner)[0]
    target=tmp_path/'helper.py';target.unlink()
    try: target.symlink_to(tmp_path/'elsewhere.py')
    except OSError: pytest.skip('Symlink creation unavailable on this Windows account')
    found,run=execute(tmp_path,scanner)
    assert not found and run.status=='PARTIAL' and run.scanner_diagnostics['cache_hits']==0


@pytest.mark.parametrize('probe_change',[False,True])
def test_final_proof_covers_negative_results_and_probes_across_batches(tmp_path,monkeypatch,probe_change):
    files={f'f{i:03}.py':'x=1\n' for i in range(81)}
    if probe_change:
        files['f000.py']='from flask import request\nimport io\ndef route(): io.open(request.args.get("name"))\n'
    write(tmp_path,**files)
    original=PythonFlow.analyze
    def mutate_later(self,file):
        if file=='f080.py':
            if probe_change: (tmp_path/'flask.py').write_text('request=None\n',encoding='utf-8')
            else: (tmp_path/'f000.py').write_text('x=2\n',encoding='utf-8')
        return original(self,file)
    monkeypatch.setattr(PythonFlow,'analyze',mutate_later)
    scanner=BoundedDataflowScanner()
    found,run=execute(tmp_path,scanner,tuple(files))
    assert not found and run.status=='PARTIAL'
    assert run.scanner_diagnostics['source_stable'] is False
    assert run.rule_coverage['total_executed']==0 and not scanner.cache.results


def test_warm_result_is_rechecked_after_normalization(tmp_path,monkeypatch):
    write(tmp_path, **{'entry.py':ENTRY,'helper.py':UNSAFE})
    scanner=BoundedDataflowScanner();execute(tmp_path,scanner)
    normalizer=FindingNormalizer(tmp_path);original=normalizer.make
    def changed(**kwargs):
        write(tmp_path,**{'helper.py':SAFE})
        return original(**kwargs)
    monkeypatch.setattr(normalizer,'make',changed)
    found,run=execute(tmp_path,scanner,normalizer=normalizer)
    assert run.scanner_diagnostics['cache_hits']==1
    assert not found and run.status=='PARTIAL' and not scanner.cache.results


def test_cache_identity_isolated_between_workspaces(tmp_path):
    first,second=tmp_path/'one',tmp_path/'two'
    first.mkdir();second.mkdir()
    write(first,**{'entry.py':ENTRY,'helper.py':UNSAFE})
    write(second,**{'entry.py':ENTRY,'helper.py':SAFE})
    scanner=BoundedDataflowScanner();assert execute(first,scanner)[0]
    found,run=execute(second,scanner)
    assert not found and run.scanner_diagnostics['cache_hits']==0


def test_abstract_step_check_observes_soft_deadline(tmp_path):
    analysis=Analysis(tmp_path,deadline=-1)
    with pytest.raises(Limit,match='TIME_BUDGET'):
        for _ in range(128): analysis.tick()


def test_process_change_discards_inherited_cache_and_lock(monkeypatch):
    cache=FlowCache()
    cache.put(('root',),{'targets':()})
    cache.parse(('tree',),'x=1',ast.parse)
    previous_lock=cache.lock; previous_pid=cache.pid
    monkeypatch.setattr(flow_cache.os,'getpid',lambda:previous_pid+1)
    assert cache.get(('root',)) is None
    assert not cache.asts and cache.lock is not previous_lock
