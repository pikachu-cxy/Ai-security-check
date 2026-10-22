from dataclasses import replace
from pathlib import Path

import pytest

from security_runtime.go_sql import GoAnalysis, GoSQLScanner, rule_pack
from security_runtime.findings import FindingNormalizer
from security_runtime.models import ScanContext, ScanMode


HANDLER = '''package app
import "net/http"
func Handle(w http.ResponseWriter, r *http.Request) {
    p := NewProfile()
    p.Lookup(r.FormValue("id"))
}
'''
HELPER = '''package app
import ("database/sql"; "fmt")
var DB *sql.DB
type Profile struct{}
func NewProfile() *Profile { return &Profile{} }
func (p *Profile) Lookup(id string) {
    query := fmt.Sprintf("SELECT name FROM users WHERE id=%s", id)
    DB.Query(query)
}
'''


def write(root, files):
    for name, text in files.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text,encoding='utf-8')


def scan(root, files):
    write(root,files)
    return GoSQLScanner().scan(ScanContext(str(root),ScanMode.RELEASE,tuple(files)),FindingNormalizer(root))


def test_cross_file_method_trace_and_hashes(tmp_path):
    found, run=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER})
    assert len(found)==1
    details=found[0].technical_details
    assert found[0].file_path=='query.go'
    assert {s['file'] for s in details['dataflow_trace']}=={'handler.go','query.go'}
    assert set(details['context_hashes'])=={'handler.go','query.go'}
    assert run.scanner_diagnostics['parsed_files']==2
    assert run.scanner_diagnostics['source_stable']


def test_two_direct_edges_and_inline_if_initializer(tmp_path):
    handler=HANDLER.replace('p := NewProfile()\n    p.Lookup(r.FormValue("id"))','First(r.URL.Query().Get("id"))')
    helper='''package app
import "database/sql"
var DB *sql.DB
func First(id string) { Second(id) }
func Second(id string) { if rows, err := DB.Query("SELECT "+id); err == nil { rows.Close() } }
'''
    found,run=scan(tmp_path,{'handler.go':handler,'query.go':helper})
    assert len(found)==1
    assert len([s for s in found[0].technical_details['dataflow_trace'] if s['kind']=='RESOLVED_CALL'])==2
    helper=helper.replace('Second(id) }','Third(id) }')+'\nfunc Third(id string) { Second(id) }\n'
    found,run=scan(tmp_path,{'handler.go':handler,'query.go':helper})
    assert not found and run.status=='PARTIAL'


def test_shadowed_function_does_not_resolve_by_name(tmp_path):
    handler=HANDLER.replace('p := NewProfile()\n    p.Lookup(r.FormValue("id"))','Lookup := unrelated\n Lookup(r.FormValue("id"))')
    helper=HELPER.replace('func (p *Profile) Lookup','func Lookup')
    found,run=scan(tmp_path,{'handler.go':handler,'query.go':helper})
    assert not found and run.status=='PARTIAL'


def test_invalid_helper_does_not_contribute_partial_index(tmp_path):
    helper=HELPER+'\nfunc Unsupported(a, b string) {}\n'
    found,run=scan(tmp_path,{'handler.go':HANDLER,'query.go':helper})
    assert not found and run.status=='PARTIAL'


def test_runtime_captures_native_go_evidence(tmp_path):
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.scanners import ScannerRegistry
    from security_runtime.storage import SQLiteStore
    root=tmp_path/'project';root.mkdir()
    write(root,{'handler.go':HANDLER,'query.go':HELPER})
    runtime=SecurityRuntime(ScannerRegistry([GoSQLScanner()],fallback_adapters=[]),SQLiteStore(tmp_path/'state'/'scan.db'))
    result=runtime.scan(root,'release')
    assert len(result.findings)==1
    assert result.findings[0].technical_details['dataflow_trace']
    assert result.coverage!='FULL'


@pytest.mark.parametrize('query',[
    'DB.Query("SELECT name FROM users WHERE id=?", id)',
    'stmt, err := DB.Prepare("SELECT name FROM users WHERE id=?"); stmt.QueryRow(id)',
    'DB.Query("SELECT name FROM users")',
])
def test_bound_values_and_fixed_sql_do_not_alert(tmp_path,query):
    helper=HELPER.replace('DB.Query(query)',query)
    found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':helper})
    assert not found


def test_tainted_prepare_is_not_a_sanitizer(tmp_path):
    found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER.replace('DB.Query(query)','DB.Prepare(query)')})
    assert len(found)==1


def test_query_context_uses_sql_argument_not_context_or_bound_values(tmp_path):
    for query, expected in [('DB.QueryContext(ctx, query)',1),('DB.QueryContext(id, "SELECT 1", id)',0)]:
        found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER.replace('DB.Query(query)',query)})
        assert len(found)==expected


def test_same_named_unrelated_receiver_is_not_database(tmp_path):
    found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER.replace('*sql.DB','*Unrelated')})
    assert not found


def test_missing_helper_and_ambiguous_method_are_partial(tmp_path):
    _,run=scan(tmp_path,{'handler.go':HANDLER})
    assert run.status=='PARTIAL'
    assert any(g['reason']=='GO_CALL_UNRESOLVED' for g in run.scanner_diagnostics['context_gaps'])
    found,run=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER,'duplicate.go':HELPER})
    assert not found and run.status=='PARTIAL'


def test_depth_recursion_time_and_file_budgets(tmp_path):
    files={'handler.go':HANDLER,'query.go':HELPER}
    write(tmp_path,files)
    for kwargs,reason in [({'max_depth':0},'GO_CALL_DEPTH_OR_RECURSION'),({'seconds':0},'GO_TIME_BUDGET'),
                           ({'max_files':1},'GO_FILE_BUDGET'),({'max_steps':1},'GO_STEP_BUDGET')]:
        a=GoAnalysis(tmp_path,tuple(files),**kwargs).run()
        assert any(r==reason for _,r in a.gaps)
    recursive=HELPER.replace('DB.Query(query)','p.Lookup(id)')
    write(tmp_path,{'query.go':recursive})
    a=GoAnalysis(tmp_path,tuple(files)).run()
    assert any(r=='GO_CALL_DEPTH_OR_RECURSION' for _,r in a.gaps)


def test_comments_literals_and_early_return_do_not_invent_sinks(tmp_path):
    helper=HELPER.replace('DB.Query(query)','return\n DB.Query(query)')
    found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':helper})
    assert not found
    helper=HELPER.replace('DB.Query(query)','// DB.Query(query)\n text := `DB.Query(query)`')
    found,_=scan(tmp_path,{'handler.go':HANDLER,'query.go':helper})
    assert not found


def test_explicit_scope_does_not_read_unrequested_helper(tmp_path):
    write(tmp_path,{'handler.go':HANDLER,'query.go':HELPER})
    context=ScanContext(str(tmp_path),ScanMode.FEATURE,('handler.go',))
    found,run=GoSQLScanner().scan(context,FindingNormalizer(tmp_path))
    assert not found and run.status=='PARTIAL'
    found,run=GoSQLScanner().scan(replace(context,context_files=('query.go',)),FindingNormalizer(tmp_path))
    assert len(found)==1 and found[0].file_path=='handler.go'


def test_changed_source_invalidates_evidence(tmp_path,monkeypatch):
    from security_runtime.flow_core import Analysis
    monkeypatch.setattr(Analysis,'stable',lambda self:False)
    found,run=scan(tmp_path,{'handler.go':HANDLER,'query.go':HELPER})
    assert not found and run.status=='PARTIAL'


def test_traversal_and_symlinks_fail_closed(tmp_path):
    a=GoAnalysis(tmp_path,('../outside.go',)).run()
    assert not a.parsed and any(r=='UNSAFE_CONTEXT_PATH' for _,r in a.gaps)


def test_provider_is_separate_and_quick_mode_stays_lightweight(tmp_path):
    from security_runtime.scanners import ScannerRegistry
    assert any(s.name=='native-go-sql' for s in ScannerRegistry().adapters)
    assert not GoSQLScanner().supports(None,ScanContext(str(tmp_path),ScanMode.QUICK,('app.go',)))
    assert len(rule_pack().catalog)==1
