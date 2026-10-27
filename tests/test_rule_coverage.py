"""Execution planning and coverage must reflect rules, targets and engine evidence."""
from dataclasses import replace
from pathlib import Path
import json
from unittest.mock import patch
import yaml
import pytest

from security_runtime.rulepacks import RulePackManager, FIRST_PARTY_RULE_PACK
from security_runtime.rule_coverage import plan_rules
from security_runtime.scanners import OpenGrepAdapter, ScannerRegistry
from security_runtime.models import ScanContext, ScanMode
from security_runtime.runtime import SecurityRuntime
from security_runtime.storage import SQLiteStore
from security_runtime.processes import ProcessResult
from security_runtime.toolchain import ResolvedTool, ToolStatus
from security_runtime.cli import render
from security_runtime.mcp_server import _agent_result


def custom_pack(tmp_path,languages):
    folder=tmp_path/'custom-rules';folder.mkdir()
    definitions=[{'id':'test.'+lang,'languages':[lang],'severity':'WARNING','message':'test','pattern':'danger(...)'} for lang in languages]
    (folder/'rules.yml').write_text(yaml.safe_dump({'rules':definitions}),encoding='utf-8')
    return folder


def run_fixture(tmp_path,languages,*,status='SUCCESS',evidence=True):
    import subprocess
    rules = custom_pack(tmp_path, languages)
    tmp_path = tmp_path / 'project'
    tmp_path.mkdir()
    subprocess.run(['git', 'init', str(tmp_path)], check=True, capture_output=True)
    (tmp_path/'App.java').write_text('class App {}')
    (tmp_path/'app.js').write_text('const value=1;')
    adapter=OpenGrepAdapter()
    calls=[]
    def execute(args,cwd,timeout):
        scope=args[args.index('--no-git-ignore')+1:];calls.append(scope)
        config=yaml.safe_load(Path(args[args.index('--config')+1]).read_text(encoding='utf-8'))
        payload={'results':[],'errors':[],'paths':{'scanned':scope},'time':{'rules':[r['id'] for r in config['rules']]}}
        if not evidence: payload.pop('time')
        return ProcessResult(0,json.dumps(payload),'',1)
    manager=adapter.tool_manager
    binary=tmp_path/'.security-runtime/mock-engine/runtime/Scripts/opengrep'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'Synthetic executable identity; never executed')
    tool=ResolvedTool('opengrep','1.32.0',str(binary),None,ToolStatus.READY if status=='SUCCESS' else ToolStatus.MISSING)
    with patch.object(manager,'ensure',return_value=tool) as ensure,patch('security_runtime.scanners._execute',side_effect=execute):
        runtime=SecurityRuntime(ScannerRegistry([adapter]),SQLiteStore(tmp_path/'.security-runtime/state.db'))
        result=runtime.scan(tmp_path,'release',rules_path=str(rules))
    return result,calls,ensure.call_count


def test_zero_rules_never_prepare_or_invoke_opengrep(tmp_path):
    result,calls,prepared=run_fixture(tmp_path,['python'])
    assert calls==[] and prepared==0
    assert result.capability_results['CODE_SAST']=='NOT_COVERED'
    assert result.scanner_runs[0].status=='NOT_COVERED'
    assert result.execution_state=='NOT_COVERED'
    assert result.rule_coverage['total_selected']==result.rule_coverage['total_executed']==0
    assert result.release_status!='SAFE'


def test_mixed_scope_only_java_rules_and_files(tmp_path):
    result,calls,prepared=run_fixture(tmp_path,['java'])
    assert calls==[['App.java']] and prepared==1
    assert result.capability_results['CODE_SAST']=='PARTIAL'
    assert result.rule_coverage['per_language']['java']['status']=='EXECUTED'
    assert result.rule_coverage['per_language']['javascript']['status']=='NOT_COVERED'
    assert result.rule_coverage['total_selected']==result.rule_coverage['total_executed']==1


def test_both_languages_covered_receive_both_scopes(tmp_path):
    result,calls,_=run_fixture(tmp_path,['java','javascript'])
    assert set(calls[0])=={'App.java','app.js'}
    assert result.capability_results['CODE_SAST']=='EXECUTED'
    assert result.rule_coverage['total_selected']==result.rule_coverage['total_executed']==2


def test_engine_exit_zero_without_rule_evidence_not_executed(tmp_path):
    result,_,_=run_fixture(tmp_path,['java','javascript'],evidence=False)
    assert result.capability_results['CODE_SAST']=='FAILED'
    assert result.rule_coverage['total_executed']==0


def test_engine_unavailable_differs_from_no_rules(tmp_path):
    result,calls,prepared=run_fixture(tmp_path,['java','javascript'],status='UNAVAILABLE')
    assert calls==[] and prepared==1
    assert result.capability_results['CODE_SAST']=='UNAVAILABLE'


def test_human_json_mcp_same_coverage(tmp_path):
    result,_,_=run_fixture(tmp_path,['java'])
    compact={key:value for key,value in result.rule_coverage.items() if key!='scope_files'}
    assert compact==_agent_result(result)['rule_coverage']
    text=render(result)
    assert '适用规则：1' in text and '执行规则：1' in text and 'javascript：未覆盖' in text


def test_catalog_actual_count_and_selection():
    pack = RulePackManager().resolve()
    assert len(pack.catalog) == 2007
    plan = plan_rules(pack, ['App.java', 'app.js', 'Mapper.xml', 'README.md', 'config.yml'])
    assert plan.rules and set(plan.files) == {'App.java', 'app.js', 'Mapper.xml', 'README.md', 'config.yml'}
    assert plan.coverage()['per_language']['javascript']['selected_rules'] > 0


def test_duplicate_user_ids_rejected(tmp_path):
    rules = custom_pack(tmp_path, ['python', 'python'])
    with pytest.raises(ValueError, match='Duplicate'):
        RulePackManager().resolve(user_path=rules)


def test_invalid_language_rejected(tmp_path):
    rules=custom_pack(tmp_path,['not-a-language'])
    with pytest.raises(ValueError,match='language'):
        RulePackManager().resolve(user_path=rules)


@pytest.mark.parametrize('status',['SUCCESS','FAILED','TIMEOUT','UNAVAILABLE'])
def test_language_failure_evidence_and_counts(status):
    pack=RulePackManager().resolve()
    plan=plan_rules(pack,['App.java'])
    if status=='SUCCESS':
        plan.observe({'time':{'rules':[r.rule_id for r in plan.rules]},'paths':{'scanned':['App.java']}},('App.java',))
    row=plan.coverage(status)['per_language']['java']
    assert row['status']=={'SUCCESS':'EXECUTED','FAILED':'FAILED','TIMEOUT':'FAILED','UNAVAILABLE':'UNAVAILABLE'}[status]
    assert row['executed_rules'] == (row['selected_rules'] if status == 'SUCCESS' else 0)


def test_parse_error_and_skipped_file_lower_coverage():
    plan=plan_rules(RulePackManager().resolve(),['App.java','Broken.java'])
    plan.observe({'time':{'rules':[r.rule_id for r in plan.rules]},'paths':{'scanned':['App.java','Broken.java']},'errors':[{'path':'Broken.java'}]},plan.files)
    assert plan.coverage('SUCCESS')['status']=='PARTIAL'
    assert plan.coverage('SUCCESS')['per_language']['java']['scanned_files']==1


def test_experimental_rules_excluded_from_default_pack():
    pack=RulePackManager().resolve()
    catalog=tuple(replace(r,maturity='EXPERIMENTAL') for r in pack.catalog)
    assert not plan_rules(replace(pack,catalog=catalog),['App.java']).rules


def test_upstream_catalog_has_source_coordinates():
    pack = RulePackManager().resolve()
    assert all((pack.path / rule.path).is_file() and rule.provenance['original_rule_id'] for rule in pack.catalog)
