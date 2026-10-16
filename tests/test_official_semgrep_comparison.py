"""Check fair public-rule selection without downloading/running external rules."""
import importlib.util
from pathlib import Path
import sys

import yaml


def evaluator():
    scripts=Path(__file__).resolve().parents[1]/'scripts'
    sys.path.insert(0,str(scripts))
    try:
        spec=importlib.util.spec_from_file_location('official_comparison',scripts/'compare_official_semgrep.py')
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally: sys.path.pop(0)


def rule(identifier,cwe,lang='python'):
    return {'id':identifier,'languages':[lang],'message':'fixture','severity':'WARNING',
            'pattern':'danger($X)','metadata':{'cwe':cwe,'license':'TEST_FIXTURE'}}


def test_all_matching_rules_are_selected_with_unique_ids(tmp_path):
    for folder in ['python/a','python/b']: (tmp_path/folder).mkdir(parents=True)
    (tmp_path/'python/a/one.yaml').write_text(yaml.safe_dump({'rules':[
        rule('same','CWE-22: traversal'),rule('other','CWE-89: SQL'),rule('unrelated','CWE-222: other')]}))
    (tmp_path/'python/b/two.yml').write_text(yaml.safe_dump({'rules':[rule('same',['CWE-73: path'])]}))
    definitions,inventory,categories=evaluator().select_rules(tmp_path,'python')
    assert len(definitions)==len(inventory)==len(categories)==3
    assert all(item['metadata']['license']=='TEST_FIXTURE' for item in inventory)
    assert sum('pathtraver' in groups for groups in categories.values())==2


def test_registry_selection_preserves_issued_ids_and_language_scope(tmp_path):
    snapshot=tmp_path/'default.json'
    snapshot.write_text(yaml.safe_dump({'rules':[rule('python.id','CWE-22: path'),
        rule('java.id','CWE-89: SQL','java')],'missed':10}))
    definitions,inventory,categories=evaluator().select_rules(tmp_path,'python',snapshot)
    assert [r['id'] for r in definitions]==['python.id']
    assert categories=={'python.id':{'pathtraver'}}


def test_missing_execution_proof_cannot_be_scored_as_clean():
    module=evaluator()
    rules=[rule('python.id','CWE-22: path'),rule('java.id','CWE-89: SQL','java')]
    assert module.execution_observed({'time':{'rules':['python.id']}},rules,['entry.py'])
    assert not module.execution_observed({'time':{'rules':['java.id']}},rules,['entry.py'])
    assert not module.execution_observed({},rules,['entry.py'])
