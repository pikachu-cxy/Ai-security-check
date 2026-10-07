"""Capability ownership, semantic identities, occurrence proof and real corpus."""
import copy
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
from unittest.mock import patch

import pytest

from security_runtime.rulepacks import RulePackManager, BundledRulePackProvider
from security_runtime.rule_program import validate_manifest, annotate, aggregate
from security_runtime.rule_ground_truth import load_corpus, evaluate, run_corpus
from security_runtime.rule_coverage import plan_rules
from security_runtime.findings import FindingNormalizer
from security_runtime.equivalence import equivalence_key
from security_runtime.hook_runtime import family_multiset, family_delta, covered
from security_runtime.models import ScannerRun
from security_runtime.remediation_policy import RemediationPolicy

ROOT=Path(__file__).resolve().parents[1]
PACK=RulePackManager().resolve()
CAPABILITIES=PACK.program.capabilities


@pytest.mark.parametrize('bad', ['schema','duplicate','maturity','engine','ownership','missing-rule',
    'foreign-language','experimental-default','auto-fix','profile-mix','evidence','legacy-default','secret-ownership'])
def test_manifest_fails_closed(bad):
    data=json.loads((PACK.path/'capabilities.json').read_text(encoding='utf-8'))
    if bad=='schema': data['unknown']=True
    elif bad=='duplicate': data['capabilities'].append(data['capabilities'][0])
    elif bad=='maturity': data['capabilities'][0]['maturity']='BETA'
    elif bad=='engine': data['capabilities'][0]['scanner_engine']='unknown'
    elif bad=='ownership': data['capabilities'][2]['underlying_rule_ids'].append('ai-security.java.trust-all-hostname')
    elif bad=='missing-rule': data['capabilities'][2]['underlying_rule_ids'].append('ai-security.java.missing')
    elif bad=='foreign-language': data['capabilities'][2]['language']='python'
    elif bad=='experimental-default': data['capabilities'][2]['maturity']='EXPERIMENTAL'
    elif bad=='auto-fix': data['capabilities'][2]['auto_fix_eligible']=True
    elif bad=='profile-mix': data['profiles']['java_core_pack_v1'].append('JAVA_SQL_INJECTION')
    elif bad=='evidence': data['capabilities'][2]['evidence_contract']={}
    elif bad=='legacy-default': data['legacy_rules'][0]['default_enabled']=True
    else: data['capabilities'][1]['underlying_rule_ids']=['ai-security.secret.replacement']
    with pytest.raises(ValueError): validate_manifest(data,PACK.catalog)


def test_manifest_version_deterministic_mapping_and_safe_defaults():
    assert len(CAPABILITIES)==10
    assert sum(c.maturity=='CORE' for c in CAPABILITIES)==2
    assert sum(c.maturity=='VALIDATED' for c in CAPABILITIES)==8
    assert [c.capability_id for c in CAPABILITIES if c.auto_fix_eligible]==['JAVA_TLS_HOSTNAME_VERIFICATION_DISABLED']
    assert PACK.program.family_rules('capability:JAVA_SSRF')==PACK.program.capability('ai-security.java.url-connection').underlying_rule_ids
    assert all(not r['default_enabled'] for r in PACK.program.legacy_rules if r['maturity']=='EXPERIMENTAL')
    assert RulePackManager().resolve().checksum==PACK.checksum


def finding(tmp_path,rid,line=10):
    capability=PACK.program.capability(rid)
    row=FindingNormalizer(tmp_path).make(scanner='semgrep',rule_id=rid,category=capability.category,
        title='underlying variant',description='candidate',severity='HIGH',confidence='HIGH',file_path='A.java',line=line)
    record=next(r for r in PACK.catalog if r.rule_id==rid)
    annotate(row,capability,PACK.program.version,record)
    row.technical_details.update(engine='semgrep',rule_version=record.rule_version)
    row.equivalence_key=equivalence_key(row)
    return row


def test_framework_variants_share_family_but_not_occurrences(tmp_path):
    a=finding(tmp_path,'ai-security.java.jdbc-statement')
    b=finding(tmp_path,'ai-security.java.spring-jdbc',20)
    assert a.technical_details['rule_id']!=b.technical_details['rule_id']
    assert a.equivalence_key==b.equivalence_key
    plan=plan_rules(PACK,['A.java']);run=ScannerRun('semgrep','1.178.0','SUCCESS',1,provider='semgrep')
    families=family_multiset([a,b],[run],{'semgrep':plan})
    family=next(iter(families.values()))
    assert len(families)==1 and family['count']==2
    assert family['rule_id']=='capability:JAVA_SQL_INJECTION'
    # Only one framework rule executing never proves the combined family absent.
    plan.observe({'paths':{'scanned':['A.java']},'time':{'rules':[a.technical_details['rule_id']]}},('A.java',))
    assert not covered(family,[run],{'semgrep':plan})
    plan.confirmed_rules={r.rule_id for r in plan.rules}
    assert covered(family,[run],{'semgrep':plan})
    remaining=family_multiset([b],[run],{'semgrep':plan})
    current,delta=family_delta(families,remaining,lambda f:covered(f,[run],{'semgrep':plan}))
    assert delta['resolved']==0 and delta['removed_occurrences']==1 and next(iter(current.values()))['count']==1
    _,delta=family_delta(current,{},lambda f:covered(f,[run],{'semgrep':plan}))
    assert delta['resolved']==1


def test_tls_historical_eq_v1_identity_and_rule_bytes_unchanged(tmp_path):
    rid='ai-security.java.trust-all-hostname'
    new=finding(tmp_path,rid)
    old=copy.deepcopy(new)
    for k in ('capability_id','capability_maturity','capability_program_version','capability_family_anchor','auto_fix_eligible','detection_evidence'):
        old.technical_details.pop(k,None)
    assert equivalence_key(old)==equivalence_key(new)
    # Existing R0 snapshot protects the actual formerly verified rule.
    before=ROOT/'.security-runtime/r0-before/src/security_runtime/rules/java/trust-all-hostname.yml'
    if before.is_file(): assert before.read_bytes()==(PACK.path/'java/trust-all-hostname.yml').read_bytes()


def test_read_write_overlap_keeps_primary_and_related_evidence(tmp_path):
    generic=finding(tmp_path,'ai-security.java.file-access')
    read=finding(tmp_path,'ai-security.java.arbitrary-file-read')
    other=finding(tmp_path,'ai-security.java.file-access',20)
    result=aggregate([generic,read,other])
    assert result==[read,other]
    assert read.technical_details['related_capabilities']==['JAVA_PATH_TRAVERSAL']
    assert read.technical_details['supporting_rule_ids']==['ai-security.java.file-access']


def test_secret_mapping_never_collapses_detector_proof_or_leaks_raw(tmp_path):
    from security_runtime.scanners import GitleaksAdapter
    raw='SYNTHETIC_SECRET_CANARY_NEVER_EXPORT'
    rows=GitleaksAdapter().normalize([{'RuleID':rid,'File':'A.java','StartLine':n,'Secret':raw,'Match':raw} for n,rid in [(1,'github-pat'),(2,'generic-api-key')]],FindingNormalizer(tmp_path))
    assert all(r.technical_details['capability_id']=='HARDCODED_SECRET' for r in rows)
    assert rows[0].equivalence_key!=rows[1].equivalence_key
    assert raw not in json.dumps([asdict(r) for r in rows])
    with patch('security_runtime.scanners.RulePackManager.resolve',side_effect=ValueError('Bad SAST metadata')):
        assert GitleaksAdapter().normalize([{'RuleID':'github-pat','File':'A.java','StartLine':1}],FindingNormalizer(tmp_path))


@pytest.mark.parametrize('capability',CAPABILITIES,ids=lambda c:c.capability_id)
def test_core_not_automatic_authorization(capability):
    for rid in capability.underlying_rule_ids:
        decision=RemediationPolicy().decide(family='test',rule=rid,priority='ACTIONABLE',
            category='secret' if capability.scanner_engine=='gitleaks' else 'code',coverage=True,deterministic=True)
        assert (decision.action=='AUTO_FIX')==capability.auto_fix_eligible


def test_program_change_invalidates_pack_cache_and_does_not_reuse_proof(tmp_path):
    path=tmp_path/'rules';shutil.copytree(PACK.path,path)
    manager=RulePackManager(BundledRulePackProvider(path))
    first=manager.resolve();second=manager.resolve()
    assert manager.cache_hit and first.checksum==second.checksum
    data=json.loads((path/'capabilities.json').read_text(encoding='utf-8'))
    data['version']='1.0.1';(path/'capabilities.json').write_text(json.dumps(data),encoding='utf-8')
    changed=manager.resolve()
    assert not manager.cache_hit and changed.checksum!=first.checksum
    plan=plan_rules(changed,['A.java'])
    assert not plan.confirmed_rules and not plan.scanned_files


def test_zero_applicable_language_and_maturity_planning():
    assert not plan_rules(PACK,['main.js','README.md']).rules
    python=plan_rules(PACK,['main.py'])
    assert all(r.language=='python' for r in python.rules) and len(python.rules)==2
    java=plan_rules(PACK,['A.java','other.js'])
    assert java.files==('A.java',)
    assert java.coverage()['applicable_capabilities']==9
    assert not any(r.rule_id.endswith('weak-digest') for r in java.rules)


def test_mapper_only_framework_scope_without_repository_discovery():
    plan=plan_rules(PACK,['mapper.xml','uncovered.js','README.md'])
    assert plan.files==('mapper.xml',)
    assert [r.rule_id for r in plan.rules]==['ai-security.java.mybatis-xml']
    coverage=plan.coverage()
    assert coverage['applicable_capabilities']==1
    assert coverage['capabilities'][0]['frameworks']
    assert 'ENGINE_TYPED_PATTERNS' in coverage['capabilities'][0]['framework_applicability']


@pytest.fixture(scope='module')
def real_corpus():
    # Prepared engines failing is a failure. An environment without the
    # optional engines is reported separately, never replaced with fake scans.
    from security_runtime.toolchain import ToolManager, ToolStatus
    manager=ToolManager()
    if any(manager.resolve(engine).status!=ToolStatus.READY for engine in ('semgrep','gitleaks')):
        pytest.skip('Rule Program corpus requires prepared offline Semgrep and Gitleaks')
    return run_corpus(ROOT/'tests/rule_program/corpus.json')


@pytest.mark.parametrize('capability',CAPABILITIES,ids=lambda c:c.capability_id)
def test_real_capability_ground_truth(real_corpus,capability):
    row=real_corpus['per_capability'][capability.capability_id]
    assert row['TP']>0 and row['TN']>0 and row['FP']==row['FN']==0
    assert real_corpus['kind']=='SYNTHETIC' and not real_corpus['independent_human_ground_truth']
    assert all(r['status']=='SUCCESS' for r in real_corpus['scanner_runs'])


def test_ground_truth_counts_wrong_detection_not_exit_status():
    corpus={'kind':'SYNTHETIC','independent_human_ground_truth':False,'cases':[
        {'case_id':'risk','file':'A.java','expected_capability':'JAVA_SSRF','expected_occurrences':2,'variant':'JDK'},
        {'case_id':'safe','file':'B.java','expected_capability':'JAVA_SSRF','expected_occurrences':0,'variant':'JDK'}]}
    finding={'file_path':'B.java','line_start':1,'line_end':1,'technical_details':{'capability_id':'JAVA_SSRF','rule_id':'ssrf'}}
    report=evaluate(corpus,[finding])
    assert report['totals']=={'TP':0,'TN':0,'FP':1,'FN':2} and report['quality_status']=='MISMATCH'


def test_structural_mybatis_evidence_does_not_claim_observed_taint(tmp_path):
    row=finding(tmp_path,'ai-security.java.mybatis-annotation')
    evidence=row.technical_details['detection_evidence']
    assert evidence['basis']=='STRUCTURAL_MATCH' and 'TRUST_NOT_ESTABLISHED' in evidence['source']
    assert evidence['exploitability']=='NOT_ESTABLISHED'
