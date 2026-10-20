import copy
import hashlib
import json
from dataclasses import asdict

import pytest

from security_runtime.findings import FindingNormalizer
from security_runtime.local_evidence import snapshot_fingerprint
from security_runtime.models import ScanResult,TargetProfile
from security_runtime.storage import SQLiteStore
from security_runtime.triage import TriageService
from security_runtime.triage_evidence import EvidenceBuilder


def sample(root, captured=True):
    path=root/'Demo.java'
    path.write_text('class Demo {\n void run(String cmd) {\n Runtime.getRuntime().exec(cmd);\n }\n}\n',encoding='utf-8')
    f=FindingNormalizer(root).make(scanner='semgrep',category='command-injection',title='Command',
        description='Synthetic',severity='HIGH',confidence='HIGH',file_path='Demo.java',line=3,rule_id='fixture.command')
    if captured: f.technical_details['evidence_locator']=snapshot_fingerprint(root,'Demo.java')
    result=ScanResult('scan','release',TargetProfile(str(root),files=['Demo.java']),'FULL',[f],[],
        'Candidates','REVIEW',1,coverage='FULL')
    store=SQLiteStore(root/'state/scans.db');store.save(result)
    return path,store,TriageService(store)


def claim(packet,verdict='LIKELY'):
    return dict(finding_id=packet['finding_id'],context_hash=packet['context_hash'],verdict=verdict,
        confidence='HIGH',exploitability='LIKELY',reason='Synthetic protocol claim, not human ground truth',
        attack_path='',evidence_refs=[dict(file=packet['file'],start_line=3,end_line=3,claim='local match')],
        preconditions_met=[],preconditions_unknown=[],recommended_action='Review')


def test_shared_reader_exact_legacy_stale_and_no_raw_changes(tmp_path):
    path,store,service=sample(tmp_path)
    raw=copy.deepcopy(store.get_scan('scan'))
    packet=service.prepare('scan')['packets'][0]
    assert packet['local_evidence']['evidence_status']=='EXACT'
    service.submit('scan',[claim(packet)])
    path.write_text(path.read_text()+'// outside excerpt change\n')
    newer=service.prepare('scan')['packets'][0]
    assert newer['local_evidence']['evidence_status']=='STALE'
    assert service.view('scan')['findings'][0]['triage_status']=='STALE'
    with pytest.raises(ValueError,match='stale'): service.submit('scan',[claim(packet)])
    outcome=service.submit('scan',[claim(newer)])
    assert outcome['records'][0]['verdict']=='NEEDS_REVIEW'
    assert outcome['records'][0]['priority']=='REVIEW'
    assert store.get_scan('scan')==raw


def test_legacy_is_current_context_not_exact(tmp_path):
    _,_,service=sample(tmp_path,captured=False)
    local=service.prepare('scan')['packets'][0]['local_evidence']
    assert local['evidence_status']=='UNAVAILABLE' and not local['original_match_verified']
    assert local['reason']=='SNAPSHOT_FINGERPRINT_MISSING'


@pytest.mark.parametrize('raw,reason',[(b'\xffbad','DECODE_FAILED_UTF8'),(b'\0binary','BINARY_FILE'),
    (b'x'*1_000_001,'FILE_TOO_LARGE'),(None,'FILE_MISSING')],ids=['encoding','binary','oversized','deleted'])
def test_reader_failure_reasons_exposed_without_source(tmp_path,raw,reason):
    path,_,service=sample(tmp_path)
    if raw is None: path.unlink()
    else: path.write_bytes(raw)
    data=service.prepare('scan')
    assert not data['packets'] and data['errors'][0]['reason']==reason


def test_full_file_multiline_scrub_and_public_literals(tmp_path):
    path,store,service=sample(tmp_path)
    synthetic='SyntheticMultilineCredentialOnly'
    path.write_text('class Demo {\n String privateKey = """\n'+synthetic+'\n""";\n void run(){ MessageDigest.getInstance("MD5"); }\n}\n')
    packet=service.prepare('scan')['packets'][0]
    text=json.dumps(packet)
    assert synthetic not in text and 'MD5' in text and 'REDACTED' in text
    assert hashlib.sha256(path.read_bytes()).hexdigest() not in text


def test_compact_submit_preserves_results_access_and_separation(tmp_path):
    _,store,service=sample(tmp_path)
    packet=service.prepare('scan')['packets'][0]
    legacy=service.submit('scan',[claim(packet)])
    compact=service.submit('scan',[claim(packet)],compact=True)
    assert compact['accepted']==1 and compact['results_access']['tool']=='get_triage'
    assert 'view' not in compact and 'records' not in compact
    assert compact['quality_reviews_changed'] is False
    assert len(json.dumps(compact))<len(json.dumps(legacy))/2


def test_secret_word_collision_cannot_corrupt_evidence_locators(tmp_path):
    path,store,service=sample(tmp_path)
    target=tmp_path/'samples/Demo.java';target.parent.mkdir();path.rename(target)
    secret=tmp_path/'config.properties';secret.write_text('api_key="sample"\n')
    scan=store.get_scan('scan')
    scan['target_profile']['files']=['samples/Demo.java','config.properties']
    scan['findings'][0]['file_path']='samples/Demo.java'
    scan['findings'].append(asdict(FindingNormalizer(tmp_path).make(scanner='gitleaks',category='secret',
        title='Synthetic',description='Synthetic',severity='HIGH',confidence='HIGH',
        file_path='config.properties',line=1,evidence='[REDACTED_SECRET]')))
    builder=EvidenceBuilder(scan,revision_key=b's'*32)
    packet=builder.build(scan['findings'][0])
    assert packet['file']=='samples/Demo.java'
    assert all(e['file']=='samples/Demo.java' for e in packet['context'])
    assert builder.safe_text('the value is sample')=='the value is [REDACTED_SECRET]'
    assert '[REDACTED_SECRET]s/' not in json.dumps(packet)


def test_public_constant_not_credential_allowlist(tmp_path):
    from security_runtime.local_evidence import safe_source
    lines=safe_source('MessageDigest.getInstance("MD5");\nlogin("MD5");\npassword = "TLS";\n')
    assert '"MD5"' in lines[0]
    assert 'MD5' in lines[1] and 'TLS' not in lines[2]
