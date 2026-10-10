import json
import os
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from security_runtime.equivalence import equivalence_key
from security_runtime.findings import FindingNormalizer
from security_runtime.hook_runtime import HookCoordinator, capture_snapshot, covered, family_delta, family_multiset, validate_state
from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScanResult, ScannerRun, TargetProfile
from security_runtime.verification_policy import scanner_process_observed, offline_scanning


@pytest.fixture
def repo(tmp_path):
    root = tmp_path/'project'; root.mkdir()
    subprocess.run(['git','init',str(root)],check=True,capture_output=True)
    subprocess.run(['git','-C',str(root),'config','user.email','fixture@example.invalid'],check=True)
    subprocess.run(['git','-C',str(root),'config','user.name','Fixture'],check=True)
    (root/'A.java').write_text('safe\n')
    subprocess.run(['git','-C',str(root),'add','.'],check=True)
    subprocess.run(['git','-C',str(root),'commit','-m','fixture'],check=True,capture_output=True)
    return root


def row(root,line=1,rule='test.rule',category='code',file='A.java',evidence='UNTRUSTED_CODE'):
    item = FindingNormalizer(root).make(category=category,title='Test',description='Test fixture',confidence='HIGH',severity='HIGH',file_path=file,
        line=line,evidence=evidence,scanner='semgrep')
    item.technical_details = {'rule_id':rule,'engine':'semgrep','rule_version':'0.1'}
    item.equivalence_key = equivalence_key(item)
    return item


class FakeRuntime:
    def __init__(self,findings=(),status='SUCCESS',complete=True):
        self.findings=list(findings); self.calls=[];self.status=status;self.complete=complete
    def scan(self,root,mode,**kwargs):
        assert mode == 'quick' and offline_scanning()
        self.calls.append(kwargs['_hook_scope'])
        scanner_process_observed()
        run = ScannerRun('semgrep','1.178.0',self.status,1,provider='semgrep')
        rule_ids={f.technical_details['rule_id'] for f in self.findings} | {'test.rule'}
        plan = SimpleNamespace(rules=[SimpleNamespace(rule_id=r,rule_version='0.1') for r in rule_ids],
            pack=SimpleNamespace(checksum='a'*64), confirmed_rules=rule_ids if self.complete else set(),
            scanned_files=set(kwargs['_hook_scope']),errored_files=set(),unscoped_error=False)
        kwargs['_hook_observer'](self.findings,[run],{'semgrep':plan})
        return ScanResult('scan-'+str(len(self.calls)),mode,TargetProfile(str(root),files=list(kwargs['_hook_scope'])),
            'COMPLETED' if self.status=='SUCCESS' else 'PARTIAL',self.findings,[run],'advisory','BLOCKED',1,
            capability_results={'CODE_SAST':'EXECUTED' if self.status=='SUCCESS' else 'FAILED'},
            execution_state='EXECUTED' if self.status=='SUCCESS' else 'FAILED')


def coordinator(tmp_path,runtime,**kwargs):
    return HookCoordinator(runtime,HookStateStore(tmp_path/'state'),**kwargs)


def dirty(repo,text='changed\n'):
    (repo/'A.java').write_text(text)


def test_no_session_first_edit_baselines_not_new(repo,tmp_path):
    dirty(repo)
    runtime=FakeRuntime([row(repo)])
    c=coordinator(tmp_path,runtime)
    result=c.handle('FILE_CHANGED',repo,'codex')
    assert result['status']=='BASELINE_ESTABLISHED' and result['delta']['new']==0
    assert result['execution']['scanner_run'] and len(runtime.calls)==1


def test_session_clean_safe_then_new_move_multiplicity_and_resolve(repo,tmp_path):
    runtime=FakeRuntime();c=coordinator(tmp_path,runtime,cooldown_ms=0)
    assert c.handle('SESSION_START',repo,'codex','s')['status']=='BASELINE_ESTABLISHED'
    dirty(repo,'safe edit\n')
    assert c.handle('FILE_CHANGED',repo,'codex','s')['delta']['new']==0
    runtime.findings=[row(repo,100)]; dirty(repo,'danger\n')
    assert c.handle('FILE_CHANGED',repo,'codex','s')['delta']['new']==1
    runtime.findings=[row(repo,110)];dirty(repo,'\n'*10+'danger\n')
    moved=c.handle('FILE_CHANGED',repo,'codex','s')
    assert moved['delta']['persisting']==1 and moved['delta']['new']==moved['delta']['resolved']==0
    runtime.findings.append(row(repo,300));dirty(repo,'two dangers\n')
    added=c.handle('FILE_CHANGED',repo,'codex','s')
    assert added['delta']['additional_occurrences']==1 and added['delta']['persisting']==1
    runtime.findings=[row(repo,300)];dirty(repo,'one danger\n')
    removed=c.handle('FILE_CHANGED',repo,'codex','s')
    assert removed['delta']['removed_occurrences']==1 and removed['delta']['resolved']==0
    runtime.findings=[];dirty(repo,'safe\n')  # reverting to HEAD still rechecks former dirty file
    fixed=c.handle('AGENT_STOP',repo,'codex','s')
    assert fixed['delta']['resolved']==1 and runtime.calls[-1]==('A.java',)
    reused=c.handle('AGENT_STOP',repo,'codex','s')
    assert reused['status']=='REUSED_LAST_RESULT' and not reused['execution']['scanner_run']


def test_dedupe_before_cooldown_and_stop_converges(repo,tmp_path,monkeypatch):
    dirty(repo);runtime=FakeRuntime(); now=[1000]
    c=coordinator(tmp_path,runtime,clock=lambda:now[0])
    c.handle('FILE_CHANGED',repo,'codex')
    import security_runtime.hook_runtime as module
    # POSIX subprocess.wait itself sleeps while polling a child with timeout.
    # Guard only the coordinator, without patching the stdlib's shared module.
    monkeypatch.setattr(module,'time',SimpleNamespace(time=time.time,monotonic=time.monotonic,
        sleep=lambda _:pytest.fail('Debounce must not sleep')))
    assert c.handle('FILE_CHANGED',repo,'codex')['status']=='NO_CHANGE'
    dirty(repo,'new change\n')
    assert c.handle('FILE_CHANGED',repo,'codex')['status']=='DEBOUNCED'
    assert len(runtime.calls)==1
    assert c.handle('AGENT_STOP',repo,'codex')['status']=='SCANNED'
    assert len(runtime.calls)==2


@pytest.mark.parametrize('stage',['unstaged','staged','untracked','same-file','deleted','rename'])
def test_snapshot_changes_for_all_git_mutations(repo,tmp_path,stage):
    store=HookStateStore(tmp_path/'state')
    with store.lock(repo):
        key=store.key(repo)
        original,_=capture_snapshot(repo,key)
        if stage=='untracked':
            (repo/'new.java').write_text('new')
        elif stage=='deleted':
            (repo/'A.java').unlink()
        elif stage=='rename':
            (repo/'A.java').rename(repo/'B.java')
        else:
            dirty(repo,'change1')
            if stage=='staged':
                subprocess.run(['git','-C',str(repo),'add','A.java'],check=True)
            if stage=='same-file':
                original,_=capture_snapshot(repo,key);dirty(repo,'change2')
        current,files=capture_snapshot(repo,key)
        assert original!=current and files
        assert capture_snapshot(repo,key)[0]==current


def test_staging_same_working_content_changes_digest(repo,tmp_path):
    dirty(repo)
    a=capture_snapshot(repo,b'a'*32)[0]
    subprocess.run(['git','-C',str(repo),'add','A.java'],check=True)
    assert capture_snapshot(repo,b'a'*32)[0]!=a


@pytest.mark.parametrize('status,complete',[('FAILED',True),('UNAVAILABLE',True),('TIMEOUT',True),('SUCCESS',False)])
def test_failed_or_partial_cannot_resolve(repo,tmp_path,status,complete):
    dirty(repo);runtime=FakeRuntime([row(repo)]);c=coordinator(tmp_path,runtime,cooldown_ms=0)
    c.handle('SESSION_START',repo)
    runtime.findings=[];runtime.status=status;runtime.complete=complete;dirty(repo,'safe edit')
    result=c.handle('AGENT_STOP',repo)
    assert result['delta']['resolved']==0 and result['status']=='PARTIAL'
    assert result['delta']['families'][0]['status']=='UNCONFIRMED_ABSENCE'


def test_deletion_not_resolved_and_rename_is_independent(repo,tmp_path):
    dirty(repo);runtime=FakeRuntime([row(repo)]);c=coordinator(tmp_path,runtime,cooldown_ms=0)
    c.handle('SESSION_START',repo)
    (repo/'A.java').rename(repo/'B.java');runtime.findings=[row(repo,file='B.java')]
    result=c.handle('AGENT_STOP',repo)
    assert result['delta']['new']==1 and result['delta']['resolved']==0
    assert result['status']=='PARTIAL'


def test_secret_multiset_2_to_1_never_stores_value(repo,tmp_path,capsys):
    secret='fixture_private_credential_do_not_log'
    dirty(repo,secret)
    runtime=FakeRuntime([row(repo,1,category='secret',evidence=secret),row(repo,3,category='secret',evidence=secret)])
    c=coordinator(tmp_path,runtime,cooldown_ms=0);c.handle('SESSION_START',repo)
    runtime.findings=runtime.findings[:1];dirty(repo,secret+' changed')
    result=c.handle('AGENT_STOP',repo)
    assert result['delta']['removed_occurrences']==1 and result['delta']['resolved']==0
    assert result['delta']['families'][0]['status']=='PERSISTING'
    assert secret not in json.dumps(result)
    assert secret not in c.store.path(repo,'generic',None).read_text()
    assert hashlib_credential(secret) not in c.store.path(repo,'generic',None).read_text()
    assert secret not in capsys.readouterr().out


def hashlib_credential(value):
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()


def test_coordinates_change_same_count_not_exact_instance_identity(repo):
    old=family_multiset([row(repo,1),row(repo,3)],[],{})
    # Only successful scanner output is observed.
    assert not old
    runs=[ScannerRun('semgrep','1','SUCCESS',0)]
    old=family_multiset([row(repo,1),row(repo,3)],runs,{})
    new=family_multiset([row(repo,10),row(repo,30)],runs,{})
    _,delta=family_delta(old,new,lambda _:True)
    assert delta['persisting']==1 and not delta['new'] and not delta['resolved']
    assert delta['additional_occurrences']==delta['removed_occurrences']==0


def test_different_rule_same_historical_fingerprint_survives_hook_projection(repo):
    a,b=row(repo,1,'rule.a'),row(repo,1,'rule.b')
    assert a.fingerprint==b.fingerprint
    families=family_multiset([a,b], [ScannerRun('semgrep','1','SUCCESS',0)],{})
    assert len(families)==2


@pytest.mark.parametrize('corrupt',[b'not json',b'{' + b'x'*2_000_000,b'{"secret":"do_not_echo"}',b'[]'],ids=['invalid','oversized','unknown-secret-field','array'])
def test_corrupt_state_rebaselines_without_echo(repo,tmp_path,corrupt):
    c=coordinator(tmp_path,FakeRuntime());path=c.store.path(repo,'generic',None)
    path.parent.mkdir(parents=True);path.write_bytes(corrupt)
    result=c.handle('AGENT_STOP',repo)
    assert result['status']=='BASELINE_ESTABLISHED' and result['state_recovered']
    assert 'do_not_echo' not in json.dumps(result)
    validate_state(json.loads(path.read_text()))


def test_scope_host_session_workspace_separate(repo,tmp_path):
    dirty(repo);runtime=FakeRuntime([row(repo)]);c=coordinator(tmp_path,runtime,cooldown_ms=0)
    a=c.handle('FILE_CHANGED',repo,'codex','a');b=c.handle('FILE_CHANGED',repo,'codex','b')
    d=c.handle('FILE_CHANGED',repo,'cursor','a')
    assert all(r['status']=='BASELINE_ESTABLISHED' for r in (a,b,d))
    assert c.store.path(repo,'codex','a')!=c.store.path(repo,'cursor','a')


@pytest.mark.parametrize('nested', ['coordinates', 'proof', 'result', 'scanner', 'delta', 'delta-family'])
def test_corrupt_nested_container_rebaselines(repo,tmp_path,nested):
    dirty(repo)
    c=coordinator(tmp_path,FakeRuntime([row(repo)]))
    c.handle('SESSION_START',repo)
    path=c.store.path(repo,'generic',None)
    state=json.loads(path.read_text())
    family=next(iter(state['families'].values()))
    result=state['last_result']
    if nested=='coordinates': family['occurrences'][0]=['line_start','line_end']
    elif nested=='proof': family['proof']=list(family['proof'])
    elif nested=='result': state['last_result']=list(result)
    elif nested=='scanner': result['scanner_runs'][0]=list(result['scanner_runs'][0])
    elif nested=='delta': result['delta']=list(result['delta'])
    else: result['delta']['families']=[['equivalence_key','file_path','rule_id','category','status','previous_count','current_count','occurrence_delta','count_certainty']]
    path.write_text(json.dumps(state))
    recovered=c.handle('AGENT_STOP',repo)
    assert recovered['status']=='BASELINE_ESTABLISHED' and recovered['state_recovered']
    validate_state(json.loads(path.read_text()))


def test_edits_during_scan_do_not_commit_false_digest(repo,tmp_path):
    dirty(repo);runtime=FakeRuntime();original=runtime.scan
    def edit(*args,**kwargs):
        result=original(*args,**kwargs);dirty(repo,'raced');return result
    runtime.scan=edit;c=coordinator(tmp_path,runtime)
    result=c.handle('FILE_CHANGED',repo)
    assert result['status']=='PARTIAL' and result['coverage']=='UNKNOWN'
    assert not c.store.path(repo,'generic',None).exists()


def test_busy_cross_process_and_crash_releases_lock(repo,tmp_path):
    state=tmp_path/'state';store=HookStateStore(state)
    code='from pathlib import Path; from security_runtime.hook_state import HookStateStore; import sys,time; s=HookStateStore(Path(sys.argv[1]));\nwith s.lock(Path(sys.argv[2])) as locked:\n print(locked,flush=True); time.sleep(30)'
    import sys
    child=subprocess.Popen([sys.executable,'-c',code,str(state),str(repo)],stdout=subprocess.PIPE,text=True)
    try:
        assert child.stdout.readline().strip()=='True'
        assert HookCoordinator(FakeRuntime(),store).handle('FILE_CHANGED',repo)['status']=='BUSY'
        child.kill();child.wait(timeout=10)
        # A lock file left behind by a dead process cannot block another run.
        assert HookCoordinator(FakeRuntime(),store).handle('AGENT_STOP',repo)['status']=='BASELINE_ESTABLISHED'
    finally:
        if child.poll() is None:
            child.kill();child.wait()


@pytest.mark.parametrize('name',['../outside.java','/outside.java','C:/outside.java','bad\n.java'])
def test_traversal_or_control_git_names_rejected(repo,name,monkeypatch):
    import security_runtime.hook_runtime as module
    monkeypatch.setattr(module,'_git',lambda *args:name.encode()+b'\0')
    with pytest.raises(ValueError):
        capture_snapshot(repo,b'a'*32)


def test_shell_metachar_filename_never_executed(repo,tmp_path):
    name='evil&echo PWN.java' if os.name=='nt' else 'evil;touch PWN.java'
    (repo/name).write_text('safe')
    digest,files=capture_snapshot(repo,b'a'*32)
    assert name in files and digest and not (repo/'PWN.java').exists()


def test_symlink_not_read(repo,tmp_path):
    outside=tmp_path/'private';outside.write_text('private secret')
    link=repo/'link.java'
    try: link.symlink_to(outside)
    except OSError: pytest.skip('OS does not permit symlink fixture')
    with pytest.raises(ValueError):capture_snapshot(repo,b'a'*32)


def test_hook_state_link_rejected(repo,tmp_path):
    link=tmp_path/'linked';target=tmp_path/'external';target.mkdir()
    try:link.symlink_to(target,target_is_directory=True)
    except OSError:pytest.skip('OS does not permit symlink fixture')
    with pytest.raises(ValueError):HookCoordinator(FakeRuntime(),HookStateStore(link)).handle('FILE_CHANGED',repo)


def test_new_git_repository_without_head(tmp_path):
    root=tmp_path/'unborn';root.mkdir()
    subprocess.run(['git','init',str(root)],check=True,capture_output=True)
    result=coordinator(tmp_path,FakeRuntime()).handle('SESSION_START',root)
    assert result['status']=='BASELINE_ESTABLISHED' and not result['execution']['scanner_run']


def test_duplicate_failed_baseline_keeps_failure_visibility(repo,tmp_path):
    dirty(repo);runtime=FakeRuntime(status='FAILED');c=coordinator(tmp_path,runtime)
    result=c.handle('SESSION_START',repo)
    assert result['status']=='BASELINE_ESTABLISHED' and result['last_check_status']=='FAILED'
    reused=c.handle('AGENT_STOP',repo)
    assert reused['status']=='REUSED_LAST_RESULT' and reused['last_check_status']=='FAILED'
    assert reused['capabilities']['CODE_SAST']=='FAILED' and len(runtime.calls)==1


def test_workspace_lock_does_not_block_other_workspace(repo,tmp_path):
    other=tmp_path/'other';other.mkdir();subprocess.run(['git','init',str(other)],check=True,capture_output=True)
    store=HookStateStore(tmp_path/'state')
    with store.lock(repo) as locked:
        assert locked
        assert HookCoordinator(FakeRuntime(),store).handle('SESSION_START',other)['status']=='BASELINE_ESTABLISHED'


def test_concurrent_edit_and_stop_single_flight_then_stop_reuses(repo,tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    dirty(repo);runtime=FakeRuntime();entered=Event();release=Event();original=runtime.scan
    def blocked(*args,**kwargs):
        entered.set();assert release.wait(3);return original(*args,**kwargs)
    runtime.scan=blocked;c=coordinator(tmp_path,runtime)
    with ThreadPoolExecutor(max_workers=2) as pool:
        edit=pool.submit(c.handle,'FILE_CHANGED',repo)
        assert entered.wait(3)
        assert c.handle('FILE_CHANGED',repo)['status']=='BUSY'
        stop=pool.submit(c.handle,'AGENT_STOP',repo)
        release.set()
        assert edit.result(timeout=5)['status']=='BASELINE_ESTABLISHED'
        assert stop.result(timeout=5)['status']=='REUSED_LAST_RESULT'
    assert len(runtime.calls)==1


@pytest.mark.parametrize('kind',['oversize-file','too-many-files','total-byte-budget'])
def test_snapshot_budget_failure_never_launches_scanner(repo,tmp_path,monkeypatch,kind):
    import security_runtime.hook_runtime as module
    if kind=='oversize-file':
        dirty(repo,'x'*1_000_001)
    elif kind=='too-many-files':
        monkeypatch.setattr(module,'MAX_FILES',1)
        dirty(repo);(repo/'B.java').write_text('new')
    else:
        monkeypatch.setattr(module,'MAX_BYTES',1);dirty(repo,'too big')
    runtime=FakeRuntime();c=coordinator(tmp_path,runtime)
    with pytest.raises(ValueError):c.handle('FILE_CHANGED',repo)
    assert not runtime.calls


def mixed_version_family(root, rule_ids=('ai-security.java.jpa-query',)):
    """Use the actual heterogeneous SQL family without launching scanners."""
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.rule_coverage import plan_rules
    from security_runtime.rule_program import annotate
    pack = RulePackManager().resolve()
    plan = plan_rules(pack, ['A.java'])
    findings = []
    for detector in rule_ids:
        finding = row(root, rule=detector, category='sql-injection')
        record = next(rule for rule in pack.catalog if rule.rule_id == detector)
        annotate(finding, pack.program.capability(detector), pack.program.version, record)
        finding.technical_details['rule_version'] = record.rule_version
        findings.append(finding)
    run = ScannerRun('semgrep', '1.178.0', 'SUCCESS', 0, provider='semgrep')
    plan.observe({'paths': {'scanned': ['A.java']},
                  'time': {'rules': [rule.rule_id for rule in plan.rules]}}, ('A.java',))
    family = next(iter(family_multiset(findings, [run], {'semgrep': plan}).values()))
    return family, plan, run, findings


def test_hook_new_variant_absence_uses_original_version_not_family_first(tmp_path):
    family, plan, run, _ = mixed_version_family(tmp_path)
    assert family['rule_id'] == 'capability:JAVA_SQL_INJECTION'
    assert family['proof']['rule_version'] == '1.2.0'
    assert family['proof']['rule_versions'] == {'ai-security.java.jpa-query': '1.2.0'}
    assert next(rule for rule in plan.rules if rule.rule_id == 'ai-security.java.jdbc-statement').rule_version == '1.1.0'
    assert covered(family, [run], {'semgrep': plan})
    _, delta = family_delta({family['equivalence_key']: family}, {},
                            lambda value: covered(value, [run], {'semgrep': plan}))
    assert delta['resolved'] == 1


def test_hook_same_coordinate_keeps_all_variant_version_receipts(tmp_path):
    family, plan, run, _ = mixed_version_family(tmp_path, ('ai-security.java.jdbc-statement', 'ai-security.java.jpa-query'))
    assert family['count'] == 1
    assert family['proof']['rule_versions'] == {
        'ai-security.java.jdbc-statement': '1.1.0', 'ai-security.java.jpa-query': '1.2.0'}
    assert covered(family, [run], {'semgrep': plan})


@pytest.mark.parametrize('invalid', ['unknown-detector', 'wrong-version', 'empty-proof', 'not-selected',
                                   'not-confirmed', 'file-not-scanned', 'parser-error', 'skipped-file',
                                   'unscoped-error', 'pack-changed', 'engine-changed', 'partial-run', 'failed-run'])
def test_hook_variant_proof_keeps_all_existing_absence_gates(tmp_path, invalid):
    family, plan, run, _ = mixed_version_family(tmp_path)
    detector = 'ai-security.java.jpa-query'
    if invalid == 'unknown-detector': family['proof']['rule_versions'] = {'unrelated.rule': '1.2.0'}
    elif invalid == 'wrong-version': family['proof']['rule_versions'][detector] = '1.1.0'
    elif invalid == 'empty-proof': family['proof']['rule_versions'] = {}
    elif invalid == 'not-selected': plan.rules = tuple(rule for rule in plan.rules if rule.rule_id != detector)
    elif invalid == 'not-confirmed': plan.confirmed_rules.remove('ai-security.java.jdbc-statement')
    elif invalid == 'file-not-scanned': plan.scanned_files.clear()
    elif invalid == 'parser-error': plan.errored_files.add('A.java')
    elif invalid == 'skipped-file': plan.skipped_files['A.java'] = 'too_big'
    elif invalid == 'unscoped-error': plan.unscoped_error = True
    elif invalid == 'pack-changed': family['proof']['rule_pack_checksum'] = 'b' * 64
    elif invalid == 'engine-changed': family['proof']['engine'] = 'other-engine'
    elif invalid == 'partial-run': run.coverage_contract = 'PARTIAL'
    else: run.status = 'FAILED'
    assert not covered(family, [run], {'semgrep': plan})


def test_hook_legacy_family_cannot_guess_between_heterogeneous_versions(tmp_path):
    family, plan, run, _ = mixed_version_family(tmp_path)
    del family['proof']['rule_versions']
    assert not covered(family, [run], {'semgrep': plan})
    family['proof']['rule_version'] = '1.1.0'
    assert not covered(family, [run], {'semgrep': plan})


def test_hook_legacy_single_version_family_remains_supported(tmp_path):
    from security_runtime.rulepacks import RulePackManager
    from security_runtime.rule_coverage import plan_rules
    pack = RulePackManager().resolve()
    plan = plan_rules(pack, ['A.java'])
    run = ScannerRun('semgrep', '1.178.0', 'SUCCESS', 0, provider='semgrep')
    family = {'scanner_sources': ['semgrep'], 'rule_id': 'ai-security.java.trust-all-hostname',
              'file_path': 'A.java', 'proof': {'rule_pack_checksum': pack.checksum,
                                           'engine': 'semgrep', 'rule_version': '1.1.0'}}
    plan.observe({'paths': {'scanned': ['A.java']},
                  'time': {'rules': [rule.rule_id for rule in plan.rules]}}, ('A.java',))
    assert covered(family, [run], {'semgrep': plan})
    family['proof']['rule_version'] = ''
    assert not covered(family, [run], {'semgrep': plan})


@pytest.mark.parametrize('ambiguous', ['version', 'engine', 'missing-version', 'selected-duplicate-version'])
def test_hook_ambiguous_variant_source_never_chooses_first_version(tmp_path, ambiguous):
    from copy import deepcopy
    from dataclasses import replace
    family, plan, run, findings = mixed_version_family(tmp_path)
    duplicate = deepcopy(findings[0])
    if ambiguous == 'version': duplicate.technical_details['rule_version'] = '1.1.0'
    elif ambiguous == 'engine': duplicate.technical_details['engine'] = 'other-engine'
    elif ambiguous == 'missing-version': duplicate.technical_details.pop('rule_version')
    else:
        original = next(rule for rule in plan.rules if rule.rule_id == 'ai-security.java.jpa-query')
        plan.rules += (replace(original, rule_version='1.1.0'),)
    family = next(iter(family_multiset([*findings, duplicate], [run], {'semgrep': plan}).values()))
    assert family['uncertain'] and family['proof']['rule_versions'] == {}
    assert not covered(family, [run], {'semgrep': plan})


def test_hook_proof_schema_supports_legacy_and_variant_map(repo, tmp_path):
    dirty(repo)
    coordinator_instance = coordinator(tmp_path, FakeRuntime([row(repo)]))
    coordinator_instance.handle('SESSION_START', repo)
    state = json.loads(coordinator_instance.store.path(repo, 'generic', None).read_text())
    family = next(iter(state['families'].values()))
    assert family['proof']['rule_versions'] == {'test.rule': '0.1'}
    validate_state(state)
    family['proof'].pop('rule_versions')
    validate_state(state)


@pytest.mark.parametrize('invalid', [[], {'bad key': '1.2.0'}, {'test.rule': ''},
                                   {'test.rule': []}, {'test.rule': 123},
                                   {str(index): '1.2.0' for index in range(1001)}],
                         ids=['not-map', 'bad-id', 'empty-version', 'container-version', 'number-version', 'oversized-map'])
def test_hook_proof_schema_rejects_invalid_variant_maps(repo, tmp_path, invalid):
    dirty(repo)
    coordinator_instance = coordinator(tmp_path, FakeRuntime([row(repo)]))
    coordinator_instance.handle('SESSION_START', repo)
    state = json.loads(coordinator_instance.store.path(repo, 'generic', None).read_text())
    next(iter(state['families'].values()))['proof']['rule_versions'] = invalid
    with pytest.raises(ValueError, match='hook'):
        validate_state(state)
