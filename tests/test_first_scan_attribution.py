"""Deterministic attribution tests; synthetic engine output is not a benchmark."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from test_hook_runtime import repo
from test_remediation import UNSAFE, FIXED
from security_runtime.first_scan_attribution import file_digest, recover_bytes
from security_runtime.hook_runtime import HookCoordinator
from security_runtime.hook_state import HookStateStore
from security_runtime.models import ScannerRun, RunStatus
from security_runtime.runtime import SecurityRuntime
from security_runtime.scanners import ScannerRegistry, SemgrepAdapter
from security_runtime.storage import SQLiteStore
from security_runtime.toolchain import ToolStatus
from security_runtime.remediation_policy import RULE


class Tools:
    def __init__(self, tmp_path):
        self.root = tmp_path
        self.path = tmp_path/'engine'; self.path.write_bytes(b'fixture-engine')
        self.version = '1.178.0'
    def resolve(self, _):
        return SimpleNamespace(status=ToolStatus.READY, version=self.version, path=self.path)
    def ensure(self, *a, **kw):
        from security_runtime.first_scan_attribution import record_probe
        record_probe('semgrep',self._probe_identity())
        return self.resolve('semgrep')
    def _probe_identity(self, *a): return self.path.read_bytes()
    def execution_identity(self, tool, binary, **kwargs):
        from security_runtime.scanner_identity import content_identity
        return content_identity((('fixture-engine', binary),))


class Secrets:
    name = scanner_id = 'gitleaks'
    engine_id = 'gitleaks'
    provider_role = 'PRIMARY'
    capabilities = frozenset({'SECRET_SCAN'})
    def supports(self, *a): return True
    def scan(self, context, n): return [], ScannerRun(self.name, '8.30.0', 'SUCCESS', 0)


@pytest.fixture
def harness(repo, tmp_path, monkeypatch):
    tools=Tools(tmp_path)
    adapter=SemgrepAdapter(tools)
    calls=[]
    phase={'pre':False}
    original_scan=adapter.scan
    def staged_scan(context, normalizer):
        # Runtime supplies the original logical root for captured current
        # input. The separately recovered pre-edit scope has no live root.
        phase['pre']=context.logical_root is None
        return original_scan(context, normalizer)
    monkeypatch.setattr(adapter,'scan',staged_scan)
    failure={'pre':False, 'version':False, 'coverage':False, 'moving':False, 'stamp':False, 'post_stamp':False, 'rule_mismatch':False}
    import security_runtime.scanners as module
    def execute(argv, cwd, timeout):
        assert not core.store.lock_held(repo)
        selected = yaml.safe_load(Path(argv[argv.index('--config')+1]).read_text())['rules']
        files = argv[argv.index('--no-git-ignore')+1:]
        # Both scans now read private immutable inputs. Their path cannot
        # distinguish current Providers from the targeted pre-edit scan.
        pre = phase['pre']
        calls.append(dict(pre=pre, root=str(cwd), files=tuple(files), rules=tuple(r['id'] for r in selected)))
        found=[]
        for name in files:
            for number,line in enumerate((Path(cwd)/name).read_bytes().splitlines(), 1):
                if b'setHostnameVerifier((hostname, session) -> true)' in line:
                    found.append(dict(check_id=RULE, path=name, start={'line':number}, end={'line':number},
                        extra={'message':'TLS fixture', 'severity':'ERROR','lines':line.decode('utf-8',errors='replace')}))
        if pre and failure['moving']:
            (repo/'A.java').write_text(UNSAFE+'// concurrent write\n')
        if pre and failure['version']:
            tools.version='1.999.0'
        if pre and failure['stamp']:
            tools.path.write_bytes(b'changed-engine-same-version')
        if not pre and failure['post_stamp']:
            tools.path.write_bytes(b'changed-during-post-scan')
        if not pre and failure['rule_mismatch']:
            from dataclasses import replace
            pack=adapter.rule_packs.resolve()
            monkeypatch.setattr(adapter.rule_packs,'resolve',lambda **kw:replace(pack,checksum='b'*64))
        payload=dict(results=found, errors=[], paths={'scanned':[] if pre and failure['coverage'] else files},
                     time={'rules':[r['id'] for r in selected]})
        return SimpleNamespace(return_code=2 if pre and failure['pre'] else 0,
                               stdout=json.dumps(payload),stderr='synthetic-private-error',timing_ms={})
    monkeypatch.setattr(module,'_execute',execute)
    # _execute's normal production implementation sets the process ledger.
    def marked(*args):
        from security_runtime.verification_policy import scanner_process_observed
        scanner_process_observed(); return execute(*args)
    monkeypatch.setattr(module,'_execute',marked)
    store=SQLiteStore(tmp_path/'db/scans.db')
    core=HookCoordinator(SecurityRuntime(ScannerRegistry([adapter,Secrets()],tool_manager=tools),store),
                         HookStateStore(tmp_path/'hooks'),cooldown_ms=0)
    return core, calls, failure, store


def commit(root, content):
    (root/'A.java').write_bytes(content.encode() if isinstance(content,str) else content)
    subprocess.run(['git','-C',str(root),'add','A.java'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(root),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit','-m','baseline','--allow-empty'],check=True,capture_output=True)


def start(core, root):
    out=core.handle_lifecycle('SESSION_START',root,'cursor','session')
    assert out['baseline_publish_status']=='PUBLISHED' and not out['execution']['scanner_run']
    return core.store.path(root,'cursor','session').read_bytes()


def edit(core, root, text=UNSAFE):
    (root/'A.java').write_bytes(text.encode() if isinstance(text,str) else text)
    return core.handle_lifecycle('WORKSPACE_ACTIVITY',root,'cursor','session')


def test_new_risk_real_pre_scan_reuses_family_and_policy(repo,harness):
    core,calls,_,store=harness; commit(repo,FIXED); start(core,repo)
    out=edit(core,repo)
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED', json.dumps(out, default=str)
    assert out['attribution_scanner_equivalent'] and out['newly_attributed_risk_count']==1
    assert out['pre_existing_risk_count']==0 and out['delta']['new']==1
    assert out['scan_id']==store.latest_scan()['scan_id']
    assert [c['pre'] for c in calls]==[False,True]
    assert calls[0]['rules']==calls[1]['rules'] and calls[1]['files']==('A.java',)
    assert not Path(calls[1]['root']).exists()
    assert Path(calls[1]['root']).parent == core.store.workspace_directory(repo)/'scan-inputs'
    from security_runtime.scan_attempt import ScanAttemptStore
    assert ScanAttemptStore(core.store,repo).read()['directories']==[]
    assert out['scanner_invocation_count']==2
    from security_runtime.remediation import RemediationService
    service=RemediationService(store,hooks=core.store)
    service.config.write('report_only')
    decision=service.on_hook(out,repo,'session',host='cursor')
    assert decision['action']=='ADVISE' and decision['finding_policy']=='ACTIONABLE'


def test_existing_risk_timeout_edit_and_line_motion_not_new(repo,harness):
    core,calls,_,_=harness; commit(repo,UNSAFE); start(core,repo)
    out=edit(core,repo,'\n\n'+UNSAFE.replace('1000','2400'))
    assert out['first_scan_attribution_status']=='FIRST_SCAN_EXISTING_RISK'
    assert out['delta']['new']==0 and out['delta']['persisting']==1
    assert out['pre_existing_risk_count']==1 and out['newly_attributed_risk_count']==0


def test_existing_plus_new_same_rule_occurrences(repo,harness):
    core,_,_,_=harness; commit(repo,UNSAFE); start(core,repo)
    out=edit(core,repo,UNSAFE.replace('  connection.setConnectTimeout',
        '  connection.setHostnameVerifier((hostname, session) -> true);\n  connection.setConnectTimeout'))
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert out['delta']['new']==0 and out['delta']['persisting']==1
    assert out['delta']['additional_occurrences']==1
    assert out['pre_existing_risk_count']==out['newly_attributed_risk_count']==1


@pytest.mark.parametrize('issue',['pre','version','coverage','moving','stamp','post_stamp','rule_mismatch'])
def test_failed_or_mismatched_attribution_never_advances_snapshot(repo,harness,issue):
    core,_,failure,_=harness; commit(repo,FIXED); before=start(core,repo); failure[issue]=True
    out=edit(core,repo)
    if issue=='post_stamp':
        # Fixed-input Providers now reject a changed actual executable before
        # attempting any pre-edit attribution, retaining the same baseline.
        assert out['status']=='PARTIAL'
        assert out['first_scan_attribution_status']=='NOT_APPLICABLE'
        assert not out['pre_edit_targeted_scan_run']
        assert any(run['error_code']=='SCAN_EXECUTION_IDENTITY_CHANGED' for run in out['scanner_runs'])
    else:
        assert out['first_scan_attribution_status']=='FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'
        assert out['reason']=='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT'
    assert out['delta']['new']==0
    assert core.store.path(repo,'cursor','session').read_bytes()==before
    assert core.store.pending_activity(repo,'cursor','session')


def test_missing_snapshot_never_uses_head_as_security_authority(repo,harness):
    core,calls,_,_=harness; commit(repo,FIXED)
    out=edit(core,repo)
    assert out['reason']=='FIRST_SCAN_UNATTRIBUTED_RISK_PRESENT' and out['delta']['new']==0
    assert not out['pre_edit_targeted_scan_run'] and len(calls)==1


def test_dirty_snapshot_not_recoverable_does_not_guess_head(repo,harness):
    core,calls,_,_=harness; commit(repo,FIXED)
    (repo/'A.java').write_text(FIXED+'// uncommitted pre-edit bytes\n')
    before=start(core,repo); out=edit(core,repo)
    assert out['first_scan_attribution_reason']=='NO_TRUSTED_PRE_EDIT_BYTES'
    assert len(calls)==1 and core.store.path(repo,'cursor','session').read_bytes()==before


def test_safe_edit_no_extra_pre_scan(repo,harness):
    core,calls,_,_=harness; commit(repo,FIXED); start(core,repo)
    out=edit(core,repo,FIXED.replace('1000','2400'))
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NO_RISK'
    assert out['pre_edit_targeted_scan_count']==0 and len(calls)==1


@pytest.mark.parametrize('encoding',['LF','CRLF','BOM'])
def test_exact_byte_recovery_and_original_source_unchanged(repo,harness,encoding):
    core,calls,_,_=harness
    pre=FIXED.encode(); post=UNSAFE.encode()
    if encoding=='CRLF': pre=pre.replace(b'\n',b'\r\n');post=post.replace(b'\n',b'\r\n')
    if encoding=='BOM': pre=b'\xef\xbb\xbf'+pre;post=b'\xef\xbb\xbf'+post
    commit(repo,pre);start(core,repo);out=edit(core,repo,post)
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert (repo/'A.java').read_bytes()==post and not Path(calls[-1]['root']).exists()


def test_only_risk_bearing_changed_file_is_materialized(repo,harness):
    core,calls,_,_=harness;commit(repo,FIXED); start(core,repo)
    (repo/'B.java').write_text('class B {}')
    out=edit(core,repo)
    assert out['changed_file_count']==2
    assert calls[-1]['files']==('A.java',) and out['pre_edit_targeted_scan_count']==1


def test_reload_keeps_digest_bound_recovery_no_source_archive(repo,harness):
    core,calls,_,_=harness;commit(repo,FIXED); start(core,repo)
    other=HookCoordinator(core.runtime,HookStateStore(core.store.directory),cooldown_ms=0)
    out=edit(other,repo)
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    for path in core.store.directory.rglob('*'):
        if path.is_file():
            assert b'setHostnameVerifier' not in path.read_bytes()
            assert FIXED.encode() not in path.read_bytes()


def test_same_rule_changed_old_span_is_inconclusive_not_new(repo,harness):
    core,_,_,_=harness;commit(repo,UNSAFE);before=start(core,repo)
    out=edit(core,repo,UNSAFE.replace('  connection.setHostnameVerifier','   connection.setHostnameVerifier'))
    assert out['first_scan_attribution_reason']=='OCCURRENCE_IDENTITY_UNPROVEN'
    assert out['delta']['new']==0 and core.store.path(repo,'cursor','session').read_bytes()==before


def test_recover_wrong_digest_and_workspace_rejected(repo,tmp_path):
    commit(repo,FIXED)
    with pytest.raises(ValueError, match='NO_TRUSTED_PRE_EDIT_BYTES'):
        recover_bytes(repo,'A.java',file_digest(b'x'*32,FIXED.encode()),b'y'*32)
    with pytest.raises(ValueError):recover_bytes(repo,'../outside.java','0'*64,b'x'*32)


def test_closed_diagnostics_no_source_or_unknown_fields():
    from security_runtime.first_scan_attribution import diagnostics
    from security_runtime.recent_hooks import safe_fields
    raw={**diagnostics(), 'first_scan_attribution_status':'FIRST_SCAN_NEW_RISK_ATTRIBUTED',
         'source':'private-source-canary', 'snapshot_content':'private-snapshot-canary',
         'first_scan_attribution_reason':'private-secret-canary'}
    safe=safe_fields(raw)
    assert safe['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert 'canary' not in json.dumps(safe)


def test_same_bytes_retry_after_pre_failure_gets_new_real_proof(repo,harness):
    core,calls,failure,_=harness;commit(repo,FIXED);start(core,repo)
    failure['pre']=True;assert edit(core,repo)['delta']['new']==0
    failure['pre']=False
    out=core.handle_lifecycle('WORKSPACE_ACTIVITY',repo,'cursor','session')
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'
    assert len(calls)==4 and not core.store.pending_activity(repo,'cursor','session')


def test_staged_baseline_recovery_is_digest_authenticated(repo,harness):
    core,_,_,_=harness;commit(repo,FIXED)
    pre=FIXED+'// staged pre-edit bytes\n'
    (repo/'A.java').write_text(pre)
    subprocess.run(['git','-C',str(repo),'add','A.java'],check=True,capture_output=True)
    start(core,repo);out=edit(core,repo,UNSAFE+'// staged pre-edit bytes\n')
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED'


def test_shared_core_legacy_entry_can_use_comparison_snapshot(repo,harness):
    core,_,_,_=harness;commit(repo,FIXED)
    core.handle_lifecycle('SESSION_START',repo,'codex','session')
    (repo/'A.java').write_text(UNSAFE)
    out=core.handle('FILE_CHANGED',repo,'codex','session')
    assert out['first_scan_attribution_status']=='FIRST_SCAN_NEW_RISK_ATTRIBUTED' and out['delta']['new']==1


def test_old_blob_timeout_is_inconclusive_without_snapshot_advance(repo,harness,monkeypatch):
    core,calls,_,_=harness;commit(repo,FIXED);before=start(core,repo)
    import security_runtime.hook_runtime as module
    git=module._git
    def timed(root,*args):
        if args[0]=='cat-file':raise subprocess.TimeoutExpired('git',10)
        return git(root,*args)
    monkeypatch.setattr(module,'_git',timed)
    out=edit(core,repo)
    assert out['first_scan_attribution_status']=='FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'
    assert out['first_scan_attribution_reason']=='NO_TRUSTED_PRE_EDIT_BYTES'
    assert out['delta']['new']==0 and len(calls)==1
    assert core.store.path(repo,'cursor','session').read_bytes()==before
    assert core.store.pending_activity(repo,'cursor','session')
