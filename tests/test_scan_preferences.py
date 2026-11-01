"""Product configuration exercises actual capture, queue, process and adapters."""
from pathlib import Path
import copy
import sys
import json
import pytest
from security_runtime.user_config import DEFAULTS, read_config
from security_runtime.scan_preferences import preferences, section

@pytest.fixture(autouse=True)
def config(tmp_path, monkeypatch):
    path = tmp_path.resolve()/'config.toml'
    monkeypatch.setenv('SECURITY_RUNTIME_CONFIG', str(path))
    return path


def policy(**sections):
    from security_runtime.user_config import _merge
    return {'values': _merge(DEFAULTS, sections), 'explicit': sections}


@pytest.mark.parametrize('text', [
    '[scan.input]\nmax_files=-1', '[scan.input]\nmax_files=true',
    '[rules.sast]\nmode="replace"', '[rules.sast]\nexclude_ids=[1]',
    '[vulnerability_data.trivy]\nrepositories=["https://user:password@host/db"]',
])
def test_bad_config_fails_before_scan(config, text):
    config.write_text(text)
    with pytest.raises(ValueError): read_config()


def test_discovery_zero_and_unified_precedence(tmp_path, monkeypatch):
    from security_runtime.target import TargetDetector, DiscoveryLimitError
    root = tmp_path.resolve()/'project'; root.mkdir()
    (root/'a.py').write_text('x=1\n'); (root/'b.py').write_text('y=2\n')
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_FILES', '1')
    with pytest.raises(DiscoveryLimitError): TargetDetector().detect(root)
    with preferences(policy(scan={'discovery': {'max_files': 0, 'max_file_bytes': 0}})):
        assert len(TargetDetector().detect(root).files) == 2
        with pytest.raises(DiscoveryLimitError): TargetDetector(max_files=1).detect(root)


def test_input_zero_captures_and_revalidates(tmp_path):
    from security_runtime.scan_input import capture_scan_input, ScanInputLimits
    from security_runtime.scan_request import ScanRequest, SourceKind
    root=tmp_path.resolve()/'project'; root.mkdir(); (root/'a.py').write_text('x=1\n')
    request=ScanRequest(root, 'release', SourceKind.WORKTREE, ('a.py',))
    with preferences(policy(scan={'input': dict(max_files=0, max_total_bytes=0, max_file_bytes=0, max_index_bytes=0)})):
        assert ScanInputLimits().files == 0
        with capture_scan_input(request, identity_key=b'k'*32) as view:
            assert (view.execution_root/'a.py').read_text() == 'x=1\n'
            view.assert_intact()


def test_unlimited_output_and_capped_output():
    from security_runtime.processes import run_process, OutputLimitError
    command=[sys.executable,'-c','import sys; sys.stdout.write("x"*1100000)']
    assert run_process(command, max_output=0, timeout=0).stdout == 'x' * 1100000
    with pytest.raises(OutputLimitError): run_process(command, max_output=10)


def test_snapshot_isolated_and_reset(config):
    config.write_text('[scan.input]\nmax_files=5')
    saved=read_config()
    config.write_text('[scan.input]\nmax_files=8')
    with preferences(saved):
        assert section('scan', 'input')['max_files'] == 5
        with preferences(): assert section('scan','input')['max_files'] == 5
    assert section('scan','input')['max_files'] == 8


def write_rule(path, ident='local.danger'):
    path.mkdir()
    (path/'rule.yaml').write_text('rules:\n- id: '+ident+'\n  languages: [python]\n  message: test\n  severity: ERROR\n  pattern: eval($X)\n')


def test_custom_rules_duplicate_exclusion_and_content(tmp_path):
    from security_runtime.rulepacks import RulePackManager
    a=tmp_path.resolve()/'rules1'; b=tmp_path.resolve()/'rules2'
    write_rule(a); write_rule(b)
    manager=RulePackManager()
    settings=dict(mode='replace', paths=[str(a)])
    with preferences(policy(rules={'sast': settings})):
        pack=manager.resolve(); assert len(pack.catalog) == 1
        assert pack.catalog[0].rule_id == 'local.danger'
    with preferences(policy(rules={'sast': dict(settings, paths=[str(a),str(b)])})):
        with pytest.raises(ValueError, match='Duplicate'): manager.resolve()
    with preferences(policy(rules={'sast': dict(settings, exclude_ids=['missing'])})):
        with pytest.raises(ValueError, match='Unknown'): manager.resolve()


def test_gitleaks_frozen_user_configuration(tmp_path):
    from security_runtime.configured_rules import gitleaks_config
    source=tmp_path.resolve()/'gitleaks.toml'; source.write_text('[extend]\nuseDefault=true\n')
    with preferences(policy(rules={'gitleaks': {'config_path':str(source)}})):
        target, identity=gitleaks_config()
        source.write_text('changed')
        assert Path(target).read_text() == '[extend]\nuseDefault=true\n'
        assert gitleaks_config() == (target,identity)
    assert not Path(target).exists()


def test_manual_offline_and_require_fresh(tmp_path, monkeypatch):
    from security_runtime.toolchain import ToolManager, ToolStatus
    from datetime import datetime, timedelta, timezone
    now=datetime.now(timezone.utc)
    tools=ToolManager(tmp_path.resolve()/'tools', now=lambda:now)
    monkeypatch.setattr(tools, '_download_trivy_database', lambda *a: pytest.fail('Unexpected download'))
    with preferences(policy(vulnerability_data={'trivy': {'update_mode':'manual'}})):
        db=tools.trivy_cache_dir()/'db'; db.mkdir(parents=True)
        (db/'trivy.db').write_bytes(b'old')
        (db/'metadata.json').write_text(json.dumps({'UpdatedAt':(now-timedelta(days=2)).isoformat(), 'NextUpdate':(now-timedelta(days=1)).isoformat()}))
        assert tools.prepare_trivy_database('trivy') == ToolStatus.READY
    with preferences(policy(vulnerability_data={'trivy': {'update_mode':'offline','stale_policy':'require_fresh'}})):
        assert tools.prepare_trivy_database('trivy') == ToolStatus.BROKEN
        assert (db/'trivy.db').read_bytes() == b'old'


def test_queue_snapshot_and_capacity_changes(tmp_path, config):
    from security_runtime.scan_jobs import ScanJobs, run_worker
    from security_runtime.hook_state import HookStateStore
    from types import SimpleNamespace
    root=tmp_path.resolve()/'project'; root.mkdir(); (root/'a.py').write_text('pass\n')
    config.write_text('[storage.explicit_scan_jobs]\nmax_records=1\n[scan.input]\nmax_files=7')
    queue=ScanJobs(HookStateStore(tmp_path.resolve()/'state/hooks'),root,scan_path=tmp_path.resolve()/'state/scans.db')
    one=queue.submit('request-one', launcher=lambda *a:None)
    row=queue.load(one['job_ref'])
    queue.update(row['job_ref'],row['ticket'],state='FAILED')
    with pytest.raises(ValueError,match='capacity'): queue.submit('request-two',launcher=lambda *a:None)
    config.write_text('[storage.explicit_scan_jobs]\nmax_records=0\n[scan.input]\nmax_files=9')
    two=queue.submit('request-two',launcher=lambda *a:None)
    row=queue.load(two['job_ref'])
    config.write_text('[scan.input]\nmax_files=11')
    seen=[]
    def scan(*args, **kwargs):
        seen.append(section('scan','input')['max_files'])
        return dict(scan_id='fake-scan',status='COMPLETE',scanner_runs=[])
    assert run_worker(root,queue.hooks.directory,row['job_ref'],row['ticket'],
                      application_factory=lambda row:SimpleNamespace(scan_project=scan)) == 0
    assert seen == [9]
    assert len(queue.listing()['jobs']) == 2


def test_legacy_limit_is_frozen(config, monkeypatch):
    from security_runtime.scan_preferences import snapshot
    from security_runtime.target import TargetDetector
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_FILES','13')
    saved=snapshot()
    monkeypatch.setenv('SECURITY_RUNTIME_MAX_FILES','17')
    with preferences(saved): assert TargetDetector().max_files == 13


def test_fast_info_does_not_verify_package(monkeypatch, capsys):
    from security_runtime import cli
    monkeypatch.setattr('security_runtime.guidance.host_guidance.runtime_info',lambda:pytest.fail('Full verification'))
    assert cli.main(['runtime-info','--fast','--json']) == 0
    assert json.loads(capsys.readouterr().out)['verification'] == 'NOT_REVALIDATED'


def test_fast_integration_reports_saved_facts_only(tmp_path, monkeypatch):
    from security_runtime.fast_status import codex_saved_status
    home=tmp_path.resolve()/'codex'; home.mkdir()
    monkeypatch.setenv('CODEX_HOME',str(home))
    (home/'config.toml').write_text('[mcp_servers.ai_security_runtime]\ncommand="never-execute-this"')
    (home/'hooks.json').write_text('{"hooks":{"Stop":[]}}')
    result=codex_saved_status()
    assert result['mcp_entry_present']
    assert result['saved_hook_events'] == ['Stop']
    assert result['ownership'] == result['live_connection'] == 'NOT_REVALIDATED'


def test_publication_capacity_zero_and_retained_readability(tmp_path):
    from security_runtime.scan_publication import ScanPublications
    from security_runtime.scan_attempt import AttemptLease
    from security_runtime.hook_state import HookStateStore
    root=tmp_path.resolve()/'project'; root.mkdir()
    hooks=HookStateStore(tmp_path.resolve()/'state/hooks'); hooks.key(root)
    journal=ScanPublications(hooks,root)
    one=AttemptLease('sa1-'+'a'*32,1,'b'*32,0)
    two=AttemptLease('sa1-'+'c'*32,2,'d'*32,0)
    with preferences(policy(storage={'scan_publication':{'max_records':1}})):
        journal.stage('HOOK','scope',one,{'result':'one'})
        with pytest.raises(ValueError,match='capacity'): journal.stage('HOOK','scope',two,{'result':'two'})
    with preferences(policy(storage={'scan_publication':dict(max_records=0,max_record_bytes=0,max_total_bytes=0)})):
        journal.stage('HOOK','scope',two,{'result':'two'})
    with preferences(policy(storage={'scan_publication':dict(max_records=1,max_record_bytes=1,max_total_bytes=1)})):
        assert len(journal.pending('HOOK','scope')) == 2


def test_report_prompts_preserve_choice_and_no_implied_disposition():
    from security_runtime.development_reporting import reporting
    message=reporting('ref',Path('/project'))['instructions']
    assert '修复／暂不处理' in message
    assert '用户未选择不保存处置' in message
    assert 'offset=0' in message


from test_scanner_hot_path import engine  # noqa: E402,F401


def test_extend_rules_reaches_engine_and_frozen_input(tmp_path, engine):
    from security_runtime.runtime import SecurityRuntime
    from security_runtime.storage import SQLiteStore
    from security_runtime.scanners import ScannerRegistry
    root, path, _, adapter, calls, _ = engine
    extra=tmp_path.resolve()/'extra'; extra.mkdir()
    (extra/'rule.yaml').write_text('rules:\n- id: local.acceptance\n  languages: [java]\n  message: Extra rule\n  severity: WARNING\n  pattern: System.exit($X)\n')
    runtime=SecurityRuntime(ScannerRegistry([adapter],fallback_adapters=[]),SQLiteStore(tmp_path/'extra.db'))
    with preferences(policy(rules={'sast':dict(mode='extend',paths=[str(extra)])})):
        result=runtime.scan(root,'release')
    assert result.scanner_runs[0].status == 'SUCCESS'
    assert 'local.acceptance' in calls[-1][0]
    assert len(calls[-1][0]) == 4


def test_custom_database_content_identity_changes(tmp_path):
    from security_runtime.toolchain import ToolManager
    from security_runtime.scanner_identity import database_content_fingerprint_disabled
    directory=tmp_path.resolve()/'trivy'
    (directory/'db').mkdir(parents=True)
    (directory/'db/trivy.db').write_bytes(b'first')
    (directory/'db/metadata.json').write_text('{}')
    manager=ToolManager(tmp_path.resolve()/'tools')
    assert database_content_fingerprint_disabled('trivy',kind='vuln')
    with preferences(policy(vulnerability_data={'trivy':{'cache_dir':str(directory)}})):
        assert not database_content_fingerprint_disabled('trivy',kind='vuln')
        before=manager.execution_data_identity('trivy',kind='vuln',ecosystems=set())
        (directory/'db/trivy.db').write_bytes(b'other')
        assert before and manager.execution_data_identity('trivy',kind='vuln',ecosystems=set()) != before
