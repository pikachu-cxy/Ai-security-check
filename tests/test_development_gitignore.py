import subprocess
import pytest
from test_development_outputs import sample
from security_runtime.development_scope import filter_gitignored
from security_runtime.development_stop import fallback
from test_development_outputs import OWNER


def test_patterns_negation_nested_and_tracked(sample):
    root, service, ref = sample
    (root/'tracked.log').write_text('source')
    subprocess.run(['git','-C',str(root),'add','tracked.log'],check=True)
    (root/'.gitignore').write_text('*.log\ncache/\n!keep.log\n')
    (root/'nested').mkdir()
    (root/'nested/.gitignore').write_text('*.tmp\n!keep.tmp\n')
    paths=['a.log','cache/deleted.py','keep.log','tracked.log','nested/a.tmp','nested/keep.tmp','new.py']
    selected,ignored,note=filter_gitignored(root,paths)
    assert selected==['keep.log','tracked.log','nested/keep.tmp','new.py']
    assert ignored==['a.log','cache/deleted.py','nested/a.tmp'] and note is None


def test_ignored_only_closeout_does_not_scan_or_block(sample):
    root,service,ref=sample
    (root/'.gitignore').write_text('scratch/\n')
    service.record(root,ref,['scratch/deleted.py'])
    result=fallback(service.hooks,root,OWNER,service=service,turn_id='one')
    assert result is None
    saved=service.get(root,ref)
    assert saved['status']=='NO_OBSERVED_CHANGES'
    assert saved['scope']['gitignored_paths']==['scratch/deleted.py']


def test_non_git_failure_keeps_inputs(tmp_path):
    paths=['scratch.py']
    assert filter_gitignored(tmp_path,paths)==(paths,[],'GIT_IGNORE_FILTER_UNAVAILABLE')


def test_git_timeout_keeps_inputs(sample,monkeypatch):
    root,_,_=sample
    def timeout(*a,**kw): raise subprocess.TimeoutExpired('git',10)
    monkeypatch.setattr(subprocess,'run',timeout)
    assert filter_gitignored(root,['a.py'])==(['a.py'],[],'GIT_IGNORE_FILTER_UNAVAILABLE')
