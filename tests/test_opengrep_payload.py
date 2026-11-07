"""Derived engines are tied to the pinned wrapper and every extracted byte."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import pytest
from security_runtime import opengrep_payload as payload
from security_runtime.toolchain import ToolManager


@pytest.fixture
def tree(tmp_path, monkeypatch):
    manager=ToolManager(tmp_path/'managed')
    wrapper=manager.managed_path('opengrep');wrapper.parent.mkdir(parents=True)
    wrapper.write_bytes(b'pinned synthetic wrapper')
    checksum=hashlib.sha256(wrapper.read_bytes()).hexdigest()
    monkeypatch.setattr(manager,'manifest',lambda _:SimpleNamespace(sha256=checksum,executable_name=wrapper.name))
    root=wrapper.parent/'payload-fixture';root.mkdir()
    (root/'opengrep.bin').write_bytes(b'executable');(root/'library.so').write_bytes(b'library')
    record=dict(wrapper=checksum,version=manager.versions['opengrep'],slot=root.name,files=payload._inventory(root))
    store=payload._store(wrapper);store.hooks.key(store.root)
    with store.transaction() as db:store._put(db,'active',record)
    return manager,wrapper,root,checksum,store


def test_reuse_and_execution_identity_are_read_only_and_root_specific(tree,monkeypatch):
    manager,wrapper,root,checksum,store=tree
    monkeypatch.setattr('security_runtime.toolchain.run_process',lambda *a,**kw:pytest.fail('Unexpected extraction'))
    first=payload.resolve(wrapper,checksum,manager.versions['opengrep'])
    assert first[0]==root/'opengrep.bin'
    assert payload.identity(first[0],manager)==first[1]
    assert payload.prepare(manager)==dict(status='READY',reused=True)
    assert manager.execution_identity('opengrep',first[0])
    assert payload.resolve(wrapper,'different-wrapper',manager.versions['opengrep']) is None
    assert payload.resolve(wrapper,checksum,'different-version') is None


@pytest.mark.parametrize('change',['library','extra','link','hardlink','wrapper','receipt'])
def test_changed_payload_is_rejected(tree,change):
    manager,wrapper,root,checksum,store=tree
    if change=='library':(root/'library.so').write_bytes(b'changed')
    elif change=='extra':(root/'injected.py').write_text('unsafe')
    elif change=='link':(root/'linked').symlink_to(root/'library.so')
    elif change=='hardlink':(root/'linked').hardlink_to(root/'library.so')
    elif change=='wrapper':wrapper.write_bytes(b'changed')
    else:
        import sqlite3
        with sqlite3.connect(store.path) as db:db.execute("UPDATE records SET data='{}'")
    assert manager.execution_identity('opengrep',root/'opengrep.bin') is None


def test_install_derives_in_fresh_cache_without_user_cache(tree,monkeypatch):
    manager,wrapper,root,checksum,store=tree
    store.path.unlink()
    seen=[]
    def extract(args,**kwargs):
        cache=Path(kwargs['env']['XDG_CACHE_HOME'])
        assert cache.parent==wrapper.parent and cache!=root
        target=cache/'opengrep'/('v'+manager.versions['opengrep']);target.mkdir(parents=True)
        (target/'opengrep.bin').write_bytes(b'fresh executable')
        seen.append(cache)
        return SimpleNamespace(returncode=0,stdout=manager.versions['opengrep'])
    monkeypatch.setattr('security_runtime.toolchain.run_process',extract)
    assert payload.prepare(manager)==dict(status='READY',reused=False)
    result=payload.resolve(wrapper,checksum,manager.versions['opengrep'])
    assert result[0].read_bytes()==b'fresh executable'
    assert not seen[0].exists()


def test_cached_hash_invalidates_equal_size_restored_mtime(tree):
    import os
    manager,wrapper,root,checksum,store=tree
    entry=root/'opengrep.bin'
    assert manager.execution_identity('opengrep',entry)
    library=root/'library.so';before=library.stat()
    library.write_bytes(b'LIBRARY')
    os.utime(library,ns=(before.st_atime_ns,before.st_mtime_ns))
    assert manager.execution_identity('opengrep',entry) is None
