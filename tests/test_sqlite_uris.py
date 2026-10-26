"""SQLite URI modes preserve native Windows paths and existing-file access."""
import os
import sqlite3

import pytest

from security_runtime.closeout_state import database_uri, readonly_uri
from security_runtime.hook_state import native_io_path


@pytest.mark.parametrize('extended', [False, True])
@pytest.mark.parametrize('long_path', [False, True])
def test_native_database_modes_and_escaped_names(tmp_path, extended, long_path):
    if (extended or long_path) and os.name != 'nt':
        pytest.skip('Windows extended path contract')
    parent = tmp_path
    if long_path:
        parent = parent / ('a' * 70) / ('b' * 70) / ('c' * 70)
    path = native_io_path(parent / '原文 #100%.db')
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE fixture(value)')
        db.execute('INSERT INTO fixture VALUES(1)')
    target = path if extended else parent / path.name
    with sqlite3.connect(database_uri(target, mode='rw'), uri=True) as db:
        db.execute('UPDATE fixture SET value=2')
    before = path.read_bytes()
    with sqlite3.connect(readonly_uri(target), uri=True) as db:
        assert db.execute('SELECT value FROM fixture').fetchone() == (2,)
        with pytest.raises(sqlite3.OperationalError):
            db.execute('UPDATE fixture SET value=3')
    assert path.read_bytes() == before
    missing = target.with_name('absent.db')
    for mode in ('ro', 'rw'):
        with pytest.raises(sqlite3.OperationalError):
            sqlite3.connect(database_uri(missing, mode=mode), uri=True)
    assert not missing.exists()


@pytest.mark.parametrize('mode', ['rwc', 'memory', 'ro&immutable=1', '', None])
def test_uri_rejects_modes_that_create_or_change_access(tmp_path, mode):
    with pytest.raises(ValueError):
        database_uri(tmp_path / 'absent.db', mode=mode)
    assert not (tmp_path / 'absent.db').exists()
