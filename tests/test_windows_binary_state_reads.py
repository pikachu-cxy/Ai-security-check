"""Windows CRT text mode must not truncate signed keys or SQLite headers."""
import hashlib
import hmac
import os
import sqlite3

from security_runtime.hook_state import HookStateStore
from security_runtime.snapshot_reader import SealedSnapshotReader
from security_runtime.tasks.frozen_body_context import _key, _DOMAIN, readonly_database


def test_frozen_database_header_with_ctrl_z_is_read_exactly(tmp_path):
    path = tmp_path/'header.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE sample (value INTEGER)')
        db.execute('PRAGMA user_version=26')
    before = path.read_bytes()
    assert b'\x1a' in before[:100]
    with readonly_database(path) as db:
        assert db.execute('PRAGMA user_version').fetchone() == (26,)
        assert db.execute('PRAGMA quick_check').fetchone() == ('ok',)
    assert path.read_bytes() == before


def test_binary_signing_key_with_text_eof_and_crlf_remains_complete(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    hooks = HookStateStore(tmp_path/'state')
    path = hooks.workspace_directory(root)/'snapshot.key'
    path.parent.mkdir(parents=True)
    raw = b'\x1a\r\n'+bytes(range(29))
    path.write_bytes(raw)
    assert len(raw) == 32
    assert _key(hooks, root) == hmac.new(raw, _DOMAIN, hashlib.sha256).digest()
    assert path.read_bytes() == raw


def test_sealed_reader_pins_binary_bytes_without_text_translation(tmp_path):
    path = tmp_path/'binary'
    raw = b'SQLite format 3\0\x1a\r\n'+bytes(range(80))
    path.write_bytes(raw)
    reader = SealedSnapshotReader(None, None, None)
    try:
        assert os.read(reader._pin(path), 200) == raw
    finally:
        reader.close()
