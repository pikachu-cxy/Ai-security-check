"""Read saved history without admitting a live workspace or launching work."""
from contextlib import closing
from pathlib import Path
import json
import sqlite3

from .tasks.durable import SignedRecords


class HistoryRecords(SignedRecords):
    """Retain the signed historical root, including removed or moved projects.

    The caller validates its hash against the storage namespace. _decode still
    checks every key, workspace and MAC; never resolve the root against today's
    filesystem or initialize a signing key. Only dashboard readers use this.
    """
    def __init__(self, path, root):
        self.path, self.root = Path(path), Path(root)
        if self.path.name == 'development-checks.db':
            self.max_record_bytes = self.max_database_bytes = 0

    def _all(self, db):
        cursor = db.execute(self._select() + ' ORDER BY rowid')
        result = []
        while page := cursor.fetchmany(128):
            result.extend(self._decode(row) for row in page)
        return result

    def transaction(self):
        raise RuntimeError('HISTORY_READ_ONLY')


def scan_rows(path):
    """One read snapshot, bounded fetches, all scans including beyond page 100."""
    from .risk_dashboard import open_readonly
    with closing(open_readonly(path)) as db:
        cursor = db.execute('SELECT CASE WHEN length(CAST(data AS BLOB)) <= 16000000 '
                            'THEN data END FROM scans ORDER BY rowid DESC')
        while page := cursor.fetchmany(100):
            yield from page


def diagnostic(error, editor, workspace_id, database):
    """Fixed messages only: no raw exception text, keys or record contents."""
    message = str(error)
    if 'signature mismatch' in message:
        code, text = 'HISTORY_SIGNATURE_INVALID', '历史记录签名校验失败，受影响工作区的开发记录未完整载入'
    elif isinstance(error, FileNotFoundError) or 'key unavailable' in message:
        code, text = 'HISTORY_FILE_MISSING', '历史存储或校验密钥缺失，相关记录未载入'
    elif 'workspace binding' in message:
        code, text = 'HISTORY_WORKSPACE_INVALID', '历史记录的项目归属校验失败，相关记录未载入'
    elif 'limit' in message.lower() or 'Oversized' in message or 'capacity' in message:
        code, text = 'HISTORY_RECORD_LIMIT', '历史记录超过安全读取容量，相关记录未载入'
    elif isinstance(error, (json.JSONDecodeError, KeyError, TypeError, AttributeError)):
        code, text = 'HISTORY_FORMAT_INVALID', '历史记录格式异常，相关记录未完整载入'
    elif isinstance(error, sqlite3.Error):
        code, text = 'HISTORY_DATABASE_UNREADABLE', '历史数据库读取失败，相关记录未完整载入'
    else:
        code, text = 'HISTORY_STORAGE_UNREADABLE', '历史存储读取或结构校验失败，相关记录未完整载入'
    return dict(code=code, editor=editor, workspace_id=workspace_id,
                database=database, message=text)
