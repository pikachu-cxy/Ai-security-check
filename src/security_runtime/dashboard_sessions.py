"""Optional local Codex title adapter; dashboard-only, metadata-only, fail soft."""
from contextlib import closing
from pathlib import Path
import hashlib
import os
import sqlite3
import threading
import time
from .hook_state import no_links
from .redactor import SecretRedactor


def setup(db):
    db.execute('CREATE TABLE IF NOT EXISTS management.session_names (editor TEXT, workspace_id TEXT, session_id TEXT, host_title TEXT DEFAULT "", alias TEXT DEFAULT "", synced_at REAL DEFAULT 0, PRIMARY KEY(editor,workspace_id,session_id))')


def scope(row):
    return tuple(row.get(k,'') for k in ('editor','workspace_id','session_id'))


def names(db):
    return {tuple(r[:3]):dict(host_title=r[3],alias=r[4],last_synced_at=r[5]) for r in db.execute('SELECT editor,workspace_id,session_id,host_title,alias,synced_at FROM session_names')}


def decorate(row, mapping):
    value = mapping.get(scope(row), {})
    title = value.get('alias') or value.get('host_title') or ('未命名会话 · '+row.get('session_id','')[:12] if row.get('session_id') else '会话归属未知')
    return dict(row, session_name=title, session_alias=value.get('alias',''),
                title_source='USER_ALIAS' if value.get('alias') else 'HOST_METADATA' if value.get('host_title') else 'FALLBACK',
                title_synced_at=value.get('last_synced_at',0))


def alias(catalog, data):
    from .dashboard_entities import groups
    if set(data) != {'id','alias','expected_alias'} or any(not isinstance(v,str) for v in data.values()) or len(data['alias'])>200:
        raise ValueError('SESSION_ALIAS_INVALID')
    text = SecretRedactor().redact(data['alias'].strip())
    if any(ord(c)<32 for c in text):
        raise ValueError('SESSION_ALIAS_INVALID')
    with closing(catalog.connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        row = groups(db,'session').get(data['id'])
        if not row:
            raise ValueError('SESSION_UNAVAILABLE')
        key = scope(row['scope'])
        current = names(db).get(key,{})
        if current.get('alias','') != data['expected_alias']:
            raise ValueError('SESSION_ALIAS_CONFLICT')
        db.execute('INSERT INTO session_names(editor,workspace_id,session_id,alias) VALUES (?,?,?,?) ON CONFLICT(editor,workspace_id,session_id) DO UPDATE SET alias=excluded.alias',(*key,text))
    return dict(saved=True)


class TitleSync:
    def __init__(self, catalog, home=None):
        self.catalog = catalog
        self.home = Path(home) if home else Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))
        self.lock = threading.Lock()
        self.status = 'NOT_SYNCED'
        self.last_attempt = 0
        self.signature = None

    def request(self):
        if time.monotonic()-self.last_attempt < 15 or not self.lock.acquire(False):
            return
        self.last_attempt = time.monotonic()
        self.status = 'SYNCING'
        def run():
            try:
                self.refresh()
            finally:
                self.lock.release()
        threading.Thread(target=run, name='dashboard-session-titles', daemon=True).start()

    def refresh(self):
        try:
            # A known schema, never guess the newest arbitrary database format.
            path = self.home/'state_5.sqlite'
            for candidate in (path,path.with_name(path.name+'-wal'),path.with_name(path.name+'-shm')):
                no_links(candidate)
            if not path.is_file():
                self.status='UNAVAILABLE';return
            stamp = tuple((p.stat().st_mtime_ns,p.stat().st_size) if p.exists() else None for p in (path,path.with_name(path.name+'-wal')))
            with closing(self.catalog.connect()) as db:
                import json
                meta=db.execute('SELECT data FROM metadata WHERE id=1').fetchone()
                wanted={tuple(r) for r in db.execute("SELECT DISTINCT editor,workspace_id,session_id FROM risks WHERE editor='codex' AND session_id!=''")}
                if meta:
                    wanted.update(scope(r) for r in json.loads(meta[0]).get('sessions',[]) if r.get('editor')=='codex' and r.get('session_id'))
            signature=(stamp,tuple(sorted(wanted)))
            if signature==self.signature:
                self.status='SYNCED'
                return
            by_session={key[2] for key in wanted}
            found={}
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)) as db:
                db.execute('PRAGMA query_only=ON')
                columns={r[1] for r in db.execute('PRAGMA table_info(threads)')}
                if not {'id','title'}<=columns:
                    self.status='UNSUPPORTED_SCHEMA';return
                deadline=time.monotonic()+2
                db.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
                title="coalesce(nullif(name,''),title)" if 'name' in columns else 'title'
                for thread,text in db.execute('SELECT id,substr('+title+',1,200) FROM threads'):
                    if time.monotonic()>deadline:
                        raise ValueError('TITLE_SYNC_BUDGET')
                    sid=hashlib.sha256(str(thread).encode()).hexdigest()
                    if sid in by_session and isinstance(text,str) and text:
                        found[sid]=SecretRedactor().redact(text)
            with closing(self.catalog.connect()) as db,db:
                for editor,workspace,sid in wanted:
                    if sid in found:
                        db.execute('INSERT INTO session_names(editor,workspace_id,session_id,host_title,synced_at) VALUES (?,?,?,?,?) ON CONFLICT(editor,workspace_id,session_id) DO UPDATE SET host_title=excluded.host_title,synced_at=excluded.synced_at', (editor,workspace,sid,found[sid],time.time()))
            self.signature=signature
            self.status='SYNCED'
        except (OSError,ValueError,sqlite3.Error):
            self.status='UNAVAILABLE'  # Keep the last successful title; never erase it.
