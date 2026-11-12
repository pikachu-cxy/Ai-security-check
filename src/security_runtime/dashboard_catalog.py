"""Rebuildable SQL read index, refreshed independently of Stop and risk writes."""
from contextlib import closing
import json
import re
import sqlite3
import threading
import time
from .dashboard_service import directory
from .hook_state import no_links
from .project_identity import describe

DIMENSIONS = ('editor', 'project_id', 'workspace_id', 'session_id', 'check_id', 'category', 'severity', 'status')
ALIASES = {'project': 'project_id', 'workspace': 'workspace_id', 'session': 'session_id', 'check': 'check_id'}
COLUMNS = 'id, ' + ', '.join(DIMENSIONS) + ', activity_at, archived, data'
BATCH = re.compile(r'[A-Za-z0-9_$.-]{1,180}')


class Catalog:
    def __init__(self):
        self.path = directory()/'catalog.db'
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.signature = None
        from .dashboard_sessions import TitleSync
        self.titles = TitleSync(self)

    def inventory(self):
        from .risk_dashboard import STATE, SOURCES
        result = []
        for _, _, folder in SOURCES:
            base = STATE/folder
            no_links(base)
            if not base.exists():
                continue
            for wd in base.iterdir():
                no_links(wd)
                if not wd.is_dir():
                    continue
                for path in (wd/'scans.db', *(wd/'hooks'/wd.name/name for name in
                        ('development-checks.db','development-risks.db','manual-risks.db','snapshot.key'))):
                    for actual in (path, path.with_name(path.name+'-wal')):
                        no_links(actual)
                        if actual.exists():
                            info = actual.stat()
                            result.append((str(actual), info.st_ino, info.st_size, info.st_mtime_ns))
        return sorted(result)

    def connect(self):
        for path in (self.path, self.path.with_name(self.path.name+'-wal'), self.path.with_name(self.path.name+'-shm')):
            no_links(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        db = sqlite3.connect(self.path, timeout=3)
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE IF NOT EXISTS risks (id TEXT PRIMARY KEY, ' +
                   ', '.join(k+' TEXT' for k in DIMENSIONS) + ', activity_at REAL, archived INTEGER, data TEXT NOT NULL)')
        # Older indexes predate the trusted activity column; the read model is
        # rebuildable, so an added column is enough and no data migration runs.
        if 'activity_at' not in {row[1] for row in db.execute('PRAGMA table_info(risks)')}:
            db.execute('ALTER TABLE risks ADD COLUMN activity_at REAL')
        for key in DIMENSIONS:
            db.execute('CREATE INDEX IF NOT EXISTS idx_'+key+' ON risks('+key+')')
        db.execute('CREATE INDEX IF NOT EXISTS idx_activity ON risks(activity_at)')
        db.execute('CREATE TABLE IF NOT EXISTS risk_batches (risk_id TEXT, batch_key TEXT, PRIMARY KEY(risk_id, batch_key))')
        db.execute('CREATE INDEX IF NOT EXISTS idx_batch_key ON risk_batches(batch_key)')
        db.execute('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY, data TEXT)')
        management = self.path.parent/"management.db"
        for path in (management, management.with_name("management.db-wal"), management.with_name("management.db-shm")):
            no_links(path)
        db.execute("ATTACH DATABASE ? AS management", (str(management),))
        from .dashboard_entities import setup
        setup(db)
        from .dashboard_sessions import setup as setup_titles
        setup_titles(db)
        return db

    def replace(self, result):
        with closing(self.connect()) as db, db:
            db.execute('DELETE FROM risks')
            db.execute('DELETE FROM risk_batches')
            def rows():
                for item in result['risks']:
                    item = dict(item)
                    if 'workspace_id' not in item:
                        item.update(describe(item['project']), editable=False, archived=False,
                                    session_id='', check_id='', scan_ids=[], observation_count=1,
                                    scanner_candidate=True, confirmed_risk=False, batch_keys=[], activity_at=0)
                    if item.get('check_id') == 'manual':
                        item['editable'] = True
                    yield (item['id'], *(str(item.get(k, '')) for k in DIMENSIONS),
                           float(item.get('activity_at') or 0), int(item.get('archived', False)),
                           json.dumps(item, ensure_ascii=False))
            db.executemany('INSERT OR REPLACE INTO risks ('+COLUMNS+') VALUES ('+','.join('?' for _ in range(12))+')', rows())
            for item in result['risks']:
                for key in item.get('batch_keys') or []:
                    db.execute('INSERT OR REPLACE INTO risk_batches VALUES (?,?)', (item['id'], str(key)))
            metadata = {k: v for k, v in result.items() if k != 'risks'}
            metadata.update(updated_at=time.time(), status='AVAILABLE')
            db.execute('INSERT OR REPLACE INTO metadata VALUES (1,?)', (json.dumps(metadata),))

    def refresh(self):
        if not self.lock.acquire(blocking=False):
            return
        try:
            from .risk_dashboard import records
            signature = self.inventory()
            if signature == self.signature and self.path.exists():
                return
            self.replace(records(complete=True))
            self.signature = signature
        except (ValueError, OSError, sqlite3.Error):
            with closing(self.connect()) as db, db:
                db.execute('DELETE FROM risks')
                db.execute('DELETE FROM risk_batches')
                db.execute('INSERT OR REPLACE INTO metadata VALUES (1,?)',
                           (json.dumps(dict(status='UNAVAILABLE', partial=True,
                                            note='风险索引无法更新，不能解释为零风险。', updated_at=time.time())),))
        finally:
            self.lock.release()

    def start(self):
        def run():
            while not self.stop.is_set():
                self.wake.clear()
                self.refresh()
                self.titles.request()
                self.wake.wait(5)
        thread = threading.Thread(target=run, name='risk-catalog', daemon=True)
        thread.start()
        return thread

    def query(self, query, *, export=False):
        allowed = set(ALIASES) | set(DIMENSIONS) | {'offset', 'limit', 'q', 'archived', 'id', 'format', 'scan', 'seq'}
        if set(query) - allowed or any(not isinstance(v, str) or len(v) > 1000 for v in query.values()):
            raise ValueError('DASHBOARD_QUERY_INVALID')
        from .dashboard_entities import VISIBLE, visible_sessions
        clauses, args = [VISIBLE], []
        for key, value in query.items():
            field = ALIASES.get(key, key)
            if field in DIMENSIONS:
                if field == 'project_id':
                    clauses.append('(project_id=? OR workspace_id=?)')
                    args.extend((value, value))  # Preserve P1 workspace-only links.
                else:
                    clauses.append(field+'=?'); args.append(value)
            elif key == 'id':
                clauses.append('id=?'); args.append(value)
        batch = batch_clause(query)
        if batch:
            clauses.append(batch[0]); args.extend(batch[1])
        archived = query.get('archived', 'false')
        if archived not in {'true', 'false', 'all'}:
            raise ValueError('DASHBOARD_QUERY_INVALID')
        if archived != 'all':
            clauses.append('archived=?'); args.append(int(archived == 'true'))
        if query.get('q'):
            clauses.append("instr(lower(data),lower(?))>0"); args.append(query['q'])
        try:
            offset, limit = int(query.get('offset', '0')), int(query.get('limit', '50'))
        except ValueError:
            raise ValueError('DASHBOARD_PAGE_INVALID') from None
        if offset < 0 or not 1 <= limit <= 200:
            raise ValueError('DASHBOARD_PAGE_INVALID')
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        with closing(self.connect()) as db, db:
            db.execute('BEGIN')
            meta = db.execute('SELECT data FROM metadata WHERE id=1').fetchone()
            if not meta:
                return dict(status='BUILDING', risks=[], total=None, note='正在载入已保存记录。', partial=True)
            result = json.loads(meta[0])
            sessions = visible_sessions(db, result.get('sessions', []))
            for key in ('editor','project','workspace','session','check'):
                if query.get(key):
                    field = ALIASES.get(key,key)
                    sessions = [s for s in sessions if s.get(field) == query[key] or
                                key == 'project' and s.get('workspace_id') == query[key]]
            from .dashboard_sessions import names, decorate
            mapping = names(db)
            result['sessions'] = [decorate(s,mapping) for s in sessions[:200]]
            result['session_names'] = {s['session_id']:decorate(s,mapping)['session_name'] for s in sessions if s.get('session_id')}
            result['title_sync_status'] = self.titles.status
            result['sessions_omitted'] = max(0, len(sessions)-200)
            total = db.execute('SELECT count(*) FROM risks'+where, args).fetchone()[0]
            stats = {k: dict(db.execute('SELECT '+k+',count(*) FROM risks'+where+' GROUP BY '+k, args))
                     for k in DIMENSIONS}
            aggregates = {}
            for label, flag in (('scanner', 'scanner_candidate'), ('confirmed', 'confirmed_risk')):
                categories = dict(db.execute('SELECT category,count(*) FROM risks'+where+
                    " AND json_extract(data,'$."+flag+"')=1 GROUP BY category", args))
                aggregates[label] = dict(total=sum(categories.values()), categories=categories)
            result['finding_metrics'] = aggregates
            # Trusted record time first; id keeps pages and exports stable.
            rows = db.execute('SELECT data FROM risks'+where+' ORDER BY activity_at DESC, id LIMIT ? OFFSET ?',
                              (*args, 100001 if export else limit, 0 if export else offset)).fetchall()
            from .dashboard_presentation import present
            result.update(risks=[present(decorate(json.loads(r[0]),mapping)) for r in rows], total=total, statistics=stats,
                          offset=offset, next_offset=None if offset+limit >= total else offset+limit)
            if query.get('session') or query.get('session_id'):
                result['note'] += ' 当前只展示已验证会话归属的记录，历史归属未知项请在全部风险查看。'
            if batch:
                result['batch_scope'] = 'VERIFIED'
            return result

    def close(self):
        self.stop.set()
        self.wake.set()


def batch_clause(query):
    """Batch identity is a saved (check, scan, dirty_seq) triple, never a guess."""
    keys = []
    scan = query.get('scan')
    if scan is not None:
        if not BATCH.fullmatch(scan):
            raise ValueError('DASHBOARD_QUERY_INVALID')
        keys.append('scan:' + scan)
    seq = query.get('seq')
    if seq is not None and seq != '':
        try:
            number = int(seq)
        except ValueError:
            raise ValueError('DASHBOARD_QUERY_INVALID') from None
        if number < 0:
            raise ValueError('DASHBOARD_QUERY_INVALID')
        keys.append('seq:' + str(number))
    if not keys:
        return None
    return ('id IN (SELECT risk_id FROM risk_batches WHERE batch_key IN (' +
            ','.join('?' for _ in keys) + '))', keys)
