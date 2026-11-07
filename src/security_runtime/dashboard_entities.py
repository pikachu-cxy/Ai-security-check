"""Recoverable removal of saved dashboard records, independent of live checks."""
import hashlib
import json
import time
from contextlib import closing

KINDS = {'editor': ('editor',), 'project': ('project_id',),
         'workspace': ('editor', 'workspace_id'), 'session': ('editor', 'workspace_id', 'session_id')}
VISIBLE = "NOT EXISTS (SELECT 1 FROM hidden_risks h WHERE h.id=risks.id AND h.revision=coalesce(json_extract(risks.data,'$.revision'),''))"


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True).encode()).hexdigest()


def setup(db):
    db.execute('CREATE TABLE IF NOT EXISTS management.deletions (id TEXT PRIMARY KEY, data TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS management.hidden_risks (entry TEXT, id TEXT, revision TEXT, PRIMARY KEY(entry,id))')
    db.execute('CREATE INDEX IF NOT EXISTS management.hidden_lookup ON hidden_risks(id,revision)')
    db.execute('CREATE TABLE IF NOT EXISTS management.hidden_sessions (entry TEXT, signature TEXT, PRIMARY KEY(entry,signature))')


def visible_sessions(db, sessions):
    hidden = {r[0] for r in db.execute('SELECT signature FROM hidden_sessions')}
    return [s for s in sessions if digest(s) not in hidden]


def groups(db, kind):
    if kind not in KINDS:
        raise ValueError('ENTITY_KIND_INVALID')
    meta = db.execute('SELECT data FROM metadata WHERE id=1').fetchone()
    metadata = json.loads(meta[0]) if meta else {}
    if metadata.get('status') != 'AVAILABLE' or metadata.get('partial'):
        raise ValueError('ENTITY_INDEX_INCOMPLETE')
    risks = [json.loads(r[0]) for r in db.execute('SELECT data FROM risks WHERE '+VISIBLE)]
    sessions = visible_sessions(db, metadata.get('sessions', []))
    found = {}
    for category, rows in (('risks',risks), ('sessions', sessions)):
        for row in rows:
            scope = {k:row.get(k,'') for k in KINDS[kind]}
            if not all(scope.values()):
                continue
            key = digest([kind,scope])
            if key not in found:
                name = (row.get('editor_label') or row['editor']) if kind=='editor' else (
                    '会话 '+row['session_id'][:12] if kind=='session' else row.get('workspace') or row.get('project'))
                found[key] = dict(id=key,kind=kind,name=name,scope=scope,risks=[],sessions=[],session_keys=[],parents={})
            parent = dict(project_id=row.get('project_id',''), workspace_id=row.get('workspace_id',''),
                          editor=row.get('editor',''), workspace=row.get('workspace') or row.get('project',''))
            found[key]['parents'][digest(parent)] = parent
            if row.get('session_id'):
                session_key=digest([row.get('editor'),row.get('workspace_id'),row['session_id']])
                if session_key not in found[key]['session_keys']:
                    found[key]['session_keys'].append(session_key)
            found[key][category].append((row['id'],row.get('revision','')) if category=='risks' else digest(row))
    for row in found.values():
        row['risks'].sort();row['sessions'].sort()
        row['parents'] = [v for _,v in sorted(row['parents'].items())]
        row['workspace_count'] = len({(p['editor'],p['workspace_id']) for p in row['parents']})
        row['revision']=digest(row)
        row['risk_count']=len(row['risks']);row['session_count']=len(row.pop('session_keys'))
    return found


def listing(catalog, kind):
    with closing(catalog.connect()) as db, db:
        db.execute('BEGIN')
        if kind=='trash':
            return dict(items=[json.loads(r[0]) for r in db.execute('SELECT data FROM deletions')])
        return dict(items=[{k:v for k,v in r.items() if k not in {'risks','sessions'}} for r in groups(db,kind).values()])


def change(catalog, data):
    if set(data) != {'action','kind','id','expected_revision','request_id'} or not all(isinstance(v,str) for v in data.values()):
        raise ValueError('ENTITY_REQUEST_INVALID')
    import re
    if not re.fullmatch('[A-Za-z0-9_-]{8,100}',data['request_id']):
        raise ValueError('ENTITY_REQUEST_INVALID')
    with closing(catalog.connect()) as db, db:
        db.execute('BEGIN IMMEDIATE')
        if data['action']=='restore':
            old=db.execute('SELECT data FROM deletions WHERE id=?',(data['id'],)).fetchone()
            if old and json.loads(old[0])['revision'] != data['expected_revision']:
                raise ValueError('ENTITY_VERSION_CONFLICT')
            db.execute('DELETE FROM hidden_risks WHERE entry=?',(data['id'],))
            db.execute('DELETE FROM hidden_sessions WHERE entry=?',(data['id'],))
            db.execute('DELETE FROM deletions WHERE id=?',(data['id'],))
            return dict(saved=True)
        if data['action']!='delete':
            raise ValueError('ENTITY_ACTION_INVALID')
        old=db.execute('SELECT data FROM deletions WHERE id=?',(data['request_id'],)).fetchone()
        if old:
            if json.loads(old[0])['request_digest'] != digest(data):
                raise ValueError('ENTITY_REQUEST_REUSED')
            return dict(saved=True,repeated=True)
        row=groups(db,data['kind']).get(data['id'])
        if not row or row['revision']!=data['expected_revision']:
            raise ValueError('ENTITY_VERSION_CONFLICT')
        entry=data['request_id']
        db.executemany('INSERT INTO hidden_risks VALUES (?,?,?)',[(entry,*r) for r in row['risks']])
        db.executemany('INSERT INTO hidden_sessions VALUES (?,?)',[(entry,s) for s in row['sessions']])
        record={k:v for k,v in row.items() if k not in {'risks','sessions'}}
        record.update(id=entry,deleted_at=time.time(),request_digest=digest(data))
        db.execute('INSERT INTO deletions VALUES (?,?)',(entry,json.dumps(record)))
        return dict(saved=True,risk_count=row['risk_count'],session_count=row['session_count'])
