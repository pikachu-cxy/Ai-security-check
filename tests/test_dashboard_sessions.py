import hashlib
import json
import sqlite3
from contextlib import closing
import pytest
from security_runtime.dashboard_catalog import Catalog
from security_runtime import dashboard_catalog, dashboard_entities as entities
from security_runtime.dashboard_sessions import TitleSync, alias

@pytest.fixture
def fixture(tmp_path,monkeypatch):
    monkeypatch.setattr(dashboard_catalog,'directory',lambda:tmp_path/'dashboard')
    catalog=Catalog()
    home=tmp_path/'codex';home.mkdir()
    sid=hashlib.sha256(b'chat-1').hexdigest()
    rows=[dict(id=str(i),revision='v1',editor='codex',project='project',project_id='project',workspace_id='work'+str(i),session_id=sid,category='sql',severity='高',status='待复核',archived=False) for i in range(2)]
    catalog.replace(dict(risks=rows,sessions=[],partial=False,note='fixture'))
    with sqlite3.connect(home/'state_5.sqlite') as db:
        db.execute('CREATE TABLE threads(id TEXT PRIMARY KEY,title TEXT,name TEXT,first_user_message TEXT)')
        db.execute('INSERT INTO threads VALUES (?,?,?,?)',('chat-1','初始聊天',None,'MUST_NOT_READ'))
        db.execute('INSERT INTO threads VALUES (?,?,?,?)',('unrelated','不应关联',None,'MUST_NOT_READ'))
    sync=TitleSync(catalog,home);catalog.titles=sync
    return catalog,home,rows


def test_exact_title_mapping_rename_alias_worktrees_and_restore(fixture):
    c,home,rows=fixture;c.titles.refresh()
    before=entities.listing(c,'session')['items']
    assert len(before)==2 and all(r['name']=='初始聊天' for r in before)
    alias(c,dict(id=before[0]['id'],alias='我的别名',expected_alias=''))
    with sqlite3.connect(home/'state_5.sqlite') as db:
        db.execute('UPDATE threads SET name=? WHERE id=?',('宿主改名','chat-1'))
    c.titles.refresh()
    after=entities.listing(c,'session')['items']
    assert {r['name'] for r in after}=={'我的别名','宿主改名'}
    assert [r['revision'] for r in after]==[r['revision'] for r in before]
    target=after[0]
    entities.change(c,dict(action='delete',kind='session',id=target['id'],expected_revision=target['revision'],request_id='delete-0001'))
    assert c.query({})['total']==1
    c.replace(dict(risks=rows,sessions=[],partial=False,note='rebuilt'))
    assert c.query({})['total']==1
    trash=entities.listing(c,'trash')['items'][0]
    entities.change(c,dict(action='restore',kind='session',id=trash['id'],expected_revision=trash['revision'],request_id='restore-0001'))
    assert c.query({})['total']==2
    assert '我的别名' in {r['name'] for r in entities.listing(c,'session')['items']}


def test_missing_database_keeps_cached_title_and_alias_conflicts(fixture):
    c,home,_=fixture;c.titles.refresh()
    row=entities.listing(c,'session')['items'][0]
    (home/'state_5.sqlite').unlink();c.titles.refresh()
    assert c.titles.status=='UNAVAILABLE'
    assert entities.listing(c,'session')['items'][0]['name']=='初始聊天'
    alias(c,dict(id=row['id'],alias='别名一',expected_alias=''))
    with pytest.raises(ValueError,match='CONFLICT'):
        alias(c,dict(id=row['id'],alias='别名二',expected_alias=''))
    alias(c,dict(id=row['id'],alias='',expected_alias='别名一'))
    assert entities.listing(c,'session')['items'][0]['name']=='初始聊天'


def test_unknown_schema_and_unmatched_session_fallback(fixture):
    c,home,rows=fixture
    with sqlite3.connect(home/'state_5.sqlite') as db:db.execute('DROP TABLE threads')
    c.titles.refresh();assert c.titles.status=='UNSUPPORTED_SCHEMA'
    assert all(r['name'].startswith('未命名会话') for r in entities.listing(c,'session')['items'])


def test_riskless_session_name_does_not_change_delete_signature(fixture):
    c,home,_=fixture
    session=dict(editor='codex',workspace_id='empty',session_id=hashlib.sha256(b'chat-1').hexdigest(),project_id='project',workspace='/fixture')
    c.replace(dict(risks=[],sessions=[session],partial=False,note='fixture'))
    c.titles.refresh();row=entities.listing(c,'session')['items'][0]
    entities.change(c,dict(action='delete',kind='session',id=row['id'],expected_revision=row['revision'],request_id='delete-0002'))
    c.replace(dict(risks=[],sessions=[session],partial=False,note='rebuilt'))
    assert c.query({})['sessions']==[]


def test_alias_http_auth_csrf_and_validation(fixture):
    from test_dashboard_service import running,request
    from http.client import HTTPConnection
    c,_,_=fixture
    row=entities.listing(c,'session')['items'][0]
    with running() as server:
        server.catalog=c
        data=json.dumps(dict(id=row['id'],alias='本地聊天别名',expected_alias='')).encode()
        def post(headers):
            conn=HTTPConnection('127.0.0.1',server.server_port)
            conn.request('POST','/api/session-alias',body=data,headers={'Content-Type':'application/json',**headers})
            r=conn.getresponse();status=r.status;r.read();conn.close();return status
        assert post({})==403
        cookie=request(server,'/'+server.token+'/')[1]['Set-Cookie'].split(';')[0]
        assert post({'Cookie':cookie})==403
        headers={'Cookie':cookie,'Origin':server.origin,'X-CSRF-Token':server.token}
        assert post(headers)==200
        assert post(headers)==409
        assert entities.listing(c,'session')['items'][0]['name']=='本地聊天别名'
