import pytest
from security_runtime.dashboard_catalog import Catalog
from security_runtime import dashboard_catalog,dashboard_entities as entities

@pytest.fixture
def catalog(tmp_path,monkeypatch):
 monkeypatch.setattr(dashboard_catalog,'directory',lambda:tmp_path)
 c=Catalog()
 rows=[dict(id=str(i),revision='v1',editor='codex',editor_label='Codex',project='/fixture',project_id='p',workspace_id='w'+str(i),session_id='s',check_id='c',category='code',severity='高',status='待处理',archived=False) for i in range(2)]
 c.replace(dict(risks=rows,sessions=[],partial=False,note='fixture'))
 return c,rows

def request(row,action='delete',key='request-0001'):
 return dict(action=action,kind=row['kind'],id=row['id'],expected_revision=row['revision'],request_id=key)

@pytest.mark.parametrize('kind',['editor','project','workspace','session'])
def test_delete_restore_and_rebuild_preserve_scope(catalog,kind):
 c,rows=catalog
 first=entities.listing(c,kind)['items'][0]
 req=request(first)
 result=entities.change(c,req)
 assert result['saved'] and entities.change(c,req)['repeated']
 expected=0 if kind in {'editor','project'} else 1
 assert c.query({})['total']==expected
 assert sum(c.query({})['statistics']['status'].values())==expected
 c.replace(dict(risks=rows,sessions=[],partial=False,note='rebuilt'))
 assert c.query({},export=True)['total']==expected
 trash=entities.listing(c,'trash')['items'][0]
 entities.change(c,request(trash,'restore'))
 assert c.query({})['total']==2

def test_deleted_old_revision_does_not_hide_new_activity(catalog):
 c,rows=catalog
 e=entities.listing(c,'project')['items'][0]
 entities.change(c,request(e))
 rows[0]['revision']='new-scan'
 c.replace(dict(risks=rows,sessions=[],partial=False,note='new'))
 assert c.query({})['total']==1
 assert entities.listing(c,'project')['items'][0]['risk_count']==1

def test_conflict_partial_and_forged_entities_do_not_delete(catalog):
 c,rows=catalog
 e=entities.listing(c,'project')['items'][0]
 rows[0]['revision']='new'
 c.replace(dict(risks=rows,sessions=[],partial=False,note='new'))
 with pytest.raises(ValueError,match='CONFLICT'):entities.change(c,request(e))
 assert c.query({})['total']==2
 c.replace(dict(risks=rows,sessions=[],partial=True,note='partial'))
 with pytest.raises(ValueError,match='INCOMPLETE'):entities.listing(c,'project')

def test_riskless_session_deletion_and_index_file_recreation(catalog):
 c,rows=catalog
 session=dict(editor='codex',workspace_id='empty',project_id='other',workspace='/other',session_id='empty',check_id='c',dirty_seq=1)
 c.replace(dict(risks=rows,sessions=[session],partial=False,note='empty'))
 e=next(e for e in entities.listing(c,'session')['items'] if e['risk_count']==0)
 entities.change(c,request(e))
 assert not c.query({})['sessions']
 c.path.unlink()
 c.replace(dict(risks=rows,sessions=[session],partial=False,note='recreated'))
 assert not c.query({})['sessions']

def test_type_metrics_separate_scanner_candidates_from_confirmed(catalog):
 c,rows=catalog
 rows[0].update(scanner_candidate=True,confirmed_risk=False,category='sql')
 rows[1].update(scanner_candidate=True,confirmed_risk=True,category='dependency')
 rows.append(dict(rows[1],id='ai',category='authorization',scanner_candidate=False))
 c.replace(dict(risks=rows,sessions=[],partial=False,note='metrics'))
 metrics=c.query({})['finding_metrics']
 assert metrics['scanner']==dict(total=2,categories={'sql':1,'dependency':1})
 assert metrics['confirmed']==dict(total=2,categories={'dependency':1,'authorization':1})
 assert c.query({'category':'sql'})['finding_metrics']['confirmed']['total']==0
 e=entities.listing(c,'editor')['items'][0]
 entities.change(c,request(e))
 assert c.query({})['finding_metrics']['scanner']['total']==0

def test_resource_parents_keep_worktrees_projects_and_editors_separate(catalog):
 c,rows=catalog
 rows.append(dict(rows[0],id='other',project_id='other-project',workspace_id='other-workspace',project='/other'))
 rows.append(dict(rows[0],id='cursor',editor='cursor'))
 c.replace(dict(risks=rows,sessions=[],partial=False,note='hierarchy'))
 project=next(e for e in entities.listing(c,'project')['items'] if e['scope']['project_id']=='p')
 assert project['workspace_count']==3
 workspaces=entities.listing(c,'workspace')['items']
 children=[e for e in workspaces if any(p['project_id']=='p' for p in e['parents'])]
 assert len(children)==3
 sessions=entities.listing(c,'session')['items']
 selected=children[0]
 child_sessions=[e for e in sessions if e['scope']['workspace_id']==selected['scope']['workspace_id'] and e['scope']['editor']==selected['scope']['editor']]
 assert len(child_sessions)==1
 entities.change(c,request(project))
 assert len(entities.listing(c,'workspace')['items'])==1
 assert len(entities.listing(c,'session')['items'])==1
 trash=entities.listing(c,'trash')['items'][0]
 entities.change(c,request(trash,'restore'))
 assert len(entities.listing(c,'workspace')['items'])==4
 assert len(entities.listing(c,'session')['items'])==4
