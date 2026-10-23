"""Explicit task focus; switching never changes either task's baseline."""
from .activity import ActivityStore, POLICY, deferred, IDLE_TTL, HARD_TTL
from .ownership import record_owner


def view_fields(service, record):
    if not deferred(record):
        return {}
    store = ActivityStore(service.hooks, record['workspace'], now=service.now)
    focus = store.focus(record_owner(record))
    pending = store.read('queue:'+record['task_ref'])
    background = record.get('closeout_dispatch') == 'BACKGROUND_V1'
    if background:
        from .closeout_queue import CloseoutQueue, PENDING
        request = CloseoutQueue(service.hooks, record['workspace'], now=service.now).read(record['task_ref'])
        is_pending = bool(request and request['state'] in PENDING)
    else:
        is_pending = bool(pending and pending['state'] == 'QUEUED')
    return dict(check_policy=record['check_policy'],
        closeout_dispatch=record.get('closeout_dispatch', 'CALLER_RETRY'),
        routing_generation=focus['generation'] if focus else 0,
        work_state=('CLOSED' if record['phase'] in {'COMPLETE', 'INCOMPLETE', 'NO_CHANGES'} else
                    'ACTIVE' if focus and focus.get('task_ref') == record['task_ref'] else 'SUSPENDED'),
        activity_seq=store.summary(record['task_ref'])['seq'],
        end_version_ref=record.get('end', {}).get('version_ref'),
        closeout_pending=is_pending,
        closeout_resume_tool='wait_task_closeout' if background else 'finish_security_task')


def expires_at(record, hooks, root, *, now):
    if not deferred(record):
        from .security_state import TTL
        return record['created_at'] + TTL
    activity = ActivityStore(hooks, root, now=now).summary(record['task_ref'])
    last = max(record['created_at'], record.get('activity_at', 0), activity.get('last_activity', 0))
    return min(record['created_at']+HARD_TTL, last+IDLE_TTL)


def register(service, root, record, *, expected_generation=None):
    if not deferred(record):
        return
    owner = record_owner(record)
    store = ActivityStore(service.hooks, root, now=service.now)
    key = 'binding:'+record['task_key']
    with store.transaction() as db:
        old = store._get(db, key)
        if old and old['task_ref'] != record['task_ref']:
            raise ValueError('Task key already bound; never reconstruct a baseline')
        if not old:
            store._put(db, key, dict(task_ref=record['task_ref'], owner=owner))
    focus = store.focus(owner)
    if expected_generation is not None:
        store.activate(owner, record['task_ref'], expected_generation=expected_generation,
                       created_at=record['created_at'])
    elif focus is None:
        store.activate(owner, record['task_ref'], expected_generation=0, created_at=record['created_at'])


def switch(service, workspace, from_ref, *, to_ref=None, new_key=None, generation):
    if type(generation) is not int or generation < 0:
        raise ValueError('Invalid routing generation')
    root = service.root(workspace)
    owner = service._owner()
    store = ActivityStore(service.hooks, root, now=service.now)
    if to_ref and new_key:
        raise ValueError('Choose an existing task or a new task, not both')
    if new_key:
        return service.begin(workspace, new_key, check_policy=POLICY,
            _switch=(from_ref, generation), background_closeout=True)
    with service.hooks.lock(root, wait_seconds=2) as acquired:
        if not acquired:
            return dict(status='BUSY', scanner_run=False)
        from ..native_repair_intent import NativeRepairIntents
        blocked = NativeRepairIntents(service.hooks, root, owner, now=service.now).guard()
        if blocked is not None:
            return blocked
        focus = store.focus(owner)
        if not focus or focus['task_ref'] != from_ref or focus['generation'] != generation:
            raise ValueError('Task routing changed; retain original task references')
        target = service.load(root, to_ref) if to_ref else None
        if target and (not deferred(target) or target['phase'] in {'COMPLETE', 'INCOMPLETE'}):
            raise ValueError('Cannot activate a legacy or terminal task')
        selected = store.activate(owner, to_ref, expected_generation=generation,
            created_at=target['created_at'] if target else service.now())
        return dict(status='ACTIVE' if target else 'SUSPENDED', task_ref=to_ref,
            routing_generation=selected['generation'], scanner_run=False)
