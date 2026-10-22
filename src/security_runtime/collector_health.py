"""Worker-owned checkpoints; a stale checkpoint signals uncertainty, not losslessness."""
from contextlib import closing
import time

COUNTERS = ('offered','enqueued','dropped','invalid','persisted','write_errors',
            'disabled','settings_errors','queued','pending')


def write_checkpoint(store, stats, state):
    try:
        from .context_cost_worker import _number, _CALL_ID
        if state not in {'RUNNING','STOPPED'} or not _CALL_ID.fullmatch(stats['producer_id']):
            return
        if store.monitoring().get('mode') == 'off':
            return
        value = dict(schema_version=1, producer_id=stats['producer_id'], state=state,
                     at=time.time(), **{name:_number(stats[name],2**63-1) for name in COUNTERS})
        db, key = store._connect(write=True)
        with closing(db), db:
            db.execute('CREATE TABLE IF NOT EXISTS collector_health (producer TEXT PRIMARY KEY,at REAL,record BLOB,mac TEXT)')
            encoded, mac = store._signed(key, value)
            db.execute('INSERT OR REPLACE INTO collector_health VALUES(?,?,?,?)',
                       (value['producer_id'],value['at'],encoded,mac))
            db.execute('DELETE FROM collector_health WHERE at<?', (time.time()-14*86400,))
            db.execute('DELETE FROM collector_health WHERE producer IN '
                       '(SELECT producer FROM collector_health ORDER BY at DESC LIMIT -1 OFFSET 256)')
    except Exception:
        pass  # Even the health channel cannot depend on healthy storage.


def read_checkpoints(store, db, key):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='collector_health'").fetchone():
        return [], 0
    return store._verified(db.execute('SELECT substr(record,1,16385),substr(mac,1,129) '
        'FROM collector_health WHERE at>=? ORDER BY at DESC LIMIT 256', (time.time()-14*86400,)).fetchall(), key)


def health_data(checkpoints, now=None):
    now = time.time() if now is None else now
    rows = []
    for index, item in enumerate(checkpoints):
        state = ('STOPPED_WITH_PENDING' if item['pending'] else 'STOPPED') if item['state'] == 'STOPPED' else (
            'STALE_OR_BLOCKED' if now-item['at'] > 15 else 'RECENT_CHECKPOINT')
        rows.append(dict(producer='producer_'+str(index+1), state=state, at=item['at'],
                         **{name:item[name] for name in COUNTERS}))
    return dict(producers=rows, scope='PRODUCER_LIFETIME; NOT_FILTERED_RUN_OR_CHAT',
                tail_coverage='UNKNOWN_AFTER_LAST_CHECKPOINT',
                lossless=False, status='OBSERVED' if rows else 'NO_CHECKPOINT')
