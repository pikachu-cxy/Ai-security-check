"""Transactional scanner feedback outbox; retrying never scans or grants edits."""
from __future__ import annotations
from contextlib import closing
import json
import sqlite3
from .closeout_state import readonly_uri
from .persistence_effects import digest, make_effect, validate_effect

MAX_PENDING = 1000

def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS finding_effects (event_id TEXT PRIMARY KEY, workspace TEXT NOT NULL, issue_key TEXT NOT NULL, data TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT)')
    if 'attempted' not in {r[1] for r in db.execute('PRAGMA table_info(finding_effects)')}:
        db.execute('ALTER TABLE finding_effects ADD COLUMN attempted INTEGER NOT NULL DEFAULT 0')
    db.execute('CREATE INDEX IF NOT EXISTS finding_effect_recovery ON finding_effects(workspace,state,attempted)')

def append_reviews(db, authority_path, workspace, scan_id, records, effects):
    if effects is not None and len(records) != len(effects):
        raise ValueError('Feedback effects must match their authority records')
    initialize(db)
    pending = db.execute("SELECT COUNT(*) FROM finding_effects WHERE state='PENDING'").fetchone()[0]
    if effects and pending + sum(v is not None for v in effects) > MAX_PENDING:
        raise ValueError('Pending feedback effect capacity exceeded')
    for number, record in enumerate(records):
        cursor = db.execute('INSERT INTO finding_reviews(workspace,scan_id,data) VALUES (?,?,?)',
                            (workspace, scan_id, json.dumps(record)))
        template = effects[number] if effects is not None else None
        if template is None:
            continue
        source_id = 'scanner-feedback:'+digest([str(authority_path.resolve()), workspace, template['issue_key']])
        effect = make_effect(source_id=source_id, source_revision=cursor.lastrowid,
            workspace=workspace, **template)
        db.execute('INSERT INTO finding_effects(event_id,workspace,issue_key,data,state,outcome) VALUES (?,?,?,?,?,?)',
            (effect['event_id'], effect['workspace'], effect['issue_key'], json.dumps(effect), 'PENDING', None))

def pending(path, workspace, *, limit=16, issue_key=None):
    if type(limit) is not int or not 1 <= limit <= 32:
        raise ValueError('Invalid feedback recovery limit')
    if not path.is_file():
        return []
    import os
    from pathlib import Path
    workspace = os.path.normcase(str(Path(workspace).resolve()))
    with closing(sqlite3.connect(readonly_uri(path), uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='finding_effects'").fetchone():
            return []
        query = "SELECT data FROM finding_effects WHERE workspace=? AND state='PENDING'"
        args = [workspace]
        if issue_key is not None:
            query += ' AND issue_key=?'
            args.append(issue_key)
        order = 'attempted,rowid' if 'attempted' in {r[1] for r in db.execute('PRAGMA table_info(finding_effects)')} else 'rowid'
        values = [json.loads(r[0]) for r in db.execute(query+' ORDER BY '+order+' LIMIT ?', (*args, limit))]
        for value in values:
            validate_effect(value)
        return values

def acknowledge(db, effect, outcome):
    validate_effect(effect)
    if outcome not in {'APPLIED', 'SUPERSEDED'}:
        raise ValueError('Invalid feedback projection outcome')
    db.execute("UPDATE finding_effects SET state='APPLIED',outcome=? WHERE event_id=? AND data=? AND state='PENDING'",
               (outcome, effect['event_id'], json.dumps(effect)))

def mark_attempt(db, effect):
    validate_effect(effect)
    initialize(db)
    sequence = db.execute("SELECT COALESCE(MAX(attempted),0)+1 FROM finding_effects WHERE state='PENDING'").fetchone()[0]
    db.execute("UPDATE finding_effects SET attempted=? WHERE event_id=? AND data=? AND state='PENDING'",
               (sequence, effect['event_id'], json.dumps(effect)))


def reconcile(store, dispositions, workspace, *, limit=16):
    values = pending(store.path, workspace, limit=limit)
    applied, failed = 0, 0
    for effect in values:
        try:
            # Fair bounded recovery: an unavailable issue cannot permanently
            # occupy the first page ahead of unrelated pending facts.
            store.mark_finding_effect_attempt(effect)
            result = dispositions.apply_effect(effect)
            # Target receipt committed before source acknowledgement. A crash
            # replays only the same event, not scans or a newer user decision.
            store.acknowledge_finding_effect(effect, result['outcome'])
            applied += 1
        except (OSError, ValueError, sqlite3.DatabaseError):
            failed += 1
    return dict(applied=applied, failed=failed,
                more_pending=bool(pending(store.path, workspace, limit=1)))
