"""Persistent reminder choices, independent of scanner truth and repair state.

Adapters own finding authorization and evidence validation. This module owns the
small transactional decision journal; no source text is persisted here.
"""
from __future__ import annotations

import ast
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import tokenize
import uuid

from .finding_quality import digest, relative_file
from .local_evidence import WorkspaceReader

VERSION = 'risk-disposition-v1'
DISPOSITIONS = ('EXCLUDE', 'DEFER', 'RESTORE')


class DispositionUnavailable(ValueError):
    """User choices cannot be read, so an older AI view is unsafe to present."""
    reason_code = 'FEEDBACK_UNAVAILABLE'


def _workspace(value):
    return os.path.normcase(str(Path(value).resolve()))


def _until(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 100:
        raise ValueError('Deferral deadline must be an ISO timestamp with timezone')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Deferral deadline must be an ISO timestamp with timezone') from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('Deferral deadline requires a timezone')
    return parsed.astimezone(timezone.utc).isoformat()


def _safe_reason(value):
    if not isinstance(value, str) or len(value) > 4000:
        raise ValueError('Reason must be a string of at most 4000 characters')
    from .diagnostics import evidence_text
    return evidence_text(value, 4000)


_TOKENS = re.compile(r'(?P<comment>//[^\r\n]*|/\*[\s\S]*?\*/)|'
    r'(?P<string>"(?:\\[\s\S]|[^"\\])*"|\'(?:\\[\s\S]|[^\'\\])*\'|`(?:\\[\s\S]|[^`\\])*`)|'
    r'(?P<space>\s+)|(?P<token>[\w$]+|[^\w\s])')


def _tokens(text, name):
    if Path(name).suffix.lower() in ('.py', '.pyi'):
        result = []
        try:
            for item in tokenize.generate_tokens(io.StringIO(text).readline):
                if item.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
                                     tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER):
                    result.append((item.string, item.start[0], item.end[0]))
            return result
        except (tokenize.TokenError, IndentationError):
            raise ValueError('Source cannot be safely tokenized') from None
    result, line = [], 1
    for match in _TOKENS.finditer(text):
        end = line + match.group().count('\n')
        if match.lastgroup not in ('comment', 'space'):
            result.append((match.group(), line, end))
        line = end
    return result


def issue_scope(workspace, file_path, line_start, line_end=None, *, category,
                rule_id='', symbol=None):
    """Identify a specific occurrence without scan IDs, line IDs or raw code.

    Statement tokens and an enclosing symbol distinguish equivalent calls in
    different functions. A same-statement ordinal avoids excluding a sibling
    occurrence. Function tokens bind relevant guard changes while tolerating
    blank lines, comments and edits to unrelated functions.
    """
    name = relative_file(file_path)
    line_end = line_start if line_end is None else line_end
    if (type(line_start) is not int or type(line_end) is not int
            or not 1 <= line_start <= line_end):
        raise ValueError('A concrete source range is required')
    raw, text = WorkspaceReader(workspace).read(name)
    rows = text.splitlines()
    if line_end > len(rows):
        raise ValueError('Source range is unavailable')
    tokens = _tokens(text, name)
    selected_tokens = [item for item in tokens if item[1] <= line_end and item[2] >= line_start]
    if not selected_tokens:
        raise ValueError('Finding range has no source tokens')
    anchor_line = selected_tokens[0][1]
    low, high, inferred, precise, semantic = 1, len(rows), '<module>', False, None
    if Path(name).suffix.lower() in ('.py', '.pyi'):
        try:
            tree = ast.parse(text)
            scopes = [node for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                      and node.lineno <= anchor_line <= (node.end_lineno or node.lineno)]
            if scopes:
                node = min(scopes, key=lambda item: (item.end_lineno or item.lineno)-item.lineno)
                low, high = node.lineno, node.end_lineno or node.lineno
                enclosing = sorted([n for n in scopes if n.lineno <= low and
                                    (n.end_lineno or n.lineno) >= high], key=lambda n: n.lineno)
                inferred, precise = '.'.join(n.name for n in enclosing), True
                # AST structure retains control-flow indentation while dropping
                # locations, comments and formatting-only whitespace.
                semantic = ast.dump(node, include_attributes=False)
            else:
                semantic = ast.dump(tree, include_attributes=False)
        except SyntaxError:
            pass
    else:
        # Braces in strings/comments have already been removed as tokens.
        stack, containing = [], []
        for index, (value, start, end) in enumerate(tokens):
            if value == '{':
                stack.append(index)
            elif value == '}' and stack:
                opening = stack.pop()
                if tokens[opening][1] <= anchor_line <= end:
                    containing.append((opening, index))
        for opening, ending in sorted(containing, key=lambda p: p[1]-p[0]):
            header_start = max(0, opening-100)
            for index in range(opening-1, header_start-1, -1):
                if tokens[index][0] in ('}', ';', '{'):
                    header_start = index+1
                    break
            header = [item[0] for item in tokens[header_start:opening]]
            joined = ' '.join(header)
            declaration = re.search(r'(?:function\s+|(?:const|let|var)\s+)([\w$]+)', joined)
            if declaration is None:
                declaration = re.search(r'([\w$]+)\s*\([^{};]*\)\s*$', joined)
            if declaration and declaration.group(1) not in ('if', 'for', 'while', 'switch', 'catch', 'with'):
                low, high = tokens[header_start][1], tokens[ending][2]
                inferred, precise = declaration.group(1), True
                break
    selected = [item[0] for item in selected_tokens]
    scope_tokens = [item[0] for item in tokens if low <= item[1] <= high]
    matched = digest(selected)
    ordinal = 0
    for number in range(low, line_start):
        same = [item[0] for item in tokens if item[1] <= number+(line_end-line_start) and item[2] >= number]
        ordinal += bool(same and digest(same) == matched)
    identity = [VERSION, name, str(category), str(rule_id), str(symbol or inferred), matched, ordinal]
    return dict(issue_key='rd1-' + digest(identity), evidence_revision=digest(semantic or scope_tokens),
                file_sha256=hashlib.sha256(raw).hexdigest(),
                metadata=dict(file=name, symbol=str(symbol or inferred), category=str(category),
                              rule_id=str(rule_id), statement_hash=matched, ordinal=ordinal,
                              token_count=len(selected), line_span=line_end-line_start+1,
                              evidence_scope='FUNCTION' if precise else 'FILE_FALLBACK',
                              material_change_confirmable=precise))


def refresh_scope(workspace, metadata):
    """Find a previously bound statement after harmless source movement."""
    name = metadata['file']
    _, text = WorkspaceReader(workspace).read(name)
    tokens = _tokens(text, name)
    starts = {}
    for index, (_, start, _) in enumerate(tokens):
        starts.setdefault(start, index)
    wanted = metadata.get('statement_hash')
    count = metadata.get('token_count')
    candidates = []
    for number, index in starts.items():
        if not count:
            window = [item for item in tokens if item[1] <= number <= item[2]]
        else:
            window = tokens[index:index+count]
            if len(window) != count:
                continue
        if digest([item[0] for item in window]) == wanted:
            candidates.append((number, window[-1][2]))
    matched = []
    for number, end in candidates[:100]:
        scope = issue_scope(workspace, name, number, end, category=metadata['category'],
                            rule_id=metadata.get('rule_id', ''))
        if (scope['metadata']['symbol'] == metadata.get('symbol') and
                scope['metadata']['ordinal'] == metadata.get('ordinal')):
            matched.append(scope)
    if len(matched) != 1:
        raise ValueError('Previously selected source occurrence cannot be located uniquely')
    return matched[0]


class RiskDispositionStore:
    """Append-only choices plus an atomic current projection in SQLite."""
    def __init__(self, path, *, now=time.time):
        self.path = Path(path)
        self.now = now

    def _now(self):
        return datetime.fromtimestamp(self.now(), timezone.utc)

    def _read(self, query, parameters):
        if not self.path.is_file():
            return []
        try:
            # native_io_path supplies Windows extended paths for deep task
            # directories. pathlib.as_uri interprets their '?' as a UNC host;
            # strip only that transport prefix when constructing the URI.
            resolved = str(self.path.resolve())
            if resolved.startswith('\\\\?\\UNC\\'):
                resolved = '\\\\' + resolved[8:]
            elif resolved.startswith('\\\\?\\'):
                resolved = resolved[4:]
            with closing(sqlite3.connect(Path(resolved).as_uri()+'?mode=ro', uri=True)) as db:
                return db.execute(query, parameters).fetchall()
        except (sqlite3.DatabaseError, OSError):
            raise DispositionUnavailable('Saved reminder choices could not be read safely') from None

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink() or self.path.is_junction():
            raise ValueError('Invalid reminder choice database path')
        db = sqlite3.connect(self.path, timeout=30)
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS choices (workspace TEXT, issue_key TEXT, data TEXT NOT NULL, PRIMARY KEY(workspace,issue_key))')
        db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, workspace TEXT, issue_key TEXT, request_id TEXT, payload_hash TEXT, data TEXT NOT NULL, UNIQUE(workspace,request_id))')
        db.execute('CREATE TABLE IF NOT EXISTS aliases (workspace TEXT, reference TEXT, issue_key TEXT, PRIMARY KEY(workspace,reference))')
        db.execute('CREATE TABLE IF NOT EXISTS assessments (workspace TEXT, issue_key TEXT, data TEXT NOT NULL, PRIMARY KEY(workspace,issue_key))')
        db.execute('CREATE TABLE IF NOT EXISTS effect_inbox (event_id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, outcome TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS effect_sources (workspace TEXT, issue_key TEXT, source_id TEXT, revision INTEGER NOT NULL, target_revision TEXT, target_choice_revision TEXT, PRIMARY KEY(workspace,issue_key,source_id))')
        if 'target_choice_revision' not in {row[1] for row in db.execute('PRAGMA table_info(effect_sources)')}:
            db.execute('ALTER TABLE effect_sources ADD COLUMN target_choice_revision TEXT')
        db.execute('CREATE TABLE IF NOT EXISTS choice_effect_outbox (event_id TEXT PRIMARY KEY, workspace TEXT NOT NULL, data TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT)')
        return db

    @staticmethod
    def _validate_key(key):
        if not isinstance(key, str) or not 1 <= len(key) <= 200:
            raise ValueError('A bounded stable issue key is required')

    def find_reference(self, workspace, reference):
        rows = self._read('SELECT issue_key FROM aliases WHERE workspace=? AND reference=?',
                          (_workspace(workspace), reference))
        return rows[0][0] if rows else None

    def has_saved_handling(self, workspace):
        return bool(self._read('SELECT 1 FROM choices WHERE workspace=? UNION ALL '
            'SELECT 1 FROM assessments WHERE workspace=? LIMIT 1',
            (_workspace(workspace), _workspace(workspace))))

    @staticmethod
    def _event(db, workspace, issue_key, request_id, payload, event):
        payload_hash = digest(payload)
        if request_id is not None:
            prior = db.execute('SELECT payload_hash,data FROM events WHERE workspace=? AND request_id=?',
                               (workspace, request_id)).fetchone()
            if prior:
                if prior[0] != payload_hash:
                    raise ValueError('Request ID already belongs to a different reminder choice')
                return json.loads(prior[1]), False
        db.execute('INSERT INTO events(workspace,issue_key,request_id,payload_hash,data) VALUES (?,?,?,?,?)',
                   (workspace, issue_key, request_id, payload_hash, json.dumps(event)))
        return event, True

    @staticmethod
    def _metadata(metadata):
        metadata = {} if metadata is None else metadata
        if not isinstance(metadata, dict) or len(json.dumps(metadata)) > 8000:
            raise ValueError('Invalid bounded decision metadata')
        # Only adapter-generated locators and digests belong in metadata.
        return metadata

    def set(self, workspace, issue_key, disposition, reason='', *, user_requested=False,
            until=None, request_id=None, evidence_revision=None, metadata=None, effects=()):
        if user_requested is not True:
            raise ValueError('A direct user request is required for this reminder choice')
        self._validate_key(issue_key)
        if disposition not in DISPOSITIONS:
            raise ValueError('Disposition must be EXCLUDE, DEFER or RESTORE')
        if until is not None and disposition != 'DEFER':
            raise ValueError('Only DEFER supports a deadline')
        if request_id is not None and (not isinstance(request_id, str) or not 1 <= len(request_id) <= 200):
            raise ValueError('Invalid reminder choice request ID')
        # Normalize once before the transaction. Retrying an ISO timestamp with
        # different offset spelling is still the same requested deadline.
        deadline = _until(until)
        reason, metadata = _safe_reason(reason), self._metadata(metadata)
        effects = tuple(effects)
        if len(effects) > 4:
            raise ValueError('Decision effect capacity exceeded')
        for effect in effects:
            if (not isinstance(effect, dict) or set(effect) != {'kind', 'payload'}
                    or effect['kind'] != 'RELEASE_NATIVE_INTENT' or not isinstance(effect['payload'], dict)
                    or set(effect['payload']) != {'owner', 'source', 'intent_sha256'}
                    or len(json.dumps(effect, ensure_ascii=False).encode()) > 16_000):
                raise ValueError('Invalid decision effect template')
        workspace = _workspace(workspace)
        payload = dict(issue_key=issue_key, disposition=disposition, reason=reason,
                       until=deadline, evidence_revision=evidence_revision, metadata=metadata)
        event = dict(payload, event_id=uuid.uuid4().hex, event_kind='USER_DISPOSITION',
                     created_at=self._now().isoformat(), user_requested=True)
        with closing(self._connect()) as db, db:
            event, inserted = self._event(db, workspace, issue_key, request_id, payload, event)
            if inserted:
                # A retry may arrive after its already-saved deadline. Only a
                # new decision needs a future deadline; the transaction rolls
                # back this new journal event if validation fails.
                if deadline and datetime.fromisoformat(deadline) <= self._now():
                    raise ValueError('Deferral deadline must be in the future')
                state = dict(event, reopened=False)
                db.execute('INSERT OR REPLACE INTO choices VALUES (?,?,?)',
                           (workspace, issue_key, json.dumps(state)))
                if metadata.get('reference'):
                    db.execute('INSERT OR REPLACE INTO aliases VALUES (?,?,?)',
                               (workspace, metadata['reference'], issue_key))
                for template in effects:
                    if disposition not in {'DEFER', 'EXCLUDE'}:
                        raise ValueError('Only a saved pause decision releases its workflow')
                    from .persistence_effects import digest as effect_digest
                    effect = dict(contract='native-intent-release-v1', decision_event_id=event['event_id'],
                        kind=template['kind'], payload=template['payload'])
                    effect['event_id'] = 'nie1-'+effect_digest(effect)
                    db.execute('INSERT INTO choice_effect_outbox VALUES (?,?,?,?,?)',
                        (effect['event_id'], workspace, json.dumps(effect), 'PENDING', None))
        return self.status(workspace, issue_key, current_revision=evidence_revision, include_history=True)

    def status(self, workspace, issue_key, *, current_revision=None, include_history=False):
        self._validate_key(issue_key)
        workspace = _workspace(workspace)
        rows = self._read('SELECT data FROM choices WHERE workspace=? AND issue_key=?', (workspace, issue_key))
        choice = json.loads(rows[0][0]) if rows else None
        rows = self._read('SELECT data FROM assessments WHERE workspace=? AND issue_key=?', (workspace, issue_key))
        assessment = json.loads(rows[0][0]) if rows else None
        active = bool(choice and choice['disposition'] in ('EXCLUDE', 'DEFER') and not choice.get('reopened'))
        expired = bool(active and choice.get('until') and datetime.fromisoformat(choice['until']) <= self._now())
        active = active and not expired
        auto = bool(assessment and assessment.get('automatic_exclusion') and current_revision is not None and
                    current_revision == assessment.get('exclusion_revision'))
        # A later model opinion never overrides a user's explicit restore.
        # The user can exclude again; technical assessment remains separate.
        if choice and choice['disposition'] == 'RESTORE':
            auto = False
        baseline = choice.get('evidence_revision') if active else assessment.get('exclusion_revision') if auto else None
        changed = bool(baseline and current_revision != baseline or
                       active and choice.get('metadata', {}).get('historical_only'))
        result = dict(contract=VERSION, issue_key=issue_key,
                      disposition=choice['disposition'] if choice else None,
                      active=active, suppressed=active or auto, automatic_excluded=auto,
                      reassessment_required=changed, expired=expired,
                      until=choice.get('until') if choice else None,
                      reason=choice.get('reason', '') if choice else '',
                      recorded_at=choice.get('created_at') if choice else None,
                      event_id=choice.get('event_id') if choice else None,
                      decision=choice, technical_assessment=assessment,
                      raw_findings_changed=False, fix_authorized=False, repair_authorized=False)
        if include_history:
            result['history'] = [json.loads(row[0]) for row in self._read(
                'SELECT data FROM events WHERE workspace=? AND issue_key=? ORDER BY id', (workspace, issue_key))]
        return result

    def confirm_material_change(self, workspace, issue_key, revision, *, assessment_id,
                                verdict, fresh=False, evidence_backed=False):
        if verdict != 'STILL_RISK' or fresh is not True or evidence_backed is not True or not revision:
            return self.status(workspace, issue_key, current_revision=revision)
        workspace = _workspace(workspace)
        with closing(self._connect()) as db, db:
            self._confirm_material_change(db, workspace, issue_key, revision,
                assessment_id=assessment_id, verdict=verdict, fresh=fresh, evidence_backed=evidence_backed)
        return self.status(workspace, issue_key, current_revision=revision)

    def _confirm_material_change(self, db, workspace, issue_key, revision, *, assessment_id,
                                 verdict, fresh=False, evidence_backed=False):
        """Apply a checked reassessment in the caller's authority transaction."""
        if verdict != 'STILL_RISK' or fresh is not True or evidence_backed is not True or not revision:
            return
        row = db.execute('SELECT data FROM choices WHERE workspace=? AND issue_key=?', (workspace, issue_key)).fetchone()
        choice = json.loads(row[0]) if row else None
        if (choice and choice['disposition'] in ('EXCLUDE', 'DEFER') and not choice.get('reopened')
                and choice.get('evidence_revision') and choice['evidence_revision'] != revision):
            choice.update(reopened=True, reopened_revision=revision,
                          reassessed_at=self._now().isoformat(), reassessment_id=assessment_id)
            event = dict(event_kind='MATERIAL_RISK_CHANGE', event_id=uuid.uuid4().hex,
                         created_at=choice['reassessed_at'], assessment_id=assessment_id,
                         evidence_revision=revision, previous_decision=choice['event_id'])
            self._event(db, workspace, issue_key, 'reassessment:'+assessment_id,
                        dict(issue_key=issue_key, revision=revision), event)
            db.execute('UPDATE choices SET data=? WHERE workspace=? AND issue_key=?',
                       (json.dumps(choice), workspace, issue_key))

    def record_assessment(self, workspace, issue_key, verdict, evidence_revision, *,
                          assessment_id, fresh=False, evidence_backed=False, metadata=None):
        self._validate_key(issue_key)
        if verdict not in ('FALSE_POSITIVE', 'STILL_RISK', 'NEEDS_CONTEXT'):
            raise ValueError('Invalid technical assessment')
        metadata = self._metadata(metadata)
        workspace = _workspace(workspace)
        with closing(self._connect()) as db, db:
            self._record_assessment(db, workspace, issue_key, verdict, evidence_revision,
                assessment_id=assessment_id, fresh=fresh, evidence_backed=evidence_backed, metadata=metadata)
        return self.status(workspace, issue_key, current_revision=evidence_revision)

    def _record_assessment(self, db, workspace, issue_key, verdict, evidence_revision, *,
                           assessment_id, fresh=False, evidence_backed=False, metadata=None):
        row = db.execute('SELECT data FROM assessments WHERE workspace=? AND issue_key=?', (workspace, issue_key)).fetchone()
        old = json.loads(row[0]) if row else {}
        auto = bool(old.get('automatic_exclusion'))
        revision = old.get('exclusion_revision')
        if fresh is True and evidence_backed is True and evidence_revision:
            if verdict == 'FALSE_POSITIVE':
                auto, revision = True, evidence_revision
            elif verdict == 'STILL_RISK' and evidence_revision != revision:
                auto = False
        assessment = dict(verdict=verdict, evidence_revision=evidence_revision,
                          assessment_id=assessment_id, fresh=fresh is True,
                          evidence_backed=evidence_backed is True, metadata=metadata,
                          created_at=self._now().isoformat(), automatic_exclusion=auto,
                          exclusion_revision=revision)
        db.execute('INSERT OR REPLACE INTO assessments VALUES (?,?,?)',
                   (workspace, issue_key, json.dumps(assessment)))
        if metadata.get('reference'):
            db.execute('INSERT OR REPLACE INTO aliases VALUES (?,?,?)',
                       (workspace, metadata['reference'], issue_key))
        if metadata.get('material_change_confirmable') is True:
            self._confirm_material_change(db, workspace, issue_key, evidence_revision,
                assessment_id=assessment_id, verdict=verdict, fresh=fresh, evidence_backed=evidence_backed)

    def clear_assessment(self, workspace, issue_key):
        """Revoke an AI assessment without altering a human reminder choice."""
        workspace = _workspace(workspace)
        if not self.path.exists():
            return
        with closing(self._connect()) as db, db:
            row = db.execute('SELECT data FROM assessments WHERE workspace=? AND issue_key=?',
                             (workspace, issue_key)).fetchone()
            if row:
                assessment = dict(json.loads(row[0]), revoked=True, automatic_exclusion=False)
                db.execute('UPDATE assessments SET data=? WHERE workspace=? AND issue_key=?',
                           (json.dumps(assessment), workspace, issue_key))

    @staticmethod
    def _pending_effect_filter(workspace, owner, ready_only):
        query = "workspace=? AND state='PENDING'"
        arguments = [_workspace(workspace)]
        if owner is not None:
            from .tasks.ownership import valid_owner
            if not valid_owner(owner):
                raise ValueError('Invalid decision recovery owner')
            query += " AND json_extract(data,'$.payload.owner.host')=? AND json_extract(data,'$.payload.owner.session')=?"
            arguments.extend((owner['host'], owner['session']))
        if type(ready_only) is not bool:
            raise ValueError('Invalid decision recovery readiness')
        if ready_only:
            query += (" AND json_type(data,'$.payload.intent_sha256')='text'"
                " AND length(json_extract(data,'$.payload.intent_sha256'))=64"
                " AND json_extract(data,'$.payload.intent_sha256') NOT GLOB '*[^0-9a-f]*'")
        return query, arguments

    def pending_effects(self, workspace, limit=16, *, owner=None, ready_only=False):
        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError('Invalid decision recovery limit')
        query, arguments = self._pending_effect_filter(workspace, owner, ready_only)
        if not self.path.is_file():
            return []
        from .closeout_state import readonly_uri
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='choice_effect_outbox'").fetchone():
                return []
            return [json.loads(r[0]) for r in db.execute(
                'SELECT data FROM choice_effect_outbox WHERE '+query+' ORDER BY rowid LIMIT ?',
                (*arguments, limit))]

    def pending_effect_count(self, workspace, *, owner=None, ready_only=False):
        query, arguments = self._pending_effect_filter(workspace, owner, ready_only)
        if not self.path.is_file():
            return 0
        from .closeout_state import readonly_uri
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='choice_effect_outbox'").fetchone():
                return 0
            return db.execute('SELECT COUNT(*) FROM choice_effect_outbox WHERE '+query, arguments).fetchone()[0]

    def acknowledge_effect(self, event_id, outcome):
        if outcome not in {'APPLIED', 'SUPERSEDED'} or not re.fullmatch(r'nie1-[a-f0-9]{64}', event_id):
            raise ValueError('Invalid decision effect acknowledgement')
        with closing(self._connect()) as db, db:
            db.execute("UPDATE choice_effect_outbox SET state='APPLIED',outcome=? WHERE event_id=? AND state='PENDING'",
                       (outcome, event_id))

    @staticmethod
    def _effect_versions(db, workspace, issue_key):
        from .persistence_effects import digest as effect_digest
        row = db.execute('SELECT (SELECT data FROM choices WHERE workspace=? AND issue_key=?), '
            '(SELECT data FROM assessments WHERE workspace=? AND issue_key=?)',
            (workspace, issue_key, workspace, issue_key)).fetchone()
        choice = json.loads(row[0]) if row[0] else None
        assessment = json.loads(row[1]) if row[1] else None
        return dict(choice_event_id=choice.get('event_id') if choice else None,
            assessment_id=assessment.get('assessment_id') if assessment else None,
            choice_revision=effect_digest(choice) if choice else None,
            assessment_revision=effect_digest(assessment) if assessment else None)

    def effect_versions(self, workspace, issue_key):
        """One read snapshot; no tables, keys, replay, scans or decisions created."""
        self._validate_key(issue_key)
        if not self.path.is_file():
            return dict(choice_event_id=None, assessment_id=None, choice_revision=None, assessment_revision=None)
        from .closeout_state import readonly_uri
        with closing(sqlite3.connect(readonly_uri(self.path), uri=True)) as db:
            db.execute('PRAGMA query_only=ON')
            return self._effect_versions(db, _workspace(workspace), issue_key)

    def apply_effect(self, effect):
        """Atomically materialize a fact and its inbox receipt, preserving newer choices."""
        from .persistence_effects import validate_effect
        validate_effect(effect)
        workspace, issue = effect['workspace'], effect['issue_key']
        payload, source = effect['payload'], effect['source']
        with closing(self._connect()) as db, db:
            prior = db.execute('SELECT payload_hash,outcome FROM effect_inbox WHERE event_id=?',
                               (effect['event_id'],)).fetchone()
            if prior:
                if prior[0] != effect['payload_sha256']:
                    raise ValueError('Persistence effect receipt mismatch')
                return dict(event_id=effect['event_id'], outcome=prior[1], already_applied=True)
            watermark = db.execute('SELECT revision,target_revision,target_choice_revision FROM effect_sources WHERE workspace=? AND issue_key=? AND source_id=?',
                (workspace, issue, source['id'])).fetchone()
            current = self._effect_versions(db, workspace, issue)
            outcome = 'SUPERSEDED'
            expected = effect['expected']
            choice_matches = all(current[k] == expected[k] for k in ('choice_event_id', 'choice_revision'))
            assessment_matches = all(current[k] == expected[k] for k in ('assessment_id', 'assessment_revision'))
            # Accept only this source's exact prior projection. Reopening a
            # reminder is also a derived choice mutation; its hash must be owned
            # by the watermark and its original human event must remain unchanged.
            # Missing legacy watermark fields never imply ownership.
            own_advance = bool(watermark and watermark[1] is not None
                               and watermark[1] == current['assessment_revision'])
            own_choice_advance = bool(watermark and watermark[2] is not None
                and current['choice_event_id'] == expected['choice_event_id']
                and watermark[2] == current['choice_revision'])
            if ((not watermark or source['revision'] > watermark[0])
                    and (choice_matches or own_choice_advance)
                    and (assessment_matches or own_advance)):
                if effect['kind'] == 'ASSESSMENT':
                    if (set(payload) != {'verdict', 'evidence_revision', 'assessment_id', 'fresh', 'evidence_backed', 'metadata'}
                            or payload['verdict'] not in ('FALSE_POSITIVE', 'STILL_RISK', 'NEEDS_CONTEXT')
                            or any(type(payload[f]) is not bool for f in ('fresh', 'evidence_backed'))):
                        raise ValueError('Invalid persistence assessment payload')
                    self._record_assessment(db, workspace, issue, metadata=self._metadata(payload['metadata']),
                        **{k: v for k, v in payload.items() if k != 'metadata'})
                elif effect['kind'] == 'CLEAR_ASSESSMENT':
                    if payload:
                        raise ValueError('Invalid persistence clear payload')
                    row = db.execute('SELECT data FROM assessments WHERE workspace=? AND issue_key=?', (workspace, issue)).fetchone()
                    if row:
                        assessment = dict(json.loads(row[0]), revoked=True, automatic_exclusion=False)
                        db.execute('UPDATE assessments SET data=? WHERE workspace=? AND issue_key=?',
                                   (json.dumps(assessment), workspace, issue))
                else:
                    if set(payload) != {'revision', 'assessment_id', 'verdict', 'fresh', 'evidence_backed'}:
                        raise ValueError('Invalid persistence material-change payload')
                    self._confirm_material_change(db, workspace, issue, **payload)
                outcome = 'APPLIED'
            if not watermark or source['revision'] > watermark[0]:
                target = self._effect_versions(db, workspace, issue) if outcome == 'APPLIED' else None
                target_revision = target['assessment_revision'] if target else watermark[1] if watermark else None
                choice_revision = target['choice_revision'] if target else watermark[2] if watermark else None
                db.execute('INSERT OR REPLACE INTO effect_sources '
                    '(workspace,issue_key,source_id,revision,target_revision,target_choice_revision) VALUES (?,?,?,?,?,?)',
                    (workspace, issue, source['id'], source['revision'], target_revision, choice_revision))
            db.execute('INSERT INTO effect_inbox VALUES (?,?,?)',
                       (effect['event_id'], effect['payload_sha256'], outcome))
        return dict(event_id=effect['event_id'], outcome=outcome, already_applied=False)


def source_revision(workspace, name):
    _, text = WorkspaceReader(workspace).read(name)
    if Path(name).suffix.lower() in ('.py', '.pyi'):
        try:
            return digest(ast.dump(ast.parse(text), include_attributes=False))
        except SyntaxError:
            pass
    return digest([item[0] for item in _tokens(text, name)])
