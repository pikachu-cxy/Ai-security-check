"""Finite pre-edit impact reasoning. Runtime validates evidence, never reasoning.

The host resolves existing scanner/native risks and performs the reasoning. This
service neither starts a task/scan nor creates, consumes or extends a repair grant.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import time
import uuid

from .local_evidence import WorkspaceReader
from .hook_state import no_links
from .repair_impact_models import (ACTIVITY_SECONDS, CONTRACT, MATERIAL_SECONDS,
    MAX_FILES, RESPONSE_BYTES, WINDOW_LINES, RepairImpactError, digest, encoded,
    path, proposal as clean_proposal, reasoning, require, source as clean_source, text, wire_bytes)
from .repair_impact_context import allocate, charge, new_ledger, read_source, unread
from .repair_impact_store import RepairImpactStore


def _logical_path(value):
    """Compare one filesystem location independent of Windows IO spelling."""
    candidate = Path(value).absolute()
    no_links(candidate)  # Check lexical ancestors before canonicalization.
    spelling = str(candidate.resolve(strict=False))
    if os.name == 'nt':
        if spelling.startswith('\\\\?\\UNC\\'):
            spelling = '\\\\'+spelling[8:]
        elif spelling.startswith('\\\\?\\'):
            spelling = spelling[4:]
    return Path(spelling)


class RepairImpactService:
    def __init__(self, workspace, directory, owner, resolve_source, *, now=time.time):
        self.reader = WorkspaceReader(workspace)
        self.root = self.reader.root
        require(isinstance(owner, dict) and set(owner) == {'host', 'session'} and
                all(isinstance(v, str) and 0 < len(v) <= 256 for v in owner.values()),
                'REPAIR_IMPACT_OWNER_REQUIRED')
        self.owner = digest(owner)
        logical_root = _logical_path(self.root)
        self.workspace = digest(str(logical_root).casefold())
        require(not _logical_path(directory).is_relative_to(logical_root),
                'REPAIR_IMPACT_PRIVATE_STORAGE_REQUIRED')
        self.store = RepairImpactStore(directory)
        self.resolve_source = resolve_source
        self.now = now

    def _time(self):
        value = self.now()
        require(type(value) in (int, float) and math.isfinite(value), 'REPAIR_IMPACT_CLOCK_INVALID')
        return value

    def _resolve(self, source):
        try:
            result = self.resolve_source(copy.deepcopy(source))
        except RepairImpactError:
            raise
        except Exception:
            raise RepairImpactError('REPAIR_IMPACT_SOURCE_UNRESOLVED') from None
        require(isinstance(result, dict) and isinstance(result.get('binding'), dict) and
                isinstance(result.get('source_paths'), list), 'REPAIR_IMPACT_SOURCE_UNRESOLVED')
        require(result['binding'].get('kind') == source['kind'] and
                result['binding'].get('task_ref') == source['task_ref'],
                'REPAIR_IMPACT_SOURCE_BINDING_MISMATCH')
        if source['kind'] == 'HOST_TASK_RISK':
            require(result['binding'].get('finding_id') == source['finding_id'] and
                    type(result['binding'].get('origin_review_revision')) is int and
                    isinstance(result['binding'].get('origin_snapshot_id'), str),
                    'REPAIR_IMPACT_ORIGIN_REVISION_REQUIRED')
            if 'origin_review_revision' in source:
                require(source['origin_review_revision'] == result['binding']['origin_review_revision'],
                        'REPAIR_IMPACT_SOURCE_BINDING_MISMATCH')
        require(len(encoded(result['binding'])) <= 16_000 and
                0 < len(result['source_paths']) <= MAX_FILES,
                'REPAIR_IMPACT_SOURCE_UNRESOLVED')
        return result

    def _sources(self, resolved, proposal):
        reasons = {c['file_path']: c['reason'] for c in proposal['changes']}
        names = set(resolved['source_paths']) | set(reasons)
        require(len(names) <= MAX_FILES, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
        ranges = resolved.get('secret_ranges', {})
        require(isinstance(ranges, dict), 'REPAIR_IMPACT_SOURCE_UNRESOLVED')
        sources, truncated = {}, {}
        for name in names:
            name, sha, lines, cut = read_source(self.reader, name, ranges.get(name, ()),
                                               documentation=bool(reasons.get(name)))
            sources[name] = (sha, lines)
            if cut:
                truncated[name] = cut
        windows = []
        required = list(resolved.get('required_windows') or []) + list(proposal['changes'])
        specified = {w.get('file_path') for w in required if isinstance(w, dict)}
        required.extend(dict(file_path=n, start_line=1, end_line=len(sources[n][1]))
                        for n in names-specified)
        for item in required:
            require(isinstance(item, dict), 'REPAIR_IMPACT_SOURCE_UNRESOLVED')
            name = item.get('file_path')
            require(name in sources, 'REPAIR_IMPACT_SOURCE_UNRESOLVED')
            low, high = item.get('start_line'), item.get('end_line')
            require(type(low) is int and type(high) is int and
                    1 <= low <= high <= len(sources[name][1]), 'REPAIR_IMPACT_RANGE_UNAVAILABLE')
            value = dict(file_path=name, start_line=low, end_line=high, file_sha256=sources[name][0])
            if value not in windows:
                windows.append(value)
        return sources, windows, truncated

    def _known_secrets(self, resolved):
        """Ephemeral exact-value scrub; matched credentials never enter metadata."""
        values = set()
        ranges = resolved.get('secret_ranges', {})
        require(isinstance(ranges, dict) and len(ranges) <= MAX_FILES,
                'REPAIR_IMPACT_SOURCE_UNRESOLVED')
        for name, spans in ranges.items():
            name = path(name)
            require(isinstance(spans, (list, tuple)) and len(spans) <= 64,
                    'REPAIR_IMPACT_SOURCE_UNRESOLVED')
            try:
                _, raw_text = self.reader.read(name)
            except (OSError, ValueError):
                raise RepairImpactError('REPAIR_IMPACT_SECRET_CONTEXT_UNAVAILABLE') from None
            lines = raw_text.splitlines()
            for span in spans:
                require(isinstance(span, (list, tuple)) and len(span) == 2 and
                        all(type(n) is int for n in span) and 1 <= span[0] <= span[1] <= len(lines),
                        'REPAIR_IMPACT_SOURCE_UNRESOLVED')
                for line in lines[span[0]-1:span[1]]:
                    values.update(re.findall(r'[\"\']([^\"\'\r\n]{4,})[\"\']', line))
                    match = re.search(r'[:=]\s*([^\s,;]{4,})', line)
                    if match:
                        values.add(match.group(1).strip('\"\''))
        return sorted((v for v in values if len(v) >= 4), key=len, reverse=True)

    def _scrub(self, value, secrets, field=None):
        if isinstance(value, str):
            if field not in {'file_path', 'evidence_refs', 'kind', 'decision', 'proposal_revision'}:
                for secret in secrets:
                    value = value.replace(secret, '[REDACTED_SECRET]')
            return value
        if isinstance(value, list):
            return [self._scrub(v, secrets, field) for v in value]
        if isinstance(value, dict):
            return {k:self._scrub(v, secrets, k) for k,v in value.items()}
        return value

    def _secret_markers(self, values):
        require(len(values) <= 128, 'REPAIR_IMPACT_SECRET_CONTEXT_CAPACITY')
        key = self.store._key()
        return [dict(size=len(v), digest=hmac.new(key, v.encode(), hashlib.sha256).hexdigest())
                for v in values if len(v) <= 800]

    def _scrub_marked(self, value, markers, field=None):
        if isinstance(value, str):
            if field in {'file_path', 'evidence_refs', 'kind', 'decision', 'proposal_revision'}:
                return value
            key, spans, by_size = self.store._key(), [], {}
            for marker in markers:
                by_size.setdefault(marker['size'], set()).add(marker['digest'])
            for size, fingerprints in by_size.items():
                for offset in range(max(0, len(value)-size+1)):
                    token = value[offset:offset+size]
                    if hmac.new(key, token.encode(), hashlib.sha256).hexdigest() in fingerprints:
                        spans.append((offset, offset+size))
            # Merge overlaps before replacement so one secret substring cannot
            # shift another replacement into previously unmasked source text.
            merged = []
            for start, end in sorted(spans):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(end, merged[-1][1])
                else:
                    merged.append([start, end])
            for start, end in reversed(merged):
                value = value[:start]+'[REDACTED_SECRET]'+value[end:]
            return value
        if isinstance(value, list):
            return [self._scrub_marked(v, markers, field) for v in value]
        if isinstance(value, dict):
            return {k:self._scrub_marked(v, markers, k) for k,v in value.items()}
        return value

    def _record(self, db, ref, *, owned=True):
        require(isinstance(ref, str) and re.fullmatch(r'ria1-[a-f0-9]{32}', ref),
                'REPAIR_IMPACT_REFERENCE_INVALID')
        record = self.store.load(db, 'assessments', ref)
        require(record is not None and record.get('workspace') == self.workspace,
                'REPAIR_IMPACT_REFERENCE_INVALID')
        if owned:
            require(record['owner'] == self.owner, 'REPAIR_IMPACT_OWNER_MISMATCH')
        cycle = self.store.load(db, 'cycles', record['cycle_id'])
        require(cycle is not None, 'REPAIR_IMPACT_STORAGE_UNAVAILABLE')
        return record, cycle

    def _fresh(self, record):
        now = self._time()
        if now < record['created_at'] or now > record['material_expires_at']:
            return False
        try:
            resolved = self._resolve(record['source'])
            if digest(resolved['binding']) != record['binding_digest']:
                return False
            for name, expected in record['source_hashes'].items():
                _, sha, _, _ = read_source(self.reader, name,
                    resolved.get('secret_ranges', {}).get(name, ()),
                    documentation=name in record['document_reasons'])
                if sha != expected:
                    return False
        except (RepairImpactError, OSError, ValueError):
            return False
        return True

    def _active(self, record):
        now = self._time()
        require(now >= record['last_progress_at'], 'REPAIR_IMPACT_CLOCK_INVALID')
        require(now <= record['activity_expires_at'], 'REPAIR_IMPACT_IDLE_RESUME_REQUIRED')

    def _progress(self, record):
        now = self._time()
        require(now >= record['last_progress_at'], 'REPAIR_IMPACT_CLOCK_INVALID')
        record.update(last_progress_at=now, activity_expires_at=now+ACTIVITY_SECONDS)

    @staticmethod
    def _choice_basis(impacts):
        # Evidence identifiers and report revisions are not business semantics.
        return digest([{k:v for k,v in item.items() if k != 'evidence_refs'} for item in impacts
                       if item['kind'] == 'BUSINESS_BEHAVIOR_CHANGE'])

    def _save(self, db, record, cycle):
        self.store.save(db, 'cycles', record['cycle_id'], cycle)
        self.store.save(db, 'assessments', record['assessment_ref'], record, cycle_id=record['cycle_id'])

    def _terminal(self, record, cycle, reason):
        """Saving bounded reasoning never requires more source/delivery quota."""
        return dict(contract=CONTRACT, status='REPAIR_IMPACT_RESULT_SAVED', result_saved=True,
            assessment_ref=record['assessment_ref'], revision=record['revision'],
            gate=self._gate(record, fresh=self._fresh(record) and
                           cycle['latest'] == record['assessment_ref']), reason_code=reason,
            impact_count=len(record['impacts']), unknown_count=len(record['unknowns']),
            repair_authorized=False, automatic_execution=False,
            result_details_required=True,
            next_action=dict(tool='get_repair_impact', assessment_ref=record['assessment_ref'], offset=0))

    def _gate(self, record, *, fresh=True):
        if not fresh:
            return 'REASSESS_REQUIRED'
        if record['coverage'] != 'REVIEWED' or unread(record) or record.get('capacity_required'):
            return 'CRITICAL_CONTEXT_MISSING'
        if any(v['critical'] for v in record['unknowns']) or record.get('truncated_ranges'):
            return 'CRITICAL_CONTEXT_MISSING'
        if any(v['kind'] == 'UNDETERMINED' for v in record['impacts']):
            return 'CRITICAL_CONTEXT_MISSING'
        if any(v['kind'] == 'BUSINESS_BEHAVIOR_CHANGE' for v in record['impacts']):
            choice = record['business_choice']
            if not choice or choice.get('impact_basis') != self._choice_basis(record['impacts']):
                return 'BUSINESS_CHOICE_REQUIRED'
        return 'READY_FOR_EXISTING_AUTH'

    def _view(self, record, cycle, *, fresh=True, offset=0, limit=5):
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 10)
        out = {key: copy.deepcopy(record[key]) for key in
               ('assessment_ref', 'revision', 'source', 'proposal', 'proposal_revision',
                'coverage', 'created_at', 'material_expires_at', 'activity_expires_at')}
        out['proposal']['changes'] = []
        gate = self._gate(record, fresh=fresh and cycle['latest'] == record['assessment_ref'])
        lifecycle = ('STALE' if not fresh else 'CURRENT' if record['submitted'] and
                     record['coverage'] == 'REVIEWED' and not unread(record) else
                     'PARTIAL' if record['submitted'] else 'DRAFT')
        out.update(contract=CONTRACT, status='REPAIR_IMPACT_ASSESSMENT', gate=gate,
            lifecycle=lifecycle, source_binding=copy.deepcopy(record['source_binding']),
            owner_matches=record['owner'] == self.owner, repair_authorized=False,
            automatic_execution=False, scanner_run=False, source_modified=False,
            analysis_trust='HOST_ANALYSIS_NOT_SCANNER_PROOF', business_choice=record['business_choice'],
            ledger={key: copy.deepcopy(cycle['ledger'][key]) for key in
                    ('source_bytes', 'navigation_bytes', 'control_bytes', 'reads', 'category_limits')},
            capacity_required=bool(record.get('capacity_required')))
        out['superseded'] = cycle['latest'] != record['assessment_ref']
        out['redaction'] = 'CONSERVATIVE_LITERALS_AND_KNOWN_SECRET_RANGES'
        out['limitations'] = ['Hidden literal values and unread context cannot prove behavior preservation.',
                              'Accepted host analysis is not a scanner or compatibility proof.']
        rows = ([dict(row_type='IMPACT', **v) for v in record['impacts']] +
                [dict(row_type='UNKNOWN', **v) for v in record['unknowns']] +
                [dict(row_type='REQUIRED_WINDOW', **v) for v in record['required_windows']] +
                [dict(row_type='UNREAD_WINDOW', **v) for v in unread(record)] +
                [dict(row_type='PROPOSAL_CHANGE', **v) for v in record['proposal']['changes']])
        selected = rows[offset:offset+limit]
        out.update(items=selected, impacts=[{k:v for k,v in r.items() if k != 'row_type'}
                   for r in selected if r['row_type'] == 'IMPACT'],
                   unknowns=[{k:v for k,v in r.items() if k != 'row_type'}
                   for r in selected if r['row_type'] == 'UNKNOWN'],
                   required_windows=[{k:v for k,v in r.items() if k != 'row_type'}
                   for r in selected if r['row_type'] == 'REQUIRED_WINDOW'],
                   unread_windows=[{k:v for k,v in r.items() if k != 'row_type'}
                   for r in selected if r['row_type'] == 'UNREAD_WINDOW'],
                   unread_window_count=len(unread(record)), impact_count=len(record['impacts']),
                   unknown_count=len(record['unknowns']), required_window_count=len(record['required_windows']),
                   page=dict(offset=offset, total=len(rows), has_more=offset+len(selected)<len(rows),
                             next_offset=offset+len(selected) if offset+len(selected)<len(rows) else None))
        out['proposal']['changes'] = [{k:v for k,v in r.items() if k != 'row_type'}
                                     for r in selected if r['row_type'] == 'PROPOSAL_CHANGE']
        out['proposal_change_count'] = len(record['proposal']['changes'])
        out['proposal_changes_truncated'] = (len(out['proposal']['changes']) !=
                                             out['proposal_change_count'])
        # Drop page rows, never silently shorten a row or source window.
        while wire_bytes(out) > RESPONSE_BYTES and len(selected) > 1:
            return self._view(record, cycle, fresh=fresh, offset=offset, limit=len(selected)-1)
        require(wire_bytes(out) <= RESPONSE_BYTES, 'REPAIR_IMPACT_RESPONSE_LIMIT')
        return out

    def prepare(self, source, proposal):
        source, proposal = clean_source(source), clean_proposal(proposal)
        resolved = self._resolve(source)
        secrets = self._known_secrets(resolved)
        proposal = self._scrub(proposal, secrets)
        data, windows, truncated = self._sources(resolved, proposal)
        binding = resolved['binding']
        proposal_revision = digest(proposal)
        basis = digest([binding, proposal_revision, {n:v[0] for n,v in data.items()}])
        # The trusted resolved identity, not an optional request field, owns the
        # cumulative ledger. Omitting/adding an original revision cannot reset it.
        identity = {k:binding[k] for k in ('kind', 'task_ref', 'finding_id', 'origin_review_revision')
                    if k in binding}
        cycle_id = digest([self.workspace, self.owner, identity])
        now = self._time()
        with self.store.connect(write=True) as db:
            cycle = self.store.load(db, 'cycles', cycle_id)
            if cycle is None:
                cycle = dict(revision=0, latest=None, ledger=new_ledger())
            previous_choice = None
            if cycle['latest']:
                old = self.store.load(db, 'assessments', cycle['latest'])
                if old['proposal_revision'] == proposal_revision:
                    previous_choice = old.get('business_choice')
                if old['basis'] == basis and self._fresh(old):
                    # Idempotent prepare never extends an active lease. Only
                    # validated same-material idle resume renews activity.
                    if now > old['activity_expires_at']:
                        self._progress(old)
                        old['resumes'] += 1
                    packet = self._view(old, cycle)
                    charge(cycle['ledger'], packet, 'navigation')
                    self._save(db, old, cycle)
                    return packet
            require(cycle['revision'] < 32, 'REPAIR_IMPACT_REVISION_CAPACITY')
            allocate(cycle['ledger'], windows, data)
            ref = 'ria1-'+uuid.uuid4().hex
            cycle.update(revision=cycle['revision']+1, latest=ref)
            record = dict(assessment_ref=ref, cycle_id=cycle_id, workspace=self.workspace,
                owner=self.owner, revision=cycle['revision'], source=source, source_binding=binding,
                binding_digest=digest(binding), basis=basis, proposal=proposal,
                proposal_revision=proposal_revision, source_hashes={n:v[0] for n,v in data.items()},
                required_windows=windows, document_reasons={c['file_path']:c['reason'] for c in proposal['changes']},
                evidence={}, impacts=[], unknowns=[], coverage='PARTIAL', business_choice=previous_choice,
                secret_markers=self._secret_markers(secrets),
                submitted=False, created_at=now, material_expires_at=now+MATERIAL_SECONDS,
                activity_expires_at=now+ACTIVITY_SECONDS, last_progress_at=now, resumes=0,
                truncated_ranges={n:[line for line in cuts if any(w['file_path'] == n and
                    w['start_line'] <= line <= w['end_line'] for w in windows)]
                    for n,cuts in truncated.items() if any(w['file_path'] == n and
                    any(w['start_line'] <= line <= w['end_line'] for line in cuts) for w in windows)},
                capacity_required=cycle['ledger']['capacity_required'])
            packet = self._view(record, cycle)
            charge(cycle['ledger'], packet, 'navigation')
            self._save(db, record, cycle)
            return packet

    def read(self, assessment_ref, file_path, start_line=1, end_line=80, reason=None):
        require(isinstance(file_path, str), 'REPAIR_IMPACT_PATH_REJECTED')
        require(type(start_line) is int and type(end_line) is int and
                1 <= start_line <= end_line <= 2_147_483_647)
        with self.store.connect(write=True) as db:
            record, cycle = self._record(db, assessment_ref)
            require(self._fresh(record), 'REPAIR_IMPACT_STALE')
            self._active(record)
            resolved = self._resolve(record['source'])
            if reason is not None:
                reason = text(reason, 240)
            documentation = bool(reason or record['document_reasons'].get(file_path))
            name = path(file_path, documentation=documentation)
            _, sha, lines, cut = read_source(self.reader, name,
                resolved.get('secret_ranges', {}).get(name, ()), documentation=documentation)
            require(start_line <= len(lines), 'REPAIR_IMPACT_RANGE_UNAVAILABLE')
            high = min(end_line, len(lines))
            is_new = name not in record['source_hashes']
            if is_new:
                require(bool(reason), 'REPAIR_IMPACT_RELATED_REASON_REQUIRED')
                require(len(record['source_hashes']) < MAX_FILES, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
            elif record['source_hashes'][name] != sha:
                raise RepairImpactError('REPAIR_IMPACT_STALE')
            # Asking for a larger range creates the whole obligation, even when
            # this response can deliver only its first bounded page.
            window = dict(file_path=name, start_line=start_line, end_line=high, file_sha256=sha)
            if window not in record['required_windows']:
                record['required_windows'].append(window)
                allocate(cycle['ledger'], [window], {name:(sha, lines)})
                record['coverage'] = 'PARTIAL'
            record['capacity_required'] = cycle['ledger']['capacity_required']
            record['source_hashes'][name] = sha
            if documentation:
                record['document_reasons'][name] = reason or record['document_reasons'][name]
            relevant_cuts = [n for n in cut if start_line <= n <= high]
            if relevant_cuts:
                record['truncated_ranges'][name] = sorted(set(
                    record['truncated_ranges'].get(name, []) + relevant_cuts))
            if record['capacity_required']:
                record['coverage'] = 'PARTIAL'
                packet = self._terminal(record, cycle, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
                self._save(db, record, cycle)
                return packet
            stop = min(high, start_line+WINDOW_LINES-1)
            ref = 'ri-evidence-'+digest([assessment_ref, name, sha, start_line, stop])[:32]
            packet = dict(contract=CONTRACT, assessment_ref=assessment_ref, evidence_ref=ref,
                file_path=name, file_sha256=sha, start_line=start_line, end_line=stop,
                numbered_lines=[f'{n}: {lines[n-1]}' for n in range(start_line,stop+1)],
                trust='UNTRUSTED_SANITIZED_CURRENT_SOURCE', repair_authorized=False,
                next_range=dict(file_path=name, start_line=stop+1, end_line=high) if stop<high else None)
            while wire_bytes(packet) > RESPONSE_BYTES and stop > start_line:
                stop -= 1
                packet.update(end_line=stop, numbered_lines=packet['numbered_lines'][:-1],
                    evidence_ref='ri-evidence-'+digest([assessment_ref,name,sha,start_line,stop])[:32],
                    next_range=dict(file_path=name,start_line=stop+1,end_line=high))
            require(wire_bytes(packet) <= RESPONSE_BYTES, 'REPAIR_IMPACT_RESPONSE_LIMIT')
            ref = packet['evidence_ref']
            if ref not in record['evidence']:
                try:
                    charge(cycle['ledger'], packet, 'source', source_bytes=len(encoded(packet['numbered_lines'])))
                except RepairImpactError as exc:
                    if exc.reason_code not in {'REPAIR_IMPACT_SOURCE_CAPACITY', 'REPAIR_IMPACT_CONTROL_CAPACITY'}:
                        raise
                    record.update(coverage='PARTIAL', capacity_required=True)
                    self._save(db, record, cycle)
                    return self._terminal(record, cycle, exc.reason_code)
                cycle['ledger']['reads'] += 1
                record['evidence'][ref] = dict(file_path=name, file_sha256=sha,
                    start_line=start_line, end_line=stop, revision=record['revision'])
                self._progress(record)
                # Newly required context invalidates any prior completed claim.
                if unread(record):
                    record['coverage'] = 'PARTIAL'
            else:
                # A receipt does not redeliver source or renew activity.
                packet.pop('numbered_lines')
                packet['status'] = 'ALREADY_DELIVERED'
                charge(cycle['ledger'], packet, 'control')
            self._save(db, record, cycle)
            return packet

    def submit(self, assessment_ref, impacts, unknowns, coverage='REVIEWED', business_choice=None):
        require(isinstance(coverage, str) and coverage in {'REVIEWED', 'PARTIAL'})
        with self.store.connect(write=True) as db:
            record, cycle = self._record(db, assessment_ref)
            fresh = self._fresh(record)
            idle = self._time() > record['activity_expires_at']
            if fresh and coverage != 'PARTIAL':
                self._active(record)
            impacts, unknowns = reasoning(impacts, unknowns, record['evidence'])
            markers = record.get('secret_markers', [])
            impacts, unknowns = self._scrub_marked(impacts, markers), self._scrub_marked(unknowns, markers)
            require(coverage == 'PARTIAL' or bool(impacts), 'REPAIR_IMPACT_ANALYSIS_REQUIRED')
            if business_choice is not None:
                require(isinstance(business_choice, dict) and set(business_choice) ==
                        {'user_requested', 'proposal_revision', 'decision'} and
                        business_choice['user_requested'] is True and
                        business_choice['proposal_revision'] == record['proposal_revision'] and
                        business_choice['decision'] == 'ACCEPT_PROPOSED_CHANGE',
                        'REPAIR_IMPACT_BUSINESS_CHOICE_INVALID')
                require(any(v['kind'] == 'BUSINESS_BEHAVIOR_CHANGE' for v in impacts),
                        'REPAIR_IMPACT_BUSINESS_CHOICE_INVALID')
                business_choice = dict(business_choice, impact_basis=self._choice_basis(impacts),
                                       trust='UNTRUSTED_HOST_REPORT_NOT_EDIT_AUTHORITY')
            if business_choice is None:
                business_choice = record['business_choice']
            body = digest([impacts, unknowns, coverage, business_choice])
            progress = body != record.get('submission_digest')
            record.update(impacts=impacts, unknowns=unknowns, business_choice=business_choice,
                coverage='PARTIAL' if unread(record) or not fresh else coverage,
                submitted=True, submission_digest=body)
            if progress and fresh and not idle:
                self._progress(record)
            # A stale or partial analysis is still valuable history. It never
            # acquires READY, a replacement snapshot, or a refreshed material TTL.
            packet = self._view(record, cycle, fresh=fresh)
            try:
                charge(cycle['ledger'], packet, 'control')
            except RepairImpactError as exc:
                if exc.reason_code != 'REPAIR_IMPACT_CONTROL_CAPACITY':
                    raise
                packet = self._terminal(record, cycle, exc.reason_code)
            self._save(db, record, cycle)
            return packet

    def get(self, assessment_ref, offset=0, limit=5):
        with self.store.connect() as db:
            record, cycle = self._record(db, assessment_ref, owned=False)
            return self._view(record, cycle, fresh=self._fresh(record), offset=offset, limit=limit)

    def validate_for_fix(self, assessment_ref, source):
        source = clean_source(source)
        with self.store.connect() as db:
            record, cycle = self._record(db, assessment_ref)
            resolved = self._resolve(source)
            require(record['binding_digest'] == digest(resolved['binding']),
                    'REPAIR_IMPACT_SOURCE_BINDING_MISMATCH')
            fresh = self._fresh(record) and cycle['latest'] == assessment_ref
            result = dict(assessment_ref=assessment_ref, revision=record['revision'],
                gate=self._gate(record, fresh=fresh), proposal_revision=record['proposal_revision'],
                repair_authorized=False, automatic_execution=False,
                analysis_trust='HOST_ANALYSIS_NOT_SCANNER_PROOF')
            return result
