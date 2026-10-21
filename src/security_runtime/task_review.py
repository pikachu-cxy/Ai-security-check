"""Versioned task review orchestration, separate from scanning and risk policy.

Immutable source references, a fixed review plan and a task-wide delivery ledger
let the host resume bounded batches without repeating scans or fabricating proof.
"""
from __future__ import annotations

import copy
import json
import uuid

from . import task_review_plan as plans
from .local_evidence import EvidenceUnavailable, WorkspaceReader, _relative, safe_source, MAX_LINE_CHARS
from .task_preimages import TaskPreimageUnavailable
from . import task_review_transport as transport
from .task_review_coverage import evidence_fields, first_unread_char
from .task_review_protocol import PROTOCOL_VERSION, validate_protocol, require_record_protocol


TERMINAL_RECEIPT_BYTES = 1_600


def submission_contract():
    """Describe submitted IDs separately from source-location metadata."""
    return dict(coverage='REVIEWED or PARTIAL',
        findings='max10; title,category,severity,primary_evidence,evidence_refs,impact,preconditions,unknowns,counterevidence,fix_advice',
        optional='risk_scope,task_evidence,current_protections; RELATED_EXISTING needs current related and task evidence plus conditions and protections',
        evidence_fields=dict(
            primary_evidence='Runtime-issued evidence_id string; must occur in evidence_refs',
            task_evidence='Runtime-issued changed-file evidence_id string; must occur in evidence_refs',
            evidence_refs='array of 1-10 Runtime-issued evidence_id strings from this exact task/session/source version'),
        evidence_format='Copy read_task_review_context evidence_id strings. Do not submit location objects containing evidence_id/file_path/start_line/end_line. source_ref is a locator, not evidence.',
        related_existing_example=dict(example_only=True, placeholders_are_issued=False,
            instruction='All IDs and prose are illustrative, not a finding. Replace IDs with actual issued strings and prose with actual code facts; never register the example risk or submit placeholders. Keep the original task_ref/review_session and actual coverage/limitations. REVIEWED requires completed required review work.',
            candidate=dict(title='Related read lacks an access check', category='ACCESS_CONTROL',
                severity='MEDIUM', risk_scope='RELATED_EXISTING',
                primary_evidence='<ISSUED_RELATED_ID>', task_evidence='<ISSUED_CHANGED_ID>',
                evidence_refs=['<ISSUED_RELATED_ID>', '<ISSUED_CHANGED_ID>', '<ISSUED_CONTROL_ID>'],
                impact='Unshared users could read content if callers lack an upstream check.',
                preconditions=['A caller can choose the document ID without authorization.'],
                unknowns=['Repository and external callers were not supplied.'],
                current_protections=['Shared listing filters owners and members.'],
                counterevidence=['That list filter does not protect the observed direct read.'],
                fix_advice='Reuse the owner/member check before returning content.')),
        correction='For recoverable submission errors, correct field_errors in the same original task/review_session/source version; do not rescan or replace the baseline. Correcting JSON does not automatically reopen terminal INCOMPLETE work or prove a finding was saved.',
        validation='HOST_REASONING; STRUCTURE_AND_SOURCE_VERSION_ONLY; NO_REPAIR_AUTHORITY')


class TaskReviewCoordinator:
    def __init__(self, service):
        self.service = service

    def _charge(self, root, record, packet, category='control', source_bytes=0):
        from .task_security import TaskContextError
        require_record_protocol(record)
        try:
            plans.charge_packet(record, packet, category, source_bytes, now=self.service.now())
        except plans.ReviewPlanError as exc:
            # A rejected response was not delivered, so it is neither evidence
            # nor a permanent source gap. Remaining required windows stay unread.
            if category != 'source':
                from .task_review_closeout import retain_delivery_blocker
                retain_delivery_blocker(self.service, root, record, exc.reason_code)
            raise TaskContextError(exc.reason_code, str(exc), recoverable=exc.reason_code=='TASK_CONTEXT_RESPONSE_BUDGET',
                guidance='Keep this task and its evidence; submit PARTIAL with the remaining plan units. Do not reset the task or its cumulative limits.') from None
        record['context_bytes'] = record['review_ledger']['total_bytes']
        registered = record.setdefault('review_transport', {}).setdefault('source_refs', [])
        bindings = packet.get('sources', [])
        if isinstance(packet.get('plan'), dict):
            bindings = [*bindings, *packet['plan'].get('sources', [])]
        if isinstance(packet.get('source'), dict):
            bindings = [*bindings, packet['source']]
        for binding in bindings:
            if binding['source_ref'] not in registered:
                registered.append(binding['source_ref'])
        capacity = transport.record_capacity(record)
        if not capacity['fits']:
            if category != 'source':
                from .task_review_closeout import retain_delivery_blocker
                retain_delivery_blocker(self.service, root, record, 'TASK_REVIEW_RECORD_CAPACITY')
            raise TaskContextError('TASK_REVIEW_RECORD_CAPACITY',
                'The signed review record cannot safely grow; existing delivered evidence is retained',
                recoverable=False, guidance='Keep this task and its existing evidence; save an honest partial result without resetting its ledger.',
                details={key: capacity[key] for key in ('required_record_bytes', 'maximum_record_bytes')})
        record.update(self.service.store(root).save(record))
        return packet

    def _method(self, protocol_version=PROTOCOL_VERSION):
        from .task_security import method
        return method(protocol_version)

    def _semantic_proof(self, root, record, name, snapshot, lines):
        """Planning-only private metadata; never returned or saved in control JSON."""
        private = self.service.preimages(root)
        if snapshot == 'baseline':
            reference = record['baseline'].get('preimages', {}).get(name)
            if reference is None:
                return dict(version=1, complete=False, line_count=len(lines), semantic_lines={})
            return private.read_semantic_proof(record['task_ref'], name,
                record['baseline']['hashes'][name], reference)
        from .task_security import hash_bytes
        raw, _ = WorkspaceReader(root).read(name)
        if hash_bytes(raw) != record['end']['hashes'].get(name):
            raise ValueError('Task source changed during semantic-proof planning; evidence is stale')
        from .source_redaction import task_version
        return private.semantic_proof(record['task_ref'], name, raw,
                                      redaction_version=task_version(record))

    def completion_packet(self, record, *, reserve_projection_sync=False):
        """Bound final delivery too; detailed risk records remain queryable."""
        require_record_protocol(record)
        from .task_projection import status as projection_status
        # The following source commit creates PENDING, and its acknowledgement
        # can only replace it with APPLIED. Reserve the larger response before
        # charging/saving; attaching the actual state afterwards never needs a
        # second budget check or a task write after a successful source commit.
        sync = (dict(state='APPLIED', pending=False) if reserve_projection_sync
                else projection_status(record))
        # This is a fixed persistence receipt, not source or navigation.
        # Neither exhausted allowances nor an idle lease can prevent saving
        # the already validated result. The caller still persists atomically.
        packet = transport.terminal_receipt(record)
        packet['risk_ledger_sync'] = sync
        if transport.packet_bytes(packet) > TERMINAL_RECEIPT_BYTES:
            raise ValueError('Terminal control receipt exceeds its independent byte limit')
        record['completion_delivery'] = dict(contract='INDEPENDENT_TERMINAL_RECEIPT',
            response_bytes=transport.packet_bytes(packet), response_limit=TERMINAL_RECEIPT_BYTES,
            source_evidence_delivered=False)
        if reserve_projection_sync:
            record['completion_delivery']['response_bytes_bound'] = 'PENDING_OR_APPLIED_UPPER_BOUND'
        return packet

    def prepare(self, workspace, ref, protocol_version=PROTOCOL_VERSION):
        validate_protocol(protocol_version)
        service = self.service
        root = service.root(workspace)
        initial = service.load(root, ref)
        require_record_protocol(initial)
        if initial['phase'] == 'ACTIVE':
            result = service.finish(workspace, ref)
            if result['status'] not in {'READY', 'NO_CHANGES'}:
                return result
        with service.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', task_ref=ref, scanner_run=False)
            record = service.load(root, ref)
            require_record_protocol(record)
            if record['phase']=='STATIC_RUNNING':
                from .scan_attempt import ScanAttemptStore
                attempts=ScanAttemptStore(service.hooks,root,now=service.now)
                lane=attempts.read()['lane']
                receipt=record.get('static_execution')
                if (lane and isinstance(receipt,dict) and lane.get('kind')=='TASK' and lane.get('scope_key')==ref
                        and lane.get('state')=='ACTIVE' and service.now()<lane['expires_at']
                        and all(lane.get(key)==receipt.get(key) for key in
                            ('attempt_id','generation','cancel_generation'))):
                    return dict(status='BUSY',task_ref=ref,scanner_run=False)
            if record['phase'] in {'NO_CHANGES', 'INCOMPLETE', 'COMPLETE'}:
                return service._view(record)
            if record['phase'] not in {'READY', 'REVIEWING'} or not service._fresh(root, record):
                return dict(status='STALE', task_ref=ref, review_required=False,
                            message='代码或文件修改检查范围已变化；保留原记录，不能沿用旧证据。')
            if record.get('review_capacity'):
                return self._capacity_packet(record)
            if record.get('review_plan'):
                if service.now() > record['review_deadline']:
                    plans.renew_activity(record, now=service.now(), resume=True)
            elif (record.get('review_deadline', float('inf')) < service.now()
                    and not record.get('pending_review_revision')):
                return dict(status='EXPIRED', task_ref=ref, review_required=False)
            # A refinish archives the old plan. Its signed pending revision is
            # validated by revision_ledger below, which renews only the idle
            # lease and retains the original baseline and cumulative spending.
            if not record.get('review_plan'):
                unplanned = copy.deepcopy(record)
                # Hydrate only task changes for hunk planning, never copy whole
                # repository source bodies into the signed control record.
                hydrated = copy.deepcopy(record)
                for snapshot in ('baseline', 'end'):
                    hydrated[snapshot]['texts'] = {}
                    hydrated[snapshot]['semantic_proofs'] = {}
                for change in record['changes']:
                    name = change['path']
                    for version, snapshot in (('BEFORE_TASK', 'baseline'), ('CURRENT', 'end')):
                        if (snapshot == 'baseline' and change['change'] == 'ADDED') or (snapshot == 'end' and change['change'] == 'DELETED'):
                            continue
                        try:
                            lines = service.before_lines(root, record, name) if snapshot == 'baseline' else service.end_lines(root, record, name)
                            if lines is not None:
                                hydrated[snapshot]['texts'][name] = lines
                                try:
                                    proof = self._semantic_proof(root, record, name, snapshot, lines)
                                except (TaskPreimageUnavailable, OSError, EvidenceUnavailable, UnicodeError) as exc:
                                    proof = dict(version=1, complete=False, line_count=len(lines), semantic_lines={})
                                    limitation = dict(path=name, location_version=version,
                                        reason='TASK_SEMANTIC_PROOF_UNVERIFIED',
                                        detail=getattr(exc, 'reason_code', 'TASK_SOURCE_UNAVAILABLE'))
                                    if limitation not in record['limitations']:
                                        record['limitations'].append(limitation)
                                hydrated[snapshot]['semantic_proofs'][name] = proof
                            else:
                                raise TaskPreimageUnavailable('TASK_PREIMAGE_MISSING')
                        except (TaskPreimageUnavailable, OSError, EvidenceUnavailable, UnicodeError) as exc:
                            limitation = dict(path=name, location_version=version,
                                reason=getattr(exc, 'reason_code', 'TASK_SOURCE_UNAVAILABLE'))
                            if limitation not in record['limitations']:
                                record['limitations'].append(limitation)
                deadline = record.get('review_deadline', service.now()+900)
                plans.build_plan(hydrated, now=service.now(), protocol_version=PROTOCOL_VERSION)
                deadline = hydrated['review_plan']['deadline']
                record['review_plan'] = hydrated['review_plan']
                record['review_ledger'] = hydrated['review_ledger']
                record.pop('pending_review_revision', None)
                record.update(review_protocol=protocol_version, phase='REVIEWING', review_deadline=deadline,
                              review_session='tr1-'+uuid.uuid4().hex)
                record.setdefault('review_started_at', service.now())
                guide = self._method(protocol_version)
                record['packet'] = dict(quick_skill={k: guide[k] for k in ('version', 'sha256')})
                capacity = transport.record_capacity(record)
                if not capacity['fits']:
                    diagnosis = dict(status='CAPACITY_REQUIRED', reason_code='TASK_REVIEW_RECORD_CAPACITY',
                        plan_id=record['review_plan']['plan_id'], snapshot_id=record['review_plan']['snapshot_id'],
                        unit_count=len(record['review_plan']['units']), reviewed_unit_count=0,
                        source_delivery_started=False,
                        **{key: capacity[key] for key in ('required_record_bytes', 'maximum_record_bytes')})
                    # Keep the complete original change inventory and source
                    # references. Do not publish a plan/ledger that storage
                    # cannot hold, or silently omit its trailing units.
                    unplanned.update(review_protocol=PROTOCOL_VERSION, review_capacity=diagnosis)
                    unplanned.update(service.store(root).save(unplanned))
                    return self._capacity_packet(unplanned)
                if record['review_plan'].get('capacity', {}).get('status') == 'CAPACITY_REQUIRED':
                    record['review_capacity'] = dict(record['review_plan']['capacity'],
                        plan_id=record['review_plan']['plan_id'],
                        snapshot_id=record['review_plan']['snapshot_id'],
                        unit_count=len(record['review_plan']['units']), reviewed_unit_count=0,
                        source_delivery_started=False)
                record.update(service.store(root).save(record))
                if record.get('review_capacity'):
                    return self._capacity_packet(record)
            guide = record['packet']['quick_skill']
            static = record['static']
            page = plans.plan_page(record, 0, 5)
            packet = dict(status='REVIEW_REQUIRED', protocol_version=protocol_version, task_ref=ref,
                review_revision=record.get('review_revision', 1),
                review_session=record['review_session'], review_required=True,
                static=dict(status=static['status'], coverage=static['coverage'],
                    scope_file_count=len(static.get('scope_files', [])), finding_count=len(static['findings']),
                    findings=[{k:f[k] for k in ('id', 'title', 'severity', 'file_path', 'line_start') if k in f} for f in static['findings'][:10]]),
                changed_file_count=len(record['changes']), plan=page, quick_skill=guide,
                method_fetch='get_task_review_method only when this exact version/digest is not already available locally',
                workflow='Read required windows; submit each unit with submit_task_review_batch; page get_task_review_plan until next_cursor is null; then submit_task_security_review with evidence-backed findings. Related source is read when needed, not an arbitrary mandatory unrelated file.',
                submission_contract=submission_contract(),
                limitations=record['limitations'][:10], trust='UNTRUSTED_SOURCE_AND_SCANNER_DATA')
            capacity = record['review_plan'].get('capacity', {})
            if capacity.get('status') == 'CAPACITY_REQUIRED':
                packet.update(status='CAPACITY_REQUIRED', capacity=capacity)
            while len(json.dumps(packet, ensure_ascii=False).encode()) > record['review_ledger']['limits']['response_bytes'] and len(packet['plan']['units']) > 1:
                packet['plan'] = plans.plan_page(record, 0, 1)
            return self._charge(root, record, packet)

    @staticmethod
    def _capacity_packet(record):
        static = record.get('static') or {}
        return dict(status='CAPACITY_REQUIRED', task_ref=record['task_ref'], protocol_version=3,
                    review_required=False, scanner_run=False, repair_authorized=False,
                    review_capacity=dict(record['review_capacity']),
                    static=dict(status=static.get('status'), coverage=static.get('coverage'),
                                finding_count=len(static.get('findings', []))),
                    message='复核所需的存储或传输资源超过当前容量，尚未开始发送源码；原任务、完整改动清单和修改前记录均已保留。')

    def method(self, workspace, ref, session):
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
                # Preserve owner/protocol rejection even under contention;
                # the successful path authenticates its one locked record.
                require_record_protocol(service.load(root, ref))
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            guide = self._method()
            if any(guide[key] != record['packet']['quick_skill'][key] for key in ('version', 'sha256')):
                raise ValueError('Review method changed; task review is stale')
            return self._charge(root, record, dict(quick_skill=guide), 'method')

    def page(self, workspace, ref, session, cursor=0, limit=10):
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
                require_record_protocol(service.load(root, ref))
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            packet = plans.plan_page(record, cursor, limit)
            # A large page is navigable in smaller pages, not a coverage gap.
            while len(json.dumps(packet, ensure_ascii=False).encode()) > record['review_ledger']['limits']['response_bytes'] and limit > 1:
                limit = max(1, limit//2)
                packet = plans.plan_page(record, cursor, limit)
            return self._charge(root, record, packet, 'navigation')

    def submit_batch(self, workspace, ref, session, unit_ids, coverage, limitations):
        from .task_security import _clean
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
                require_record_protocol(service.load(root, ref))
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            if not isinstance(limitations, list) or len(limitations) > 30:
                raise ValueError('Invalid batch limitations')
            result = plans.submit_units(record, unit_ids, coverage, [_clean(v, 500) for v in limitations], now=service.now())
            packet = dict(status='BATCH_RECORDED', **result,
                          reviewed_unit_count=sum(u['status']=='REVIEWED' for u in record['review_plan']['units']),
                          unit_count=len(record['review_plan']['units']), scanner_run=False)
            return self._charge(root, record, packet)

    def read(self, workspace, ref, session, path, start_line=1, end_line=80, source_version='CURRENT'):
        from .task_security import TaskContextError, _supported, _environment, hash_bytes, digest_value, _merge_spans
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
                require_record_protocol(service.load(root, ref))
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            def reject(reason, message, recoverable=True, details=None):
                raise TaskContextError(reason, message, recoverable=recoverable,
                    guidance='Use this task plan and the same session. Correct a recoverable range/path; otherwise submit PARTIAL with the named missing source.', details=details)
            if source_version not in {'CURRENT', 'BEFORE_TASK'}:
                reject('TASK_CONTEXT_VERSION_INVALID', 'Use CURRENT or BEFORE_TASK')
            try:
                name = _relative(path)
            except (ValueError, EvidenceUnavailable):
                reject('TASK_CONTEXT_PATH_REJECTED', 'Source path rejected')
            if not _supported(name):
                reject('TASK_CONTEXT_FILE_UNSUPPORTED', 'File type is outside source context')
            if _environment(name):
                reject('TASK_CONTEXT_PATH_EXCLUDED', 'Environment content remains excluded')
            if type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line <= 2_147_483_647:
                reject('TASK_CONTEXT_RANGE_INVALID', 'Invalid source range')
            changes = {c['path']: c['change'] for c in record['changes']}
            deleted = changes.get(name) == 'DELETED'
            before = deleted or source_version == 'BEFORE_TASK'
            snapshot = record['baseline' if before else 'end']
            if name not in snapshot['hashes']:
                reject('TASK_CONTEXT_PATH_EXCLUDED', 'Path is outside the requested source version')
            related_limit = record['review_ledger']['limits']['related_files']
            if name not in changes and name not in record['related_files'] and len(record['related_files']) >= related_limit:
                service._context_gap(root, record, 'TASK_CONTEXT_RELATED_FILE_BUDGET', name)
                reject('TASK_CONTEXT_RELATED_FILE_BUDGET', 'Related source file limit exceeded', False)
            if before:
                try:
                    lines = service.before_lines(root, record, name)
                    if lines is None:
                        raise TaskPreimageUnavailable('TASK_PREIMAGE_MISSING')
                except (TaskPreimageUnavailable, OSError) as exc:
                    reason = getattr(exc, 'reason_code', 'TASK_PREIMAGE_UNAVAILABLE')
                    service._context_gap(root, record, reason, name,
                        location_version='BEFORE_DELETION' if deleted else 'BEFORE_TASK')
                    reject(reason, 'Task-start source is unavailable; it cannot be reconstructed after editing', False)
                location = 'BEFORE_DELETION' if deleted else 'BEFORE_TASK'
                truncated = snapshot.get('text_truncations', {}).get(name)
            else:
                try:
                    raw, text = WorkspaceReader(root).read(name)
                except (OSError, EvidenceUnavailable, UnicodeError):
                    service._context_gap(root, record, 'TASK_CONTEXT_SOURCE_UNAVAILABLE', name,
                        location_version='CURRENT_TASK_END')
                    reject('TASK_CONTEXT_SOURCE_UNAVAILABLE', 'Current task source is unavailable', False)
                if hash_bytes(raw) != snapshot['hashes'][name]:
                    raise ValueError('Task source changed during context read; evidence is stale')
                from .source_redaction import task_version
                version = task_version(record)
                cache = service.source_cache
                cache_key = (str(root), ref, session, 'CURRENT_TASK_END', name,
                             snapshot['hashes'][name], version)
                cached = cache.get(cache_key) if cache is not None else None
                if cached is None:
                    long_lines = []
                    lines = safe_source(text, source_path=name, truncation_lines=long_lines,
                                        redaction_version=version, max_line_chars=None)
                    if cache is not None:
                        cache.put(cache_key, lines, long_lines)
                else:
                    lines, long_lines = cached
                truncated = dict(line_count=len(long_lines), lines=long_lines) if long_lines else None
                location = 'CURRENT_TASK_END'
            if truncated:
                service._context_gap(root, record, 'TASK_PREIMAGE_LINE_TRUNCATED', name,
                                     location_version=location)
                reject('TASK_PREIMAGE_LINE_TRUNCATED',
                       'An older snapshot lost source characters; its prefix cannot prove full source coverage', False)
            if start_line > len(lines):
                reject('TASK_CONTEXT_RANGE_UNAVAILABLE', 'Source range unavailable', details=dict(total_lines=len(lines)))
            requested_high = min(end_line, len(lines))
            key = digest_value([name, snapshot['hashes'][name], location])
            request = record.setdefault('context_requests', {}).setdefault(key,
                dict(path=name, file_sha256=snapshot['hashes'][name], location_version=location, spans=[]))
            request['spans'] = _merge_spans([*request['spans'], [start_line, requested_high]])
            return self._deliver_v3(root, record, ref, session, name, location, lines,
                                    truncated, start_line, requested_high, changes)

    def _deliver_v3(self, root, record, ref, session, name, location, lines,
                    truncated, start_line, requested_high, changes):
        """Pack readable source once; record only the actual delivered interval."""
        from .task_security import TaskContextError, digest_value
        service = self.service
        snapshot = record['end' if location == 'CURRENT_TASK_END' else 'baseline']
        file_hash = snapshot['hashes'][name]
        refused = copy.deepcopy(record)
        binding = plans.source_binding(record, name, file_hash, location, total_lines=len(lines))
        missing, prior_refs = transport.delivered_ranges(record, name, file_hash, location,
                                                         start_line, requested_high)
        if not missing:
            packet = transport.duplicate_packet(binding['source_ref'], start_line, requested_high, prior_refs)
            return self._charge(root, record, packet, 'navigation')
        low, first_high = missing[0]
        high = min(first_high, low + 599)
        registered = binding['source_ref'] in record.get('review_transport', {}).get('source_refs', [])
        def pack(last_line, fragment=None):
            identity = [ref, name, file_hash, low, last_line, location]
            if fragment is not None:
                identity.extend(fragment)
            identifier = 'te3-' + digest_value(identity)[:32]
            evidence = dict(evidence_id=identifier, path=name, file_sha256=file_hash,
                            location_version=location, start_line=low, end_line=last_line,
                            total_lines=len(lines))
            if fragment is not None:
                evidence.update(zip(('start_char', 'end_char', 'line_chars'), fragment))
            truncated_window = [i for i in (truncated or {}).get('lines', []) if low <= i <= last_line]
            truncation = dict(lines=truncated_window, max_line_chars=MAX_LINE_CHARS) if truncated_window else None
            packet = transport.source_packet(evidence, binding['source_ref'], lines,
                requested_high=requested_high, registered_source=None if registered else binding,
                line_truncation=truncation)
            return evidence, packet, truncated_window

        matching = [item for item in record.get('evidence', {}).values()
                    if (item['path'], item['file_sha256'], item['location_version']) ==
                    (name, file_hash, location)]
        partial = any(item['start_line'] == low and 'start_char' in item for item in matching)
        limit = record['review_ledger']['limits']['response_bytes']
        while True:
            evidence, packet, truncated_window = pack(high)
            if transport.packet_bytes(packet) <= limit or high == low:
                break
            high = low + (high - low) // 2
        if lines[low - 1] and (partial or transport.packet_bytes(packet) > limit):
            # Repeated requests resume the same immutable line. A fragment is
            # real evidence, but coverage only advances after all its chars arrive.
            count = len(lines[low - 1])
            first = first_unread_char(matching, low, count)
            left, right, best = first + 1, count, None
            while left <= right:
                last = (left + right) // 2
                candidate = pack(low, (first, last, count))
                if transport.packet_bytes(candidate[1]) <= limit:
                    best = candidate
                    left = last + 1
                else:
                    right = last - 1
            if best is None:
                # Preserve the usual bounded-delivery failure/rollback path.
                best = pack(low, (first, first + 1, count))
            evidence, packet, truncated_window = best
        identifier = evidence['evidence_id']
        if truncated_window:
            limitation = dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET',
                              location_version=location, lines=truncated_window[:20])
            if not any(v.get('path') == name and v.get('reason') == 'SOURCE_LINE_CHAR_BUDGET'
                       for v in record['limitations']):
                record['limitations'].append(limitation)
        try:
            if name not in changes:
                # Requested related obligations remain explicit even when the
                # bounded response delivers only their first unread interval.
                plans.register_related(record, None, name, file_hash, start_line,
                                       requested_high, location, now=service.now(), source_lines=lines)
            plans.record_read(record, evidence, now=service.now())
            record['evidence'][identifier] = evidence_fields(evidence)
            if name not in changes and name not in record['related_files']:
                record['related_files'].append(name)
            source_bytes = len(json.dumps(packet['lines'], ensure_ascii=False).encode('utf-8'))
            return self._charge(root, record, packet, 'source', source_bytes)
        except plans.ReviewPlanError as exc:
            from .task_review_closeout import DELIVERY_BLOCKERS
            if exc.reason_code in DELIVERY_BLOCKERS:
                refused['review_delivery_blocker'] = dict(reason=exc.reason_code,
                    review_revision=record.get('review_revision', 1))
            service.store(root).save(refused)
            raise TaskContextError(exc.reason_code, str(exc), recoverable=False,
                guidance='Keep this task, source bindings and delivered evidence; correct the named capacity or range limitation without resetting its ledger.') from None
        except TaskContextError as exc:
            # Rejecting a packet cannot publish its source coverage or renew the
            # activity lease. The original requested interval is still retained.
            from .task_review_closeout import DELIVERY_BLOCKERS
            if exc.reason_code in DELIVERY_BLOCKERS:
                refused['review_delivery_blocker'] = dict(reason=exc.reason_code,
                    review_revision=record.get('review_revision', 1))
            service.store(root).save(refused)
            raise
