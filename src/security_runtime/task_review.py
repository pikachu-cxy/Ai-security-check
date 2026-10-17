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


LIMITS = dict(total_bytes=256_000, response_bytes=16_000, batch_bytes=64_000,
              reads=160, changed_files=100, related_files=20)
TERMINAL_RECEIPT_BYTES = 1_600
_DELIVERY_BUDGET_ERRORS = frozenset({'TASK_CONTEXT_BYTE_BUDGET',
    'TASK_CONTEXT_BATCH_BUDGET', 'TASK_CONTEXT_RESPONSE_BUDGET'})


class TaskReviewCoordinator:
    def __init__(self, service):
        self.service = service

    def _charge(self, root, record, packet, category='control', source_bytes=0):
        from .task_security import TaskContextError
        try:
            plans.charge_packet(record, packet, category, source_bytes, now=self.service.now())
        except plans.ReviewPlanError as exc:
            # A rejected response was not delivered, so it is neither evidence
            # nor a permanent source gap. Remaining required windows stay unread.
            raise TaskContextError(exc.reason_code, str(exc), recoverable=exc.reason_code=='TASK_CONTEXT_RESPONSE_BUDGET',
                guidance='Keep this task and its evidence; submit PARTIAL with the remaining plan units. Do not reset the task or its cumulative limits.') from None
        record['context_bytes'] = record['review_ledger']['total_bytes']
        if record.get('review_protocol') == 3:
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
                raise TaskContextError('TASK_REVIEW_RECORD_CAPACITY',
                    'The signed review record cannot safely grow; existing delivered evidence is retained',
                    recoverable=False, guidance='Keep this task and its existing evidence; save an honest partial result without resetting its ledger.',
                    details={key: capacity[key] for key in ('required_record_bytes', 'maximum_record_bytes')})
        record.update(self.service.store(root).save(record))
        return packet

    def _method(self, protocol_version=2):
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
        return private.semantic_proof(record['task_ref'], name, raw)

    def completion_packet(self, record):
        """Bound final delivery too; detailed risk records remain queryable."""
        if record.get('review_protocol') == 3:
            # This is a fixed persistence receipt, not source or navigation.
            # Neither exhausted allowances nor an idle lease can prevent saving
            # the already validated result. The caller still persists atomically.
            packet = transport.terminal_receipt(record)
            if transport.packet_bytes(packet) > TERMINAL_RECEIPT_BYTES:
                raise ValueError('Terminal control receipt exceeds its independent byte limit')
            record['completion_delivery'] = dict(contract='INDEPENDENT_TERMINAL_RECEIPT',
                response_bytes=transport.packet_bytes(packet), response_limit=TERMINAL_RECEIPT_BYTES,
                source_evidence_delivered=False)
            return packet
        packet = self.service._view(record)
        if len(json.dumps(packet, ensure_ascii=False).encode()) > LIMITS['response_bytes']:
            packet = dict(status=record['phase'], task_ref=record['task_ref'],
                review_required=False, repair_authorized=False,
                static=dict(status=record['static']['status'], coverage=record['static']['coverage'],
                            finding_count=len(record['static']['findings'])),
                host_review=dict(coverage=record['review']['coverage'], finding_count=len(record['review']['findings'])),
                review_progress=packet['review_progress'], result_details_required=True,
                next_action=dict(tool='get_task_security_review', task_ref=record['task_ref'], finding_offset=0, finding_limit=1),
                message='完整风险说明已保存；读取结果详情后再向用户解释，不以此导航摘要代替风险内容。')
        try:
            plans.charge_packet(record, packet, now=self.service.now())
        except plans.ReviewPlanError as exc:
            if exc.reason_code not in _DELIVERY_BUDGET_ERRORS:
                raise
            # Like a budget rejection, this fixed control receipt is not a
            # source/evidence delivery. It cannot carry host prose, source,
            # paths or arbitrary progress details outside the spent ledger.
            # submit() still saves the complete validated record before it
            # returns this receipt; storage failures must propagate.
            completion = record['review_completion']
            packet = dict(status='COMPLETE', task_ref=record['task_ref'],
                review_required=False, scanner_run=False, source_modified=False,
                repair_authorized=False, result_saved=True,
                result_details_required=True, reason_code=exc.reason_code,
                delivery_contract='BOUNDED_TERMINAL_CONTROL_RECEIPT',
                static=dict(finding_count=len(record['static']['findings'])),
                host_review=dict(coverage=record['review']['coverage'],
                                 finding_count=len(record['review']['findings'])),
                review_progress={key: completion[key]
                                 for key in ('unit_count', 'reviewed_unit_count')},
                next_action=dict(tool='get_task_security_review', task_ref=record['task_ref'],
                                 finding_offset=0, finding_limit=1),
                message='结果已保存，响应额度已用完；请读取已保存详情查看风险及未完成范围。')
            receipt_bytes = len(json.dumps(packet, ensure_ascii=False).encode('utf-8'))
            if receipt_bytes > TERMINAL_RECEIPT_BYTES:
                raise ValueError('Terminal control receipt exceeds its independent byte limit')
            record['completion_delivery'] = dict(contract='BOUNDED_TERMINAL_CONTROL_RECEIPT',
                reason_code=exc.reason_code, response_bytes=receipt_bytes,
                response_limit=TERMINAL_RECEIPT_BYTES,
                source_evidence_delivered=False)
        record['context_bytes'] = record['review_ledger']['total_bytes']
        return packet

    def prepare(self, workspace, ref, protocol_version=2):
        if type(protocol_version) is not int or protocol_version not in {2, 3}:
            raise ValueError('Unsupported planned task review protocol')
        service = self.service
        root = service.root(workspace)
        initial = service.load(root, ref)
        if initial.get('review_protocol', protocol_version) != protocol_version:
            raise ValueError('A prepared task keeps its original review protocol and budgets')
        if initial['phase'] == 'ACTIVE':
            result = service.finish(workspace, ref)
            if result['status'] not in {'READY', 'NO_CHANGES'}:
                return result
        with service.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', task_ref=ref, scanner_run=False)
            record = service.load(root, ref)
            if record['phase'] in {'NO_CHANGES', 'INCOMPLETE', 'COMPLETE'}:
                return service._view(record)
            if record['phase'] not in {'READY', 'REVIEWING'} or not service._fresh(root, record):
                return dict(status='STALE', task_ref=ref, review_required=False,
                            message='代码或文件修改检查范围已变化；保留原记录，不能沿用旧证据。')
            if record.get('review_capacity'):
                return self._capacity_packet(record)
            if record.get('review_protocol', protocol_version) != protocol_version:
                raise ValueError('An active legacy review keeps its original protocol and budgets')
            if protocol_version == 3 and record.get('review_plan'):
                if service.now() > record['review_deadline']:
                    plans.renew_activity(record, now=service.now(), resume=True)
            elif record.get('review_deadline', float('inf')) < service.now():
                return dict(status='EXPIRED', task_ref=ref, review_required=False)
            if not record.get('review_plan'):
                unplanned = copy.deepcopy(record)
                # Hydrate only task changes for hunk planning, never copy whole
                # repository source bodies into the signed control record.
                hydrated = copy.deepcopy(record)
                for snapshot in ('baseline', 'end'):
                    hydrated[snapshot]['texts'] = {}
                    if protocol_version == 3:
                        hydrated[snapshot]['semantic_proofs'] = {}
                for change in (record['changes'] if protocol_version == 3 else record['changes'][:LIMITS['changed_files']]):
                    name = change['path']
                    for version, snapshot in (('BEFORE_TASK', 'baseline'), ('CURRENT', 'end')):
                        if (snapshot == 'baseline' and change['change'] == 'ADDED') or (snapshot == 'end' and change['change'] == 'DELETED'):
                            continue
                        try:
                            lines = service.before_lines(root, record, name) if snapshot == 'baseline' else service.end_lines(root, record, name)
                            if lines is not None:
                                hydrated[snapshot]['texts'][name] = lines
                                if protocol_version == 3:
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
                if protocol_version == 3:
                    plans.build_plan(hydrated, now=service.now(), protocol_version=3)
                    deadline = hydrated['review_plan']['deadline']
                else:
                    plans.build_plan(hydrated, now=service.now(), deadline=deadline, limits=LIMITS)
                record['review_plan'] = hydrated['review_plan']
                record['review_ledger'] = hydrated['review_ledger']
                record.pop('pending_review_revision', None)
                record.update(review_protocol=protocol_version, phase='REVIEWING', review_deadline=deadline,
                              review_session='tr1-'+uuid.uuid4().hex)
                if protocol_version == 3:
                    record.setdefault('review_started_at', service.now())
                guide = self._method(protocol_version)
                record['packet'] = dict(quick_skill={k: guide[k] for k in ('version', 'sha256')})
                if protocol_version == 3:
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
                        unplanned.update(review_protocol=3, review_capacity=diagnosis)
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
                submission_contract=dict(coverage='REVIEWED or PARTIAL', findings='max10; title,category,severity,primary_evidence,evidence_refs,impact,preconditions,unknowns,counterevidence,fix_advice',
                    optional='risk_scope,task_evidence,current_protections; RELATED_EXISTING needs current related and task evidence plus conditions and protections',
                    validation='HOST_REASONING; STRUCTURE_AND_SOURCE_VERSION_ONLY; NO_REPAIR_AUTHORITY'),
                limitations=record['limitations'][:10], trust='UNTRUSTED_SOURCE_AND_SCANNER_DATA')
            if protocol_version == 3:
                capacity = record['review_plan'].get('capacity', {})
                if capacity.get('status') == 'CAPACITY_REQUIRED':
                    packet.update(status='CAPACITY_REQUIRED', capacity=capacity)
            while len(json.dumps(packet, ensure_ascii=False).encode()) > LIMITS['response_bytes'] and len(packet['plan']['units']) > 1:
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
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            guide = self._method(record.get('review_protocol', 2))
            if guide['sha256'] != record['packet']['quick_skill']['sha256']:
                raise ValueError('Review method changed; task review is stale')
            return self._charge(root, record, dict(quick_skill=guide))

    def page(self, workspace, ref, session, cursor=0, limit=10):
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
                return dict(status='BUSY', scanner_run=False)
            record = service._session(root, ref, session, full_fresh=False)
            packet = plans.plan_page(record, cursor, limit)
            # A large page is navigable in smaller pages, not a coverage gap.
            while len(json.dumps(packet, ensure_ascii=False).encode()) > LIMITS['response_bytes'] and limit > 1:
                limit = max(1, limit//2)
                packet = plans.plan_page(record, cursor, limit)
            return self._charge(root, record, packet, 'navigation')

    def submit_batch(self, workspace, ref, session, unit_ids, coverage, limitations):
        from .task_security import _clean
        service = self.service
        root = service.root(workspace)
        with service.hooks.lock(root) as acquired:
            if not acquired:
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
            related_limit = (record['review_ledger']['limits']['related_files']
                             if record.get('review_protocol') == 3 else LIMITS['related_files'])
            if name not in changes and name not in record['related_files'] and len(record['related_files']) >= related_limit:
                service._context_gap(root, record, 'TASK_CONTEXT_RELATED_FILE_BUDGET', name)
                reject('TASK_CONTEXT_RELATED_FILE_BUDGET', 'Related source file limit exceeded', False)
            if before:
                try:
                    lines = service.before_lines(root, record, name)
                    if lines is None:
                        raise TaskPreimageUnavailable('TASK_PREIMAGE_MISSING')
                except (TaskPreimageUnavailable, OSError) as exc:
                    reject(getattr(exc, 'reason_code', 'TASK_PREIMAGE_UNAVAILABLE'), 'Task-start source is unavailable; it cannot be reconstructed after editing', False)
                location = 'BEFORE_DELETION' if deleted else 'BEFORE_TASK'
                truncated = snapshot.get('text_truncations', {}).get(name)
            else:
                try:
                    raw, text = WorkspaceReader(root).read(name)
                except (OSError, EvidenceUnavailable, UnicodeError):
                    reject('TASK_CONTEXT_SOURCE_UNAVAILABLE', 'Current task source is unavailable', False)
                if hash_bytes(raw) != snapshot['hashes'][name]:
                    raise ValueError('Task source changed during context read; evidence is stale')
                long_lines = []
                lines = safe_source(text, source_path=name, truncation_lines=long_lines)
                truncated = dict(line_count=len(long_lines), lines=long_lines) if long_lines else None
                location = 'CURRENT_TASK_END'
            if start_line > len(lines):
                reject('TASK_CONTEXT_RANGE_UNAVAILABLE', 'Source range unavailable', details=dict(total_lines=len(lines)))
            requested_high = min(end_line, len(lines))
            key = digest_value([name, snapshot['hashes'][name], location])
            request = record.setdefault('context_requests', {}).setdefault(key,
                dict(path=name, file_sha256=snapshot['hashes'][name], location_version=location, spans=[]))
            request['spans'] = _merge_spans([*request['spans'], [start_line, requested_high]])
            if record.get('review_protocol') == 3:
                return self._deliver_v3(root, record, ref, session, name, location, lines,
                                        truncated, start_line, requested_high, changes)
            # On a hard delivery refusal retain the explicit request, without
            # retaining unsent evidence or charging bytes that were not sent.
            refused = copy.deepcopy(record)
            high = min(requested_high, start_line+79)
            while True:
                eid = 'te1-'+digest_value([ref, session, name, snapshot['hashes'][name], start_line, high, location])[:32]
                packet = dict(evidence_id=eid, path=name, file_sha256=snapshot['hashes'][name],
                    location_version=location, start_line=start_line, end_line=high, total_lines=len(lines),
                    has_more=high<requested_high,
                    next_read=(dict(task_ref=ref, review_session=session, file_path=name, start_line=high+1,
                        end_line=requested_high, source_version=source_version, workspace_path=str(root)) if high<requested_high else None),
                    numbered_lines=[f'{i}: {lines[i-1]}' for i in range(start_line, high+1)], trust='UNTRUSTED_CODE')
                truncated_window = [i for i in (truncated or {}).get('lines', []) if start_line <= i <= high]
                if truncated_window:
                    packet['line_truncation'] = dict(lines=truncated_window, max_line_chars=MAX_LINE_CHARS)
                if len(json.dumps(packet, ensure_ascii=False).encode()) <= LIMITS['response_bytes'] or high == start_line:
                    break
                high = start_line+(high-start_line)//2
            truncated_window = [i for i in (truncated or {}).get('lines', []) if start_line <= i <= high]
            if truncated_window:
                if not any(v.get('path')==name and v.get('reason')=='SOURCE_LINE_CHAR_BUDGET' for v in record['limitations']):
                    record['limitations'].append(dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET', lines=truncated_window[:20]))
            try:
                if name not in changes:
                    plans.register_related(record, None, name, snapshot['hashes'][name], start_line, requested_high, location, now=service.now())
                plans.record_read(record, packet, now=service.now())
            except plans.ReviewPlanError as exc:
                service.store(root).save(refused)
                reject(exc.reason_code, str(exc), False)
            source_bytes = len(json.dumps(packet['numbered_lines'], ensure_ascii=False).encode())
            # Charge before returning; mutation is saved atomically only when
            # the actual response fits the fixed task and batch budgets.
            record['evidence'][eid] = {k:packet[k] for k in ('path','file_sha256','location_version','start_line','end_line')}
            if name not in changes and name not in record['related_files']:
                record['related_files'].append(name)
            try:
                return self._charge(root, record, packet, 'source', source_bytes)
            except TaskContextError as exc:
                if not exc.recoverable:
                    service.store(root).save(refused)
                raise

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
        while True:
            identifier = 'te3-' + digest_value([ref, name, file_hash, low, high, location])[:32]
            evidence = dict(evidence_id=identifier, path=name, file_sha256=file_hash,
                            location_version=location, start_line=low, end_line=high,
                            total_lines=len(lines))
            truncated_window = [i for i in (truncated or {}).get('lines', []) if low <= i <= high]
            truncation = dict(lines=truncated_window, max_line_chars=MAX_LINE_CHARS) if truncated_window else None
            packet = transport.source_packet(evidence, binding['source_ref'], lines,
                requested_high=requested_high, registered_source=None if registered else binding,
                line_truncation=truncation)
            if (transport.packet_bytes(packet) <= record['review_ledger']['limits']['response_bytes']
                    or high == low):
                break
            high = low + (high - low) // 2
        if truncated_window:
            limitation = dict(path=name, reason='SOURCE_LINE_CHAR_BUDGET', lines=truncated_window[:20])
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
            record['evidence'][identifier] = {key: evidence[key] for key in
                ('path', 'file_sha256', 'location_version', 'start_line', 'end_line')}
            if name not in changes and name not in record['related_files']:
                record['related_files'].append(name)
            source_bytes = len(json.dumps(packet['lines'], ensure_ascii=False).encode('utf-8'))
            return self._charge(root, record, packet, 'source', source_bytes)
        except plans.ReviewPlanError as exc:
            service.store(root).save(refused)
            raise TaskContextError(exc.reason_code, str(exc), recoverable=False,
                guidance='Keep this task, source bindings and delivered evidence; correct the named capacity or range limitation without resetting its ledger.') from None
        except TaskContextError:
            # Rejecting a packet cannot publish its source coverage or renew the
            # activity lease. The original requested interval is still retained.
            service.store(root).save(refused)
            raise
