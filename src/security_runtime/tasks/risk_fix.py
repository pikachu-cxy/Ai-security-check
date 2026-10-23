"""Pre-edit bridge for one host-reviewed risk, never a scanner repair grant."""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ..repair_impact_models import digest, require, source as clean_source

NativeTaskReference = Annotated[str, Field(min_length=36, max_length=36, pattern=r'^ts1-[a-f0-9]{32}$')]
NativeFindingReference = Annotated[str, Field(min_length=1, max_length=160)]
NativeImpactReference = Annotated[str, Field(min_length=37, max_length=37, pattern=r'^ria1-[a-f0-9]{32}$')]
NativeReviewRevision = Annotated[int, Field(strict=True, ge=1)]
NativeFixIntent = Annotated[bool, Field(strict=True, json_schema_extra={'const': True})]


class TaskRiskFixService:
    def __init__(self, tasks, impacts, intents):
        self.tasks, self.impacts, self.intents = tasks, impacts, intents

    @staticmethod
    def packet(context, task, *, reused=False, allow_edits=True):
        phase = task['status']
        active = phase == 'ACTIVE' and allow_edits
        return dict(status='NATIVE_RISK_FIX_PREPARED' if active else 'NATIVE_RISK_FIX_REVIEW_REQUIRED',
            ready_for_host_fix=active, source=context['source'],
            source_binding=context['source_binding'],
            assessment_ref=context['assessment_ref'],
            proposal_revision=context['proposal_revision'],
            proposal_summary=context['proposal_summary'], security_goal=context['security_goal'],
            preserve=context['preserve'], repair_task_ref=task['task_ref'],
            baseline_reused=reused, task_phase=phase,
            authorization=dict(user_requested=True, trust='UNTRUSTED_HOST_REPORT',
                scope='EXACT_SELECTED_NATIVE_RISK_AND_PROPOSAL', new_approval_required=False),
            repair_authorized=False, automatic_execution=False, scanner_run=False,
            source_modified=False, atomic_edit_enforcement=False,
            message=('沿用已有具体修复请求和这份编辑前记录，在原方案内修复；完成后核查实际改动并逐项复查原风险。'
                     if active else '当前不具备继续编辑的条件；保留这份原修复任务完成核查，不创建替代基线。'),
            resolution_target=dict(original_task_ref=context['source']['task_ref'],
                finding_id=context['source']['finding_id'],
                evidence_type='HOST_CODE_REVIEW_NOT_SCANNER_PROOF'))

    def _risk_is_active(self, workspace, source):
        offset = 0
        rows = []
        while offset <= 10_000:
            page = self.tasks.risk_ledger(workspace, source['task_ref'], offset=offset, limit=30)
            rows.extend(row for row in page.get('items', []) if row.get('finding_id') == source['finding_id'])
            if not page.get('has_more'):
                break
            offset += 30
        require(offset <= 10_000 and len(rows) == 1, 'REPAIR_IMPACT_SOURCE_UNRESOLVED')
        row = rows[0]
        return not (row.get('reminder_suppressed') or (row.get('feedback') or {}).get('folded')
            or row.get('status') in {'CODE_REVIEWED_RESOLVED', 'SCANNER_VERIFIED_RESOLVED'}
            or row.get('recorded_status') in {'CODE_REVIEWED_RESOLVED', 'SCANNER_VERIFIED_RESOLVED'})

    @staticmethod
    def _original_source(record, source):
        candidates = []
        views = [dict(revision=record.get('review_revision', 1), review=record.get('review')),
                 *record.get('review_history', [])]
        for view in views:
            if ('origin_review_revision' in source and
                    source['origin_review_revision'] != view.get('revision')):
                continue
            review = view.get('review') or {}
            if review.get('source') == 'HOST_TASK_REVIEW' and any(
                    finding.get('id') == source['finding_id'] for finding in review.get('findings', [])):
                candidates.append(view['revision'])
        require(len(candidates) == 1, 'REPAIR_IMPACT_ORIGIN_REVISION_UNAVAILABLE')
        return dict(source, origin_review_revision=candidates[0])

    def prepare(self, workspace, task_ref, finding_id, assessment_ref, *, user_requested,
                origin_review_revision=None):
        require(user_requested is True, 'REPAIR_IMPACT_NATIVE_FIX_INTENT_REQUIRED')
        source = dict(kind='HOST_TASK_RISK', task_ref=task_ref, finding_id=finding_id)
        if origin_review_revision is not None:
            source['origin_review_revision'] = origin_review_revision
        source = clean_source(source)
        root = self.tasks.root(workspace)
        # History access is deliberately weaker than selected repair ownership.
        original = self.tasks.load(root, task_ref)
        prior = self.intents.get()
        if prior and prior.get('repair_task_ref') and prior.get('assessment_ref') == assessment_ref:
            context = prior.get('preparation') or {}
            bound = context.get('source') or {}
            require(all(bound.get(k) == v for k, v in source.items()),
                    'REPAIR_IMPACT_SOURCE_BINDING_MISMATCH')
            record = self.tasks.load(root, prior['repair_task_ref'])
            from ..task_review.protocol import require_record_protocol
            require_record_protocol(record)
            require(record.get('native_repair') == context, 'REPAIR_IMPACT_NATIVE_BASELINE_MISMATCH')
            require(all(record['baseline']['hashes'].get(name) == sha
                        for name, sha in context['source_hashes'].items()),
                    'REPAIR_IMPACT_NATIVE_BASELINE_MISMATCH')
            if not self._risk_is_active(root, bound):
                return self.packet(context, self.tasks._view(record), reused=True, allow_edits=False)
            current = self.impacts.bound_native_fix_status(assessment_ref, context)
            if current != 'READY_FOR_EXISTING_AUTH':
                return self.packet(context, self.tasks._view(record), reused=True, allow_edits=False)
            if prior.get('status') == 'CANCELLED':
                # Pausing permits other work. Revalidate its resulting current
                # source before resuming, while retaining the original baseline.
                # A partial repair that changed the source must finish its
                # existing review rather than turn history into fresh edit scope.
                from ..repair_impact_models import RepairImpactError
                try:
                    refreshed = self.impacts.native_fix_context(assessment_ref, source)
                except RepairImpactError:
                    return self.packet(context, self.tasks._view(record), reused=True, allow_edits=False)
                if refreshed['gate'] != 'READY_FOR_EXISTING_AUTH':
                    return self.packet(context, self.tasks._view(record), reused=True, allow_edits=False)
                prior = self.intents.request(bound, assessment_ref)
            require(prior.get('status') == 'BOUND', 'REPAIR_IMPACT_NATIVE_FIX_PAUSED')
            # A repair's own edits invalidate the pre-repair impact snapshot.
            # They do not authorize replacing its original task baseline.
            return self.packet(context, self.tasks._view(record), reused=True)

        source = self._original_source(original, source)
        require(self._risk_is_active(root, source), 'REPAIR_IMPACT_SOURCE_NOT_ACTIVE')
        # The selected risk is real and owned at this point. A bad or stale
        # impact reference cannot downgrade that explicit repair into ordinary
        # development and replace its starting point.
        self.intents.request(source, assessment_ref)
        context = self.impacts.native_fix_context(assessment_ref, source)
        if context['gate'] != 'READY_FOR_EXISTING_AUTH':
            return dict(status='IMPACT_REQUIRED', ready_for_host_fix=False,
                gate=context['gate'], assessment_ref=assessment_ref, source=context['source'],
                repair_authorized=False, automatic_execution=False, scanner_run=False,
                source_modified=False, new_approval_required=False,
                message='影响分析尚未满足编辑前条件；保留已有修复请求，补足原评估后继续，不另建普通任务绕过。',
                next_action=dict(tool='get_repair_impact', arguments=dict(
                    workspace_path=str(root), assessment_ref=assessment_ref)))
        context.pop('gate')
        context.pop('repair_authorized')
        context.pop('automatic_execution')
        self.intents.ready(context)
        task_key = 'native-risk-fix-' + digest([context['source_binding'], assessment_ref,
                                               context['proposal_revision']])
        task = self.tasks.begin(root, task_key, _native_preparation=context)
        if task.get('status') != 'ACTIVE':
            return dict(task, ready_for_host_fix=False, repair_authorized=False)
        record = self.tasks.load(root, task['task_ref'])
        require(record.get('native_repair') == context, 'REPAIR_IMPACT_NATIVE_BASELINE_MISMATCH')
        require(all(record['baseline']['hashes'].get(name) == sha
                    for name, sha in context['source_hashes'].items()),
                'REPAIR_IMPACT_NATIVE_BASELINE_MISMATCH')
        self.intents.bind(task['task_ref'])
        return self.packet(context, task)
