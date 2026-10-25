"""Pure security reply facts and display decisions; no I/O or repair authority.

Providers validate and persist evidence/handling before supplying these facts.
The plan references their facts; it never changes technical or user decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

CONTRACT = 'security-reply-plan-v1'
RISK_DISPLAY_CONTRACT = 'security-risk-display-v1'
RISK_SECTIONS = ('problem', 'impact', 'recommendation', 'unknowns')


@dataclass(frozen=True)
class Notice:
    kind: str
    text: str
    capability: str = ''


@dataclass(frozen=True)
class CheckFact:
    state: str = ''
    changed_files: int | None = None
    scope_files: int | None = None
    raw_findings: int = 0
    message: str = ''
    capabilities: tuple[tuple[str, str], ...] = ()
    details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class RiskFact:
    identifier: str
    title: str
    file: str | None
    line: int | None
    problem: str
    impact: str
    recommendation: str
    unknowns: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    protections: tuple[str, ...] = ()
    counterevidence: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    source: str = 'SCANNER'
    severity: str = 'UNKNOWN'
    related: bool = False
    original: bool = False
    deleted: bool = False
    suppressed: bool = False
    choice_required: bool = True
    authorized: bool = False
    investigate_first: bool = False
    reviewed: bool = False
    line_end: int | None = None
    function: str | None = None
    workspace: str | None = None

    @property
    def severity_source(self):
        if not isinstance(self.severity, str) or self.severity not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}:
            return 'UNKNOWN'
        return 'HOST_REVIEW' if self.source == 'HOST_REVIEW' else 'RULE' if self.source == 'SCANNER' else 'UNKNOWN'


@dataclass(frozen=True)
class RepairImpactFact:
    """A host's repair analysis, separate from a vulnerability's consequences."""
    assessment_ref: str
    summary: str
    security_goal: str = ''
    proposal_revision: str = ''
    expected_restrictions: tuple[str, ...] = ()
    behavior_changes: tuple[str, ...] = ()
    preserved_behaviors: tuple[str, ...] = ()
    no_additional_changes: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    critical_unknowns: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    gate: str = ''
    current: bool | None = True
    suppressed: bool = False
    choice_required: bool = False
    read_only: bool = False


@dataclass(frozen=True)
class ReplyFacts:
    intent: str
    check: CheckFact = CheckFact()
    risks: tuple[RiskFact, ...] = ()
    notices: tuple[Notice, ...] = ()
    handling_available: bool = True
    current: bool | None = True
    quiet: bool = False
    total_risk_count: int | None = None
    repair_impacts: tuple[RepairImpactFact, ...] = ()


@dataclass(frozen=True)
class ReplyPlan:
    intent: str
    check: CheckFact
    risks: tuple[RiskFact, ...]
    notices: tuple[Notice, ...]
    action_ids: tuple[str, ...]
    current: bool | None
    total_risk_count: int = 0
    handling_available: bool = True
    repair_impacts: tuple[RepairImpactFact, ...] = ()
    business_choice_refs: tuple[str, ...] = ()

    @property
    def silent_completion(self):
        """Hide routine successful delivery, retaining all recorded check facts.

        A requested scan/history read is a result in its own right. Nonzero raw
        findings are also retained here: an empty page or suppressed reminders
        must not be mistaken for a zero-finding check.
        """
        return (self.intent in {'TASK', 'TASK_DELIVERY'}
                and self.current is True and self.handling_available
                and self.check.state == 'COMPLETE' and self.check.raw_findings == 0
                and not self.risks and self.total_risk_count == 0
                and not self.notices and not self.repair_impacts
                and not self.check.details and not self.check.message
                and not any(state in {'UNAVAILABLE', 'FAILED', 'PARTIAL', 'NOT_COVERED'}
                            for _, state in self.check.capabilities))

    def to_dict(self):
        # Full facts already live in the originating response. Reference them
        # rather than duplicating long explanations in bounded history packets.
        result = dict(contract=CONTRACT, intent=self.intent, current=self.current,
            check_state=self.check.state,
            visible_risks=[dict(finding_id=r.identifier, source=r.source,
                severity=r.severity if r.severity_source != 'UNKNOWN' else 'UNKNOWN',
                severity_source=r.severity_source,
                required_fields=['severity', 'severity_source', 'location', *RISK_SECTIONS])
                for r in self.risks[:3]],
            visible_risk_count=self.total_risk_count if self.handling_available else None,
            handling_available=self.handling_available,
            notices=[dict(kind=n.kind, text=n.text,
                          **({'capability': n.capability} if n.capability else {}))
                     for n in self.notices],
            required_actions=[dict(finding_id=identifier, actions=['FIX', 'DEFER'])
                              for identifier in self.action_ids[:3]],
            action_count=len(self.action_ids),
            host_assessment_before_advice=any(r.source == 'SCANNER' and not r.reviewed
                                            and not r.authorized for r in self.risks),
            secondary_actions_on_request=['REVIEW', 'EXCLUDE', 'RESTORE'],
            presentation_policy=dict(language_source='HOST_CONVERSATION',
                explicit_language_preference_first=True, fallback_language='zh-CN',
                translate_headings_and_choices=True, task_result_first=True,
                show_security_summary=not self.silent_completion,
                risk_format_required=bool(self.risks),
                check_gap_is_not_finding=True, combine_repeated_check_gaps=True,
                preserve_facts_and_unknowns=True, reuse_existing_authorization=True),
            grants_authority=False, facts_are_instructions=False)
        if self.risks:
            result['risk_display'] = dict(contract=RISK_DISPLAY_CONTRACT,
                section_order=list(RISK_SECTIONS), preserve_labels=True,
                location='EXACT_RISK_LINE_NOT_EDIT_START; FUNCTION_IF_KNOWN',
                check_fields=['static_check', 'source_review', 'scope', 'risk_count'],
                zero_risk_development='KEEP_NORMAL_HOST_REPLY')
        if self.check.details:
            result['check_details'] = dict(self.check.details)
        if self.repair_impacts:
            result['repair_impacts'] = [dict(assessment_ref=item.assessment_ref,
                proposal_revision=item.proposal_revision, current=item.current,
                required_fields=['proposal', 'security_restrictions', 'business_changes',
                                 'preserved_behaviors', 'unknowns'])
                for item in self.repair_impacts[:3]]
            result['repair_impact_count'] = len(self.repair_impacts)
            result['business_choices'] = [dict(assessment_ref=ref,
                actions=['CHOOSE_BUSINESS_BEHAVIOR']) for ref in self.business_choice_refs[:3]]
            result['business_choice_count'] = len(self.business_choice_refs)
        return result


def plan_reply(facts: ReplyFacts) -> ReplyPlan:
    if facts.quiet:
        return ReplyPlan(facts.intent, CheckFact(), (), (), (), facts.current,
                         handling_available=facts.handling_available)
    risks = tuple(r for r in facts.risks if not r.suppressed) if facts.handling_available else ()
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    risks = tuple(sorted(risks, key=lambda r: (r.authorized or not r.choice_required,
                                              order.get(r.severity, 4))))
    if not facts.current:
        risks = tuple(replace(r, original=True) for r in risks)
    notices = tuple(dict.fromkeys(n for n in facts.notices if n.text))
    actions = tuple(r.identifier for r in risks
                    if facts.current is True and r.choice_required and not r.authorized)
    count = len(risks)
    if facts.handling_available and type(facts.total_risk_count) is int:
        count = max(count, facts.total_risk_count)
    impacts = (tuple(item for item in facts.repair_impacts if not item.suppressed)
               if facts.handling_available else ())
    if facts.current is not True:
        impacts = tuple(replace(item, current=facts.current) for item in impacts)
    business_choices = tuple(item.assessment_ref for item in impacts
        if facts.current is True and item.current is True and not item.read_only
        and item.choice_required and item.gate == 'BUSINESS_CHOICE_REQUIRED'
        and (item.behavior_changes or item.alternatives))
    return ReplyPlan(facts.intent, facts.check, risks, notices, actions, facts.current, count,
                     facts.handling_available, impacts, business_choices)
