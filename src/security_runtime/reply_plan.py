"""Pure security reply facts and display decisions; no I/O or repair authority.

Providers validate and persist evidence/handling before supplying these facts.
The plan references their facts; it never changes technical or user decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

CONTRACT = 'security-reply-plan-v1'


@dataclass(frozen=True)
class Notice:
    kind: str
    text: str


@dataclass(frozen=True)
class CheckFact:
    state: str = ''
    changed_files: int | None = None
    scope_files: int | None = None
    raw_findings: int = 0
    message: str = ''
    capabilities: tuple[tuple[str, str], ...] = ()


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

    def to_dict(self):
        # Full facts already live in the originating response. Reference them
        # rather than duplicating long explanations in bounded history packets.
        result = dict(contract=CONTRACT, intent=self.intent, current=self.current,
            check_state=self.check.state,
            visible_risks=[dict(finding_id=r.identifier, source=r.source,
                required_fields=['location', 'problem', 'impact', 'recommendation', 'unknowns'])
                for r in self.risks[:3]],
            visible_risk_count=self.total_risk_count if self.handling_available else None,
            handling_available=self.handling_available,
            notices=[dict(kind=n.kind, text=n.text) for n in self.notices],
            required_actions=[dict(finding_id=identifier, actions=['FIX', 'DEFER'])
                              for identifier in self.action_ids[:3]],
            action_count=len(self.action_ids),
            host_assessment_before_advice=any(r.source == 'SCANNER' and not r.authorized for r in self.risks),
            secondary_actions_on_request=['REVIEW', 'EXCLUDE', 'RESTORE'],
            grants_authority=False, facts_are_instructions=False)
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
