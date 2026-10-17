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
class ReplyFacts:
    intent: str
    check: CheckFact = CheckFact()
    risks: tuple[RiskFact, ...] = ()
    notices: tuple[Notice, ...] = ()
    handling_available: bool = True
    current: bool | None = True
    quiet: bool = False
    total_risk_count: int | None = None


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

    def to_dict(self):
        # Full facts already live in the originating response. Reference them
        # rather than duplicating long explanations in bounded history packets.
        return dict(contract=CONTRACT, intent=self.intent, current=self.current,
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
    return ReplyPlan(facts.intent, facts.check, risks, notices, actions, facts.current, count,
                     facts.handling_available)
