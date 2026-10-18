"""Closed, bounded contracts for host impact reasoning; never repair authority."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .local_evidence import _relative, safe_source
from .repair_impact_policy import valid_unknown_classification

CONTRACT = 'repair-impact-v1'
KINDS = {'EXPECTED_SECURITY_RESTRICTION', 'NO_ADDITIONAL_CHANGE_IDENTIFIED',
         'BUSINESS_BEHAVIOR_CHANGE', 'UNDETERMINED'}
SOURCE_KINDS = {'SCANNER_TASK_GROUP', 'HOST_TASK_RISK'}
COVERAGES = {'REVIEWED', 'PARTIAL'}
RESPONSE_BYTES = 16_000
WINDOW_LINES = 80
ACTIVITY_SECONDS = 900
MATERIAL_SECONDS = 86_400
MAX_FILES = 64
MAX_RECORD_BYTES = 1_000_000
HARD_BYTES = dict(source=4_000_000, navigation=1_000_000, control=2_000_000)
SOURCE_SUFFIXES = frozenset({'.py', '.pyi', '.java', '.js', '.jsx', '.ts', '.tsx',
    '.mjs', '.cjs', '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.go', '.rs', '.rb',
    '.php', '.kt', '.kts', '.swift', '.scala', '.vue', '.svelte', '.html', '.css',
    '.scss', '.sql', '.graphql', '.json', '.toml', '.yaml', '.yml', '.xml', '.ini',
    '.conf', '.config', '.properties', '.gradle', '.lock', '.sh', '.ps1'})
BLOCKED_DIRECTORIES = frozenset({'node_modules', '__pycache__', 'build', 'dist',
    'vendor', 'target', 'coverage', 'site-packages', 'venv', 'env', 'bin', 'obj'})


ImpactKind = Literal['EXPECTED_SECURITY_RESTRICTION', 'NO_ADDITIONAL_CHANGE_IDENTIFIED',
                     'BUSINESS_BEHAVIOR_CHANGE', 'UNDETERMINED']
ImpactCoverage = Literal['REVIEWED', 'PARTIAL']
ImpactText = Annotated[str, Field(min_length=1, max_length=800)]
ImpactDetail = Annotated[str, Field(min_length=1, max_length=240)]
ImpactEvidenceRef = Annotated[str, Field(pattern=r'^ri-evidence-[a-f0-9]{32}$',
    description='An evidence_ref actually issued by read_repair_impact_context for this assessment.')]
ImpactAssessmentRef = Annotated[str, Field(pattern=r'^ria1-[a-f0-9]{32}$')]
ImpactLine = Annotated[int, Field(ge=1, le=2_147_483_647)]
ImpactOffset = Annotated[int, Field(ge=0)]
ImpactLimit = Annotated[int, Field(ge=1, le=10,
    description='Rows per saved report page, 1 through 10; follow page.next_offset.')]
ImpactWorkspacePath = Annotated[str, Field(min_length=1, max_length=4096)]
ImpactSessionRef = Annotated[str, Field(min_length=1, max_length=1024)]
ImpactPath = Annotated[str, Field(min_length=1, max_length=4096,
    description='Relative workspace file path; path and source access are checked separately.')]


class ImpactInput(BaseModel):
    """Public input only; it neither changes evidence nor grants authority."""
    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)

    # Literal source kinds also inherit this validator. Validate after type/tag
    # selection so it cannot interfere with Pydantic's discriminated union.
    @field_validator('*', mode='after')
    @classmethod
    def reject_blank_text(cls, value):
        values = value if isinstance(value, list) else [value]
        if any(isinstance(item, str) and not item.strip() for item in values):
            raise ValueError('IMPACT_NONEMPTY_TEXT_REQUIRED')
        return value


class ScannerImpactSource(ImpactInput):
    kind: Literal['SCANNER_TASK_GROUP']
    task_ref: Annotated[str, Field(min_length=1, max_length=4096)]


class NativeImpactSource(ImpactInput):
    kind: Literal['HOST_TASK_RISK']
    task_ref: Annotated[str, Field(min_length=1, max_length=4096)]
    finding_id: Annotated[str, Field(min_length=1, max_length=160)]
    origin_review_revision: Annotated[int, Field(ge=1)] | None = None


RepairImpactSource = Annotated[ScannerImpactSource | NativeImpactSource, Field(discriminator='kind')]


class ImpactProposalChange(ImpactInput):
    file_path: ImpactPath
    start_line: ImpactLine
    end_line: ImpactLine
    reason: ImpactDetail

    @model_validator(mode='after')
    def ordered_range(self):
        if self.end_line < self.start_line:
            raise ValueError('IMPACT_RANGE_ORDER_INVALID')
        return self


class RepairImpactProposal(ImpactInput):
    security_goal: ImpactText
    summary: ImpactText
    changes: Annotated[list[ImpactProposalChange], Field(min_length=1, max_length=1024)]
    preserve: Annotated[list[Annotated[str, Field(min_length=1, max_length=200)]],
                        Field(max_length=10)] = Field(default_factory=list)


class RepairImpactItem(ImpactInput):
    kind: Annotated[ImpactKind, Field(description=(
        'EXPECTED_SECURITY_RESTRICTION: intended restriction of unsafe access; '
        'NO_ADDITIONAL_CHANGE_IDENTIFIED: no extra behavior change identified in read evidence; '
        'BUSINESS_BEHAVIOR_CHANGE: a normal business behavior changes; '
        'UNDETERMINED: a specific normal operation within the current proposal cannot be '
        'decided without a fact that changes implementation; always blocks. External scope '
        'limitations belong in unknowns, not UNDETERMINED.'))]
    summary: ImpactText
    evidence_refs: Annotated[list[ImpactEvidenceRef], Field(min_length=1, max_length=12)]
    affected_roles: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    affected_operations: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    affected_modules: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    interfaces: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    alternatives: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    counterevidence: Annotated[list[ImpactDetail], Field(max_length=5)] = Field(default_factory=list)
    decision_basis: Annotated[ImpactText, Field(description=(
        'For UNDETERMINED, identify the normal operation, missing fact, how its answer '
        'changes this proposal, and the smallest necessary check. Not a global proof requirement.'))] | None = None

    @model_validator(mode='after')
    def undetermined_basis_only(self):
        if self.decision_basis is not None and self.kind != 'UNDETERMINED':
            raise ValueError('IMPACT_DECISION_BASIS_INVALID')
        return self


class RepairImpactUnknown(ImpactInput):
    summary: ImpactText
    critical: Annotated[bool, Field(description=(
        'True only when a missing fact is necessary to decide this exact proposal or '
        'preserve a specific normal operation. Missing external context alone is not a blocker.'))]
    evidence_refs: Annotated[list[ImpactEvidenceRef], Field(max_length=12)] = Field(default_factory=list)
    classification: Annotated[Literal['BLOCKING_CONTEXT', 'SCOPE_LIMITATION'], Field(description=(
        'BLOCKING_CONTEXT requires critical=true, issued evidence and decision_basis. '
        'SCOPE_LIMITATION requires critical=false and decision_basis explaining why the '
        'unknown limits the conclusion but does not change this local proposal. '
        'Omission preserves legacy critical semantics, never downgrades a saved blocker.'))] | None = None
    decision_basis: Annotated[ImpactText, Field(description=(
        'Required with classification. Identify the concrete operation, missing fact and '
        'its effect on this proposal; blockers also explain what must be checked before editing.'))] | None = None

    @model_validator(mode='after')
    def consistent_classification(self):
        if not valid_unknown_classification(self.classification, self.critical,
                                           self.decision_basis, self.evidence_refs):
            raise ValueError('IMPACT_UNKNOWN_CLASSIFICATION_INVALID')
        return self


ImpactItems = Annotated[list[RepairImpactItem], Field(max_length=20)]
ImpactUnknowns = Annotated[list[RepairImpactUnknown], Field(max_length=20)]


class RepairImpactBusinessChoice(ImpactInput):
    user_requested: Annotated[Literal[True], Field(description=(
        'Report only the user\'s already explicit choice about this concrete business change; '
        'omit business_choice for an impact-only question. This is not repair authority.'))]
    proposal_revision: Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
    decision: Literal['ACCEPT_PROPOSED_CHANGE']

    @field_validator('user_requested', mode='before')
    @classmethod
    def literal_user_choice(cls, value):
        if value is not True:
            raise ValueError('IMPACT_EXPLICIT_CHOICE_REQUIRED')
        return value


class ImpactWorkspaceInput(ImpactInput):
    workspace_path: ImpactWorkspacePath | None = None
    session_ref: ImpactSessionRef | None = None


class PrepareRepairImpactInput(ImpactWorkspaceInput):
    source: RepairImpactSource
    proposal: RepairImpactProposal


class ReadRepairImpactInput(ImpactWorkspaceInput):
    assessment_ref: ImpactAssessmentRef
    file_path: ImpactPath
    start_line: ImpactLine = 1
    end_line: ImpactLine = 80
    reason: ImpactDetail | None = None

    @model_validator(mode='after')
    def ordered_range(self):
        if self.end_line < self.start_line:
            raise ValueError('IMPACT_RANGE_ORDER_INVALID')
        return self


class SubmitRepairImpactInput(ImpactWorkspaceInput):
    assessment_ref: ImpactAssessmentRef
    impacts: ImpactItems
    unknowns: ImpactUnknowns
    coverage: ImpactCoverage = 'REVIEWED'
    business_choice: RepairImpactBusinessChoice | None = None


class GetRepairImpactInput(ImpactWorkspaceInput):
    assessment_ref: ImpactAssessmentRef
    offset: ImpactOffset = 0
    limit: ImpactLimit = 10


IMPACT_INPUT_MODELS = {
    'prepare_repair_impact': PrepareRepairImpactInput,
    'read_repair_impact_context': ReadRepairImpactInput,
    'submit_repair_impact': SubmitRepairImpactInput,
    'get_repair_impact': GetRepairImpactInput,
}


def validate_impact_request(tool_name, arguments):
    """Use the same closed input contract for direct, local and global callers."""
    return IMPACT_INPUT_MODELS[tool_name].model_validate(arguments)


class RepairImpactError(ValueError):
    def __init__(self, reason_code, message=None):
        self.reason_code = reason_code
        super().__init__(message or reason_code)

    def response(self):
        return dict(status='REPAIR_IMPACT_UNAVAILABLE', reason_code=self.reason_code,
                    repair_authorized=False, automatic_execution=False,
                    scanner_run=False, source_modified=False)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def wire_bytes(value):
    """Include ordinary JSON framing whitespace in the public packet ceiling."""
    return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8'))


def require(condition, reason='REPAIR_IMPACT_INPUT_INVALID'):
    if not condition:
        raise RepairImpactError(reason)


def text(value, maximum=800):
    require(isinstance(value, str) and bool(value.strip()) and len(value) <= maximum)
    # The same literal/credential scrub as source delivery applies before any
    # host prose is saved. Analysis is untrusted, not an instruction channel.
    return '\n'.join(safe_source(value)).strip()[:maximum]


def path(value, *, documentation=False):
    require(isinstance(value, str), 'REPAIR_IMPACT_PATH_REJECTED')
    try:
        name = _relative(value)
    except ValueError:
        raise RepairImpactError('REPAIR_IMPACT_PATH_REJECTED') from None
    parts = PurePosixPath(name).parts
    require(not any(p.startswith('.') or p.lower() in BLOCKED_DIRECTORIES
                    for p in parts), 'REPAIR_IMPACT_PATH_REJECTED')
    require(not any(re.search(r'(?i)(?:^|\.)env(?:\.|$)', p) for p in parts),
            'REPAIR_IMPACT_PATH_REJECTED')
    require(not name.lower().endswith(('.pem', '.key', '.p12', '.pfx', '.crt')),
            'REPAIR_IMPACT_PATH_REJECTED')
    require(documentation or not name.lower().endswith(('.md', '.rst', '.txt')),
            'REPAIR_IMPACT_DOCUMENT_REASON_REQUIRED')
    require(PurePosixPath(name).suffix.lower() in SOURCE_SUFFIXES or
            PurePosixPath(name).name.lower() in {'dockerfile', 'makefile', 'requirements.txt',
                                                'gemfile', 'cargo.lock'} or
            (documentation and PurePosixPath(name).suffix.lower() in {'.md', '.rst', '.txt'}),
            'REPAIR_IMPACT_PATH_REJECTED')
    return name


def source(value):
    require(isinstance(value, dict) and isinstance(value.get('kind'), str) and value['kind'] in SOURCE_KINDS)
    require(isinstance(value.get('task_ref'), str) and 0 < len(value['task_ref']) <= 4096)
    allowed = {'kind', 'task_ref', 'finding_id', 'origin_review_revision'}
    require(set(value) <= allowed)
    if value['kind'] == 'SCANNER_TASK_GROUP':
        require(set(value) <= {'kind', 'task_ref'})
    if value['kind'] == 'HOST_TASK_RISK':
        require(isinstance(value.get('finding_id'), str) and 0 < len(value['finding_id']) <= 160)
    if 'origin_review_revision' in value:
        require(type(value['origin_review_revision']) is int and value['origin_review_revision'] >= 1)
    return dict(value)


def proposal(value):
    require(isinstance(value, dict) and set(value) <= {'security_goal', 'summary', 'changes', 'preserve'})
    changes = value.get('changes')
    require(isinstance(changes, list) and 1 <= len(changes) <= 1024,
            'REPAIR_IMPACT_CAPACITY_REQUIRED')
    out = dict(security_goal=text(value.get('security_goal')), summary=text(value.get('summary')),
               changes=[], preserve=[])
    for change in changes:
        require(isinstance(change, dict) and set(change) == {'file_path', 'start_line', 'end_line', 'reason'})
        low, high = change['start_line'], change['end_line']
        require(type(low) is int and type(high) is int and 1 <= low <= high <= 2_147_483_647)
        reason = text(change['reason'], 240)
        out['changes'].append(dict(file_path=path(change['file_path'], documentation=bool(reason)),
                                   start_line=low, end_line=high, reason=reason))
    preserve = value.get('preserve', [])
    require(isinstance(preserve, list) and len(preserve) <= 10)
    out['preserve'] = [text(item, 200) for item in preserve]
    require(len(encoded(out)) <= 128_000, 'REPAIR_IMPACT_CAPACITY_REQUIRED')
    return out


def reasoning(impacts, unknowns, evidence):
    require(isinstance(impacts, list) and len(impacts) <= 20)
    require(isinstance(unknowns, list) and len(unknowns) <= 20)
    result, missing = [], []
    optional = {'affected_roles', 'affected_operations', 'affected_modules',
                'interfaces', 'alternatives', 'counterevidence'}
    for item in impacts:
        require(isinstance(item, dict) and set(item) <= {'kind', 'summary', 'evidence_refs', 'decision_basis'} | optional)
        require(isinstance(item.get('kind'), str) and item['kind'] in KINDS)
        basis = item.get('decision_basis')
        require(basis is None or item['kind'] == 'UNDETERMINED', 'REPAIR_IMPACT_DECISION_BASIS_INVALID')
        refs = item.get('evidence_refs')
        require(isinstance(refs, list) and 1 <= len(refs) <= 12 and
                all(isinstance(ref, str) and ref in evidence for ref in refs),
                'REPAIR_IMPACT_EVIDENCE_INVALID')
        row = dict(kind=item['kind'], summary=text(item.get('summary')),
                   evidence_refs=list(dict.fromkeys(refs)))
        if basis is not None:
            row['decision_basis'] = text(basis)
        for field in optional & set(item):
            require(isinstance(item[field], list) and len(item[field]) <= 5)
            row[field] = [text(v, 240) for v in item[field]]
        result.append(row)
    for item in unknowns:
        require(isinstance(item, dict) and set(item) <= {
            'summary', 'critical', 'evidence_refs', 'classification', 'decision_basis'})
        require(type(item.get('critical')) is bool)
        refs = item.get('evidence_refs', [])
        require(isinstance(refs, list) and len(refs) <= 12 and
                all(isinstance(ref, str) and ref in evidence for ref in refs),
                'REPAIR_IMPACT_EVIDENCE_INVALID')
        classification, basis = item.get('classification'), item.get('decision_basis')
        require(valid_unknown_classification(classification, item['critical'], basis, refs),
                'REPAIR_IMPACT_UNKNOWN_CLASSIFICATION_INVALID')
        row = dict(summary=text(item.get('summary')), critical=item['critical'],
                   evidence_refs=list(dict.fromkeys(refs)))
        if classification is not None:
            row.update(classification=classification, decision_basis=text(basis))
        missing.append(row)
    require(len(encoded([result, missing])) <= 64_000)
    return result, missing


def merge(spans):
    out = []
    for low, high in sorted(spans):
        if out and low <= out[-1][1] + 1:
            out[-1][1] = max(high, out[-1][1])
        else:
            out.append([low, high])
    return out


def uncovered(low, high, spans):
    cursor, out = low, []
    for left, right in merge(spans):
        if right < cursor or left > high:
            continue
        if cursor < left:
            out.append([cursor, min(high, left - 1)])
        cursor = max(cursor, right + 1)
    if cursor <= high:
        out.append([cursor, high])
    return out
