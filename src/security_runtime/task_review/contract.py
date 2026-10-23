"""Typed task findings and bounded diagnostics; never evidence or repair authority."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError
from typing_extensions import NotRequired, TypedDict


CONTRACT = 'task-review-submission-v1'


def _nonblank(value: str) -> str:
    if not value.strip():
        raise ValueError('TASK_REVIEW_NONEMPTY_TEXT_REQUIRED')
    return value


ReviewText = Annotated[str, Field(min_length=1, max_length=1200), AfterValidator(_nonblank)]
ReviewDetail = Annotated[str, Field(min_length=1, max_length=500), AfterValidator(_nonblank)]
ReviewEvidence = Annotated[str, Field(min_length=1, max_length=160, description=(
    'The evidence_id string actually issued by read_task_review_context for this task and '
    'review version. Never pass an object containing file/line/evidence_id fields.')),
    AfterValidator(_nonblank)]
ReviewEvidenceRefs = Annotated[list[ReviewEvidence], Field(min_length=1, max_length=10)]
ReviewDetails = Annotated[list[ReviewDetail], Field(max_length=10)]
ReviewCoverage = Literal['REVIEWED', 'PARTIAL']


class RiskAttribution(TypedDict):
    __pydantic_config__ = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)
    finding_id: ReviewEvidence
    origin: Literal['EXISTING', 'INTRODUCED', 'EXPANDED', 'UNKNOWN']
    impact: Literal['UNCHANGED', 'EXPANDED', 'UNKNOWN']
    rationale: ReviewText
    evidence_refs: ReviewEvidenceRefs


RiskAttributions = Annotated[list[RiskAttribution], Field(max_length=100)]


class TaskReviewCandidate(TypedDict):
    """Preserve omitted optional keys and the identity of existing valid candidates."""
    __pydantic_config__ = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)

    title: ReviewText
    category: ReviewText
    severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    primary_evidence: ReviewEvidence
    evidence_refs: ReviewEvidenceRefs
    impact: ReviewText
    preconditions: ReviewDetails
    unknowns: ReviewDetails
    counterevidence: ReviewDetails
    fix_advice: ReviewText
    risk_scope: NotRequired[Literal['TASK_CHANGED', 'RELATED_EXISTING']]
    task_evidence: NotRequired[ReviewEvidence]
    current_protections: NotRequired[ReviewDetails]
    same_issue_as: NotRequired[ReviewEvidence]
    risk_origin: NotRequired[Literal['EXISTING', 'INTRODUCED', 'EXPANDED', 'UNKNOWN']]
    impact_change: NotRequired[Literal['UNCHANGED', 'EXPANDED', 'UNKNOWN']]
    attribution_rationale: NotRequired[ReviewText]


TaskReviewFindings = Annotated[list[TaskReviewCandidate], Field(max_length=10)]
TaskReviewLimitations = Annotated[list[ReviewDetail], Field(max_length=30)]


class TaskReviewBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)

    findings: TaskReviewFindings
    coverage: ReviewCoverage
    limitations: TaskReviewLimitations


class SubmitTaskSecurityReviewInput(TaskReviewBody):
    task_ref: Annotated[str, Field(min_length=1, max_length=4096)]
    review_session: Annotated[str, Field(min_length=1, max_length=4096)]
    workspace_path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    session_ref: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    # Resolution semantics remain validated by the original risk ledger.
    risk_resolutions: list[dict] | None = None
    risk_attributions: RiskAttributions | None = None


_FIELDS = frozenset({'findings', 'coverage', 'limitations', 'title', 'category', 'severity',
    'primary_evidence', 'evidence_refs', 'impact', 'preconditions', 'unknowns',
    'counterevidence', 'fix_advice', 'risk_scope', 'task_evidence', 'current_protections',
    'task_ref', 'review_session', 'workspace_path', 'session_ref', 'risk_resolutions',
    'risk_attributions', 'finding_id', 'origin', 'rationale', 'same_issue_as',
    'risk_origin', 'impact_change', 'attribution_rationale'})
_MAX_ERRORS = 6


def _field_path(location):
    # Pydantic locations may contain caller-selected extra keys. Never echo them.
    path = ''
    for part in location[:6]:
        if type(part) is int:
            path += f'[{part}]' if 0 <= part <= 1024 else '[]'
        else:
            path += ('.' if path else '') + (part if part in _FIELDS else '?')
    return path or '$'


def _field_error(error):
    field = _field_path(error.get('loc', ()))
    kind = error.get('type', '')
    code, correction = 'INVALID_VALUE', '按工具 schema 修正此字段。'
    if kind == 'missing':
        code, correction = 'REQUIRED', '补齐工具 schema 要求的字段。'
    elif kind == 'extra_forbidden':
        code, correction = 'UNSUPPORTED_FIELD', '删除工具 schema 未声明的字段。'
    elif kind.endswith('_type'):
        code, correction = 'WRONG_TYPE', '使用工具 schema 声明的 JSON 类型。'
    elif kind == 'value_error':
        code, correction = 'NONEMPTY_TEXT_REQUIRED', '文本和文本数组项必须包含非空白内容。'
    elif kind in {'too_long', 'too_short', 'string_too_long', 'string_too_short'}:
        code, correction = 'OUT_OF_RANGE', '使用工具 schema 声明的数量和长度范围。'
    result = dict(field=field, code=code, correction=correction)
    if field.endswith(('.primary_evidence', '.task_evidence')) or '.evidence_refs[' in field:
        result['expected_type'] = 'string'
        result['correction'] = ('只传同一任务和复核版本 read_task_review_context 实际返回的 '
            'evidence_id 字符串；不要传含文件、行号或 evidence_id 的对象。')
    elif field.endswith('.evidence_refs'):
        result['expected_type'] = 'array of strings'
        result['correction'] = '传已签发 evidence_id 字符串数组，数量为 1 至 10；不要传证据对象数组。'
    elif field.endswith('.severity'):
        result.update(allowed_values=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
    elif field.endswith('.risk_scope'):
        result.update(allowed_values=['TASK_CHANGED', 'RELATED_EXISTING'])
    elif field == 'coverage':
        result.update(allowed_values=['REVIEWED', 'PARTIAL'])
    return result


class TaskReviewInputError(ValueError):
    """Fixed, input-free errors shared by direct, local and global callers."""
    reason_code = 'TASK_REVIEW_INPUT_INVALID'

    def __init__(self, field_errors):
        self.field_errors = field_errors[:_MAX_ERRORS]
        super().__init__('Use the task candidate schema with Runtime-issued evidence; unsupported fields are forbidden')

    def response(self):
        return dict(contract=CONTRACT, status='INCONCLUSIVE',
            reason_code=self.reason_code, scanner_run=False, source_modified=False,
            security_proof=False, repair_authorized=False, review_state_changed=False,
            field_errors=self.field_errors,
            message='风险登记参数未被接受；本次没有保存最终复核或结束原任务。',
            correction=('按 field_errors 和工具 schema 修正参数；原任务仍可复核时，沿用原 task_ref、'
                '当前 review_session 和已签发证据重试。不要为格式错误重新扫描、重建基线或结束核查；'
                '已结束、过期或版本变化的任务仍遵守原状态与版本门禁。'))


def validate_task_review_body(findings, coverage, limitations):
    try:
        return TaskReviewBody.model_validate(dict(findings=findings, coverage=coverage,
            limitations=limitations)).model_dump(exclude_unset=True)
    except ValidationError as exc:
        errors = exc.errors(include_input=False, include_context=False, include_url=False)
        raise TaskReviewInputError([_field_error(row) for row in errors[:_MAX_ERRORS]]) from None


def task_review_input_failure(arguments, *, require_workspace=False):
    """Diagnose malformed input before SDK error rendering or workspace admission."""
    errors = []
    try:
        request = SubmitTaskSecurityReviewInput.model_validate(arguments)
        if require_workspace and not request.workspace_path:
            errors.append(dict(field='workspace_path', code='REQUIRED',
                correction='全局入口需要当前项目的绝对 workspace_path。'))
    except ValidationError as exc:
        errors = [_field_error(row) for row in
            exc.errors(include_input=False, include_context=False, include_url=False)[:_MAX_ERRORS]]
    return TaskReviewInputError(errors).response()


def evidence_error(index, field, code, correction):
    """Only service-selected field names and fixed diagnostics cross this boundary."""
    return TaskReviewInputError([dict(field=f'findings[{index}].{field}', code=code,
        correction=correction)])


def find_task_review_input_error(error):
    # FastMCP may wrap the service exception. Inspect types, never exception prose.
    cause = error
    for _ in range(8):
        if isinstance(cause, TaskReviewInputError):
            return cause
        cause = cause.__cause__ or cause.__context__
        if cause is None:
            break
    return None
