"""Public feedback input and safe protocol diagnostics, separate from verdicts."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class FindingEvidenceReference(BaseModel):
    """A claim about one exact range returned by prepare_finding_feedback."""

    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)
    file: str = Field(min_length=1, description='Exact file from the issued evidence packet.')
    start_line: int = Field(ge=1, description='Inclusive first line in the issued evidence range.')
    end_line: int = Field(ge=1, description='Inclusive last line; must be at least start_line.')
    claim: str = Field(min_length=1, max_length=500,
                      description='Required explanation of what this code range demonstrates.')

    @model_validator(mode='after')
    def valid_range(self):
        if self.end_line < self.start_line or not self.file.strip() or not self.claim.strip():
            raise ValueError('FEEDBACK_INPUT_INVALID')
        return self


FEEDBACK_TOOLS = {
    'prepare_finding_feedback', 'submit_finding_feedback', 'mark_finding_false_positive',
    'revoke_finding_feedback', 'get_finding_feedback', 'set_finding_disposition',
    'prepare_task_risk_feedback', 'submit_task_risk_feedback', 'mark_task_risk_false_positive',
    'revoke_task_risk_feedback', 'get_task_risk_feedback', 'set_task_risk_disposition',
}
FEEDBACK_READS = {'prepare_finding_feedback', 'prepare_task_risk_feedback',
                  'get_task_risk_feedback', 'get_finding_feedback'}

MESSAGES = {
    'FEEDBACK_INPUT_INVALID': '反馈参数格式不正确。请按工具参数要求重试；证据引用必须包含 file、start_line、end_line、claim。',
    'FEEDBACK_REFERENCE_REJECTED': '告警、任务或会话归属不匹配。请使用原项目和原告警返回的引用。',
    'FEEDBACK_SESSION_EXPIRED': '复核凭据已失效或已使用。请为原告警重新读取复核材料，不要新建告警。',
    'FEEDBACK_EVIDENCE_CHANGED': '复核依据已变化。请重新读取原告警的当前材料后再提交。',
    'FEEDBACK_EVIDENCE_REJECTED': '提交的证据不是本次复核发放的范围，或不足以支持该结论。原记录已保留。',
    'FEEDBACK_UNAVAILABLE': '本次未能读取反馈记录。请保留原引用后重试。',
    'FEEDBACK_SAVE_FAILED': '本次反馈未能确认保存，请勿告诉用户已保存；保留原引用后重试。',
}


class FeedbackInputError(ValueError):
    """A bounded input error that can cross either MCP transport safely."""

    reason_code = 'FEEDBACK_INPUT_INVALID'

    def __init__(self):
        super().__init__(self.reason_code)


def disposition_unavailable(exc):
    """Recognize the typed state-read failure across SDK exception wrappers."""
    from .risk_disposition import DispositionUnavailable
    current = exc
    for _ in range(12):
        if isinstance(current, DispositionUnavailable):
            return True
        current = current.__cause__ or current.__context__
        if current is None:
            break
    return False


def feedback_reason(exc, name):
    """Inspect only fixed error types/text; never reflect supplied code or paths."""
    from .task_ownership import TaskOwnershipError
    current = exc
    for _ in range(12):
        if isinstance(current, TaskOwnershipError):
            return current.reason_code
        if isinstance(current, (ValidationError, FeedbackInputError)):
            return 'FEEDBACK_INPUT_INVALID'
        code = getattr(current, 'reason_code', None)
        if code in MESSAGES:
            return code
        if isinstance(current, ValueError):
            message = str(current)
            if message in {
                'Scan does not belong to this workspace', 'Scan does not belong to this MCP workspace',
                'Finding does not belong to this MCP workspace', 'Select one finding from this scan',
                'Requested workspace is outside this MCP connection', 'Original host risk is unavailable',
                'Use a host task risk candidate; scanner findings use finding feedback',
                'Task session reference is invalid, expired or belongs to another workspace',
                'Task is unavailable or expired; never infer a baseline after editing',
            }:
                return 'FEEDBACK_REFERENCE_REJECTED'
            if message in {
                'Invalid or expired feedback handoff; prepare the selected finding again',
                'Feedback review is expired, consumed, or belongs to another session',
            }:
                return 'FEEDBACK_SESSION_EXPIRED'
            if message in {
                'Feedback context changed; prepare the same finding again',
                'Feedback evidence changed; prepare a fresh feedback review',
                'Finding source changed; scan the current source before selecting this occurrence',
                'Feedback source changed while validating; prepare this finding again',
            }:
                return 'FEEDBACK_EVIDENCE_CHANGED'
            if message in {
                'Feedback reference was not supplied in the evidence packet',
                'Feedback requires original issued evidence references',
                'False-positive review requires current complete counterevidence; retain NEEDS_CONTEXT',
                'Still-risk assessment requires current code references',
            }:
                return 'FEEDBACK_EVIDENCE_REJECTED'
            if message in {
                'Invalid feedback verdict or confidence', 'Invalid feedback verdict',
                'Context completeness must be an explicit boolean', 'Invalid unknown preconditions',
                'Invalid feedback evidence references', 'Invalid feedback reference fields',
                'Invalid feedback revocation source', 'A bounded, nonempty review reason is required',
                'A bounded feedback rationale is required', 'Use bounded feedback evidence and uncertainty lists',
                'An explicit user false-positive request is required', 'An explicit user revocation request is required',
                'User marking requires an explicit user request', 'A bounded user reason is required',
                'Revocation requires an explicit user request', 'A bounded revocation reason is required',
                'Use bounded feedback audit pages', 'At most five explicit related files may be reviewed',
                'A direct user request is required for this reminder choice',
                'Disposition must be EXCLUDE, DEFER or RESTORE', 'Only DEFER supports a deadline',
                'Invalid reminder choice request ID', 'Reason must be a string of at most 4000 characters',
                'Deferral deadline must be an ISO timestamp with timezone',
                'Deferral deadline requires a timezone', 'Deferral deadline must be in the future',
                'Request ID already belongs to a different reminder choice',
                'Invalid task reference',
            }:
                return 'FEEDBACK_INPUT_INVALID'
        current = current.__cause__ or current.__context__
        if current is None:
            break
    return 'FEEDBACK_UNAVAILABLE' if name in FEEDBACK_READS else 'FEEDBACK_SAVE_FAILED'


def feedback_failure(reason):
    """No failure response grants authority or claims a write succeeded."""
    return dict(status='FEEDBACK_REQUEST_REJECTED', reason_code=reason,
                message=MESSAGES.get(reason, MESSAGES['FEEDBACK_REFERENCE_REJECTED']),
                saved=False, scanner_run=False, source_modified=False,
                security_proof=False, repair_authorized=False, fix_authorized=False)
