"""Strict, recoverable input for explicit user risk dispositions."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, ValidationError


Choice = Literal['DEFER', 'EXCLUDE', 'RESTORE']


class DispositionRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    check_ref: str
    risk_id: str
    user_requested: Literal[True]
    decision: Choice | None = None
    disposition: Choice | None = None
    reason: str = Field(default='', max_length=4000)
    expected_seq: int | None = Field(default=None, ge=0)
    expected_revision: str | None = None
    request_id: str | None = Field(default=None, pattern=r'^[a-zA-Z0-9_-]{8,100}$')
    workspace_path: str | None = None
    session_ref: str | None = None


def input_failure(arguments, *, require_workspace=False):
    errors = []
    try:
        value = DispositionRequest.model_validate(arguments)
        if value.decision is None and value.disposition is None:
            errors.append(dict(field='decision', code='missing'))
        if value.decision and value.disposition and value.decision != value.disposition:
            errors.append(dict(field='disposition', code='conflicting_alias'))
        if require_workspace and not value.workspace_path:
            errors.append(dict(field='workspace_path', code='missing'))
    except ValidationError as exc:
        for error in exc.errors(include_input=False, include_context=False, include_url=False)[:8]:
            field = str(error['loc'][0]) if error['loc'] else '$'
            errors.append(dict(field=field if field in DispositionRequest.model_fields else '<unknown>', code=error['type']))
    if not errors:
        return None
    return dict(status='REJECTED', reason_code='DEVELOPMENT_DISPOSITION_INPUT_INVALID',
        field_errors=errors, saved=False, scanner_run=False, source_modified=False,
        message='处置未保存。decision 使用 DEFER（暂不处理）、EXCLUDE（用户标记误报）或 RESTORE（恢复提醒）；'
                '兼容 disposition，但两个字段不得冲突。仅在用户明确选择时传 user_requested=true，reason 填写用户原因。',
        accepted_fields=list(DispositionRequest.model_fields))
