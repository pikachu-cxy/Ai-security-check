"""Closed host-result contract; text is untrusted and never echoed or persisted."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HostStepResult(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)
    command_id: str = Field(min_length=1, max_length=80)
    execution_status: Literal['COMPLETED', 'TIMEOUT', 'NOT_AVAILABLE', 'CANCELLED',
                              'OUTPUT_LIMIT', 'FAILED_TO_START']
    exit_code: int | None = Field(default=None, ge=-2147483648, le=4294967295)
    duration_ms: int = Field(ge=0, le=180000)
    stdout_summary: str = Field(default='', max_length=8192)
    stderr_summary: str = Field(default='', max_length=8192)


class FunctionalExecutionReport(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, hide_input_in_errors=True)
    plan_digest: str = Field(min_length=64, max_length=64, pattern='^[a-f0-9]{64}$')
    network_access: Literal['DENIED', 'UNKNOWN']
    project_code_reviewed: bool
    steps: list[HostStepResult] = Field(min_length=1, max_length=9)
