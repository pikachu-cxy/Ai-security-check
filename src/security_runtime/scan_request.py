"""Internal public scan inputs, independent of Hook, MCP and provider adapters."""
from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from .models import ScanMode

REQUEST_CONTRACT = 'scan-request-v1'

# Public fixed diagnostics only. Never allow arbitrary exception text, even
# when a caller supplies a value with a plausible SCAN_INPUT_ prefix.
SCAN_INPUT_REASON_CODES = frozenset({
    'INDEX_SCAN_REQUIRES_QUICK_MODE',
    'SCAN_FILES_GLOBS_NOT_SUPPORTED', 'SCAN_FILES_SELECTION_INVALID',
    'SCAN_FILES_SELECTION_UNVERIFIABLE', 'SCAN_FILES_TARGET_EXCLUDED',
    'SCAN_FILES_TARGET_UNSUPPORTED',
    'SCAN_INPUT_ABSENCE_CHANGED', 'SCAN_INPUT_BINDING_CHANGED',
    'SCAN_INPUT_BINDING_INVALID', 'SCAN_INPUT_BYTE_BUDGET',
    'SCAN_INPUT_CAPTURE_UNAVAILABLE', 'SCAN_INPUT_CLOSED',
    'SCAN_INPUT_CODE_PREFERENCE_INVALID', 'SCAN_INPUT_CONFIGURATION_UNBOUND',
    'SCAN_INPUT_DEPENDENCY_SCOPE_INVALID', 'SCAN_INPUT_DERIVATION_SCOPE_UNAVAILABLE',
    'SCAN_INPUT_FILE_BUDGET', 'SCAN_INPUT_FILE_COUNT_BUDGET',
    'SCAN_INPUT_FROZEN_SOURCE_MODE_INVALID', 'SCAN_INPUT_IDENTITY_KEY_INVALID',
    'SCAN_INPUT_INDEX_BYTE_BUDGET', 'SCAN_INPUT_INDEX_CHANGED',
    'SCAN_INPUT_INDEX_ENTRY_UNSUPPORTED', 'SCAN_INPUT_INDEX_WORKSPACE_MISMATCH',
    'SCAN_INPUT_INVENTORY_CHANGED', 'SCAN_INPUT_LIMIT_INVALID',
    'SCAN_INPUT_NOT_REGULAR', 'SCAN_INPUT_PATHS_INVALID',
    'SCAN_INPUT_PATH_COLLISION', 'SCAN_INPUT_PATH_DUPLICATE', 'SCAN_INPUT_PATH_INVALID',
    'SCAN_INPUT_PRIVATE_DIRECTORY_CHANGED', 'SCAN_INPUT_PRIVATE_DIRECTORY_IN_WORKSPACE',
    'SCAN_INPUT_PRIVATE_DIRECTORY_UNAVAILABLE', 'SCAN_INPUT_PRIVATE_PATH_BUDGET',
    'SCAN_INPUT_REQUEST_CONTRACT_INVALID', 'SCAN_INPUT_REQUEST_INVALID',
    'SCAN_INPUT_REQUIRED_FILE_MISSING', 'SCAN_INPUT_RULES_ALREADY_CAPTURED',
    'SCAN_INPUT_RULES_CHANGED', 'SCAN_INPUT_RULE_DIRECTORY_REQUIRED',
    'SCAN_INPUT_RULE_INVENTORY_BUDGET', 'SCAN_INPUT_RULE_PACK_MISMATCH',
    'SCAN_INPUT_SELECTION_REVISION_INVALID', 'SCAN_INPUT_SOURCE_CHANGED',
    'SCAN_INPUT_SOURCE_MOVING', 'SCAN_INPUT_VIEW_CHANGED', 'SCAN_INPUT_VIEW_UNREADABLE',
    'SCAN_INPUT_WORKSPACE_INVALID', 'SCAN_INPUT_WORKSPACE_MISMATCH',
    'VERIFICATION_RULE_INPUT_MISMATCH',
})


class SourceKind(StrEnum):
    WORKTREE = 'WORKTREE'
    INDEX = 'INDEX'


class ScanInputError(ValueError):
    """Fixed diagnostics: never include project bytes or arbitrary paths."""

    def __init__(self, reason_code):
        self.reason_code = reason_code
        super().__init__(reason_code)


def relative_path(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096:
        raise ScanInputError('SCAN_INPUT_PATH_INVALID')
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value or '\\' in value or ':' in value
            or any(part in {'', '.', '..'} or part.endswith(('.', ' '))
                   or any(ord(char) < 32 for char in part) for part in path.parts)):
        raise ScanInputError('SCAN_INPUT_PATH_INVALID')
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)),
                *(f'LPT{i}' for i in range(1, 10))}
    if any(part.split('.')[0].upper() in reserved for part in path.parts):
        raise ScanInputError('SCAN_INPUT_PATH_INVALID')
    return value


def paths(values):
    if not isinstance(values, (tuple, list)):
        raise ScanInputError('SCAN_INPUT_PATHS_INVALID')
    normalized = tuple(relative_path(value) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ScanInputError('SCAN_INPUT_PATH_DUPLICATE')
    if len({os.path.normcase(value) for value in normalized}) != len(normalized):
        raise ScanInputError('SCAN_INPUT_PATH_COLLISION')
    return normalized


@dataclass(frozen=True)
class ScanBinding:
    """Actual rules/tool/data identity, checked again at the execution boundary."""

    kind: str
    name: str
    identity: str

    def __post_init__(self):
        if (not isinstance(self.kind, str) or self.kind not in {'RULES', 'TOOL', 'DATA'} or
                any(not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096
                    or any(ord(char) < 32 for char in value) for value in (self.name, self.identity))):
            raise ScanInputError('SCAN_INPUT_BINDING_INVALID')


@dataclass(frozen=True)
class ScanRequest:
    workspace_root: Path
    mode: ScanMode
    source_kind: SourceKind
    files: tuple[str, ...]
    context_files: tuple[str, ...] = ()
    absent_files: tuple[str, ...] = ()
    dependency_changes: tuple[str, ...] | None = None
    rules_path: Path | None = None
    bindings: tuple[ScanBinding, ...] = ()
    selection_revision: str | None = None
    code_preference: str = 'FULL'
    recheck_native: bool = False
    contract: str = REQUEST_CONTRACT

    def __post_init__(self):
        if self.contract != REQUEST_CONTRACT:
            raise ScanInputError('SCAN_INPUT_REQUEST_CONTRACT_INVALID')
        try:
            object.__setattr__(self, 'workspace_root', Path(self.workspace_root).absolute())
            object.__setattr__(self, 'mode', ScanMode(self.mode))
            object.__setattr__(self, 'source_kind', SourceKind(self.source_kind))
        except (ValueError, TypeError, OSError):
            raise ScanInputError('SCAN_INPUT_REQUEST_INVALID') from None
        if self.source_kind == SourceKind.INDEX and self.mode != ScanMode.QUICK:
            raise ScanInputError('INDEX_SCAN_REQUIRES_QUICK_MODE')
        if (not isinstance(self.code_preference, str) or self.code_preference not in
                {'FULL', 'CANONICAL_DYNAMIC_WHEN_ELIGIBLE'} or type(self.recheck_native) is not bool):
            raise ScanInputError('SCAN_INPUT_CODE_PREFERENCE_INVALID')
        for name in ('files', 'context_files', 'absent_files'):
            object.__setattr__(self, name, paths(getattr(self, name)))
        all_paths = (*self.files, *self.context_files, *self.absent_files)
        paths(all_paths)
        if self.dependency_changes is not None:
            object.__setattr__(self, 'dependency_changes', paths(self.dependency_changes))
            if not set(self.dependency_changes).issubset(all_paths):
                raise ScanInputError('SCAN_INPUT_DEPENDENCY_SCOPE_INVALID')
        if self.rules_path is not None:
            object.__setattr__(self, 'rules_path', Path(self.rules_path).absolute())
        if self.selection_revision is not None and (not isinstance(self.selection_revision, str)
                or len(self.selection_revision) != 64
                or any(char not in '0123456789abcdef' for char in self.selection_revision)):
            raise ScanInputError('SCAN_INPUT_SELECTION_REVISION_INVALID')
        if (not isinstance(self.bindings, tuple) or len(self.bindings) > 128
                or any(not isinstance(binding, ScanBinding) for binding in self.bindings)
                or len({(binding.kind, binding.name) for binding in self.bindings}) != len(self.bindings)):
            raise ScanInputError('SCAN_INPUT_BINDING_INVALID')

    @property
    def source_paths(self):
        return (*self.files, *self.context_files)

    @property
    def requested_files(self):
        return tuple(sorted((*self.files, *self.absent_files)))
