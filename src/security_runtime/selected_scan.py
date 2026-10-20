"""Explicit file selection; never substitute repository discovery or Git changes."""
from __future__ import annotations

import stat
from pathlib import Path

from .hook_state import no_links
from .scan_request import ScanInputError, ScanRequest, SourceKind, paths
from .target import TargetDetector


MAX_SELECTED_FILES = 100
SCOPE_CONTRACT = 'selected-file-scan-v1'


def selected_request(root, files):
    """Validate the complete selection before claiming an execution lease.

    Deleted files are useful for development diffs, but an explicit file check
    must not silently turn a misspelled or missing filename into NO_CHANGES.
    Capture still rechecks links, file identity and bytes at execution time.
    """
    if not isinstance(files, (list, tuple)) or not 1 <= len(files) <= MAX_SELECTED_FILES:
        raise ScanInputError('SCAN_FILES_SELECTION_INVALID')
    names = paths(files)
    if any(any(char in name for char in '*?[]') for name in names):
        raise ScanInputError('SCAN_FILES_GLOBS_NOT_SUPPORTED')
    root = Path(root)
    detector = TargetDetector()
    try:
        no_links(root)
        for name in names:
            path = root / name
            no_links(path)
            if not stat.S_ISREG(path.stat().st_mode):
                raise ScanInputError('SCAN_INPUT_NOT_REGULAR')
            if not path.resolve(strict=True).is_relative_to(root):
                raise ScanInputError('SCAN_INPUT_PATH_INVALID')
            if set(Path(name).parts) & detector.ignored:
                raise ScanInputError('SCAN_FILES_TARGET_EXCLUDED')
        profile=detector.detect(root,list(names),select_scan_targets=True)
        if set(profile.files)!=set(names):
            raise ScanInputError('SCAN_FILES_TARGET_UNSUPPORTED')
    except ScanInputError:
        raise
    except FileNotFoundError:
        raise ScanInputError('SCAN_INPUT_REQUIRED_FILE_MISSING') from None
    except (OSError, ValueError, RuntimeError):
        raise ScanInputError('SCAN_FILES_SELECTION_UNVERIFIABLE') from None
    # Feature means all applicable rules for these complete files, including
    # IaC. The explicit request prevents Git diff/changed-line filtering.
    return ScanRequest(root, 'feature', SourceKind.WORKTREE, names)


def selection_captured(view, requested):
    # Runtime discovery can race with deletion/replacement. Missing requested
    # bytes must fail before any provider runs, rather than become NO_CHANGES.
    return set(view.request.files)==set(requested) and all(
        any(entry.path==name and entry.role=='TARGET' for entry in view.manifest)
        for name in requested)


def selection_scope(result, requested):
    """Display derived scope without altering the persisted signed context."""
    context = result.scan_context
    actual = list(context.get('input_files', ()))
    supporting = list(context.get('context_files', ()))
    skipped = list(result.target_profile.skipped_files)
    return dict(contract=SCOPE_CONTRACT, kind='SELECTED_FILES',
        requested_files=list(requested), target_files=actual,
        context_files=supporting, excluded_files=skipped,
        full_project=False, expanded_to_project=False,
        context_purpose='SCANNER_CONFIGURATION_AND_DEPENDENCY_CONTEXT',
        notice='仅检查明确指定的文件；上下文文件用于规则配置及依赖解析，不代表完整项目检查。')
