"""First-scan proof from digest-authenticated old bytes, never a guessed baseline.

Git is only a byte recovery source. HEAD/index alone convey no authority: every
candidate must match the session's keyed filesystem digest. No source archive,
history search, working-tree overwrite, or pre-edit Finding DB is created.
"""
from __future__ import annotations

import difflib
import hashlib
import hmac
import re
import subprocess
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

MAX_TARGETS = 16
MAX_TOTAL = 4_000_000
MAX_FILE = 1_000_000
STATUSES = {'NOT_APPLICABLE', 'FIRST_SCAN_NO_RISK', 'FIRST_SCAN_EXISTING_RISK',
            'FIRST_SCAN_NEW_RISK_ATTRIBUTED', 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'}
REASONS = {'NO_TRUSTED_PRE_EDIT_BYTES', 'DETECTOR_NOT_EQUIVALENT',
           'TARGET_IDENTITY_NOT_PROVEN', 'ATTRIBUTION_BUDGET_EXCEEDED',
           'PRE_EDIT_SCAN_INCOMPLETE', 'OCCURRENCE_IDENTITY_UNPROVEN',
           'SOURCE_CHANGED_DURING_ATTRIBUTION', 'ATTRIBUTION_VERIFIED'}
_probes = ContextVar('attribution_engine_probes', default=None)


@contextmanager
def probe_scope():
    values = {}
    token = _probes.set(values)
    try:
        yield values
    finally:
        _probes.reset(token)


def record_probe(tool_id, identity):
    # The existing content validation already computed this value. No extra
    # hash/probe on a safe first edit; nothing is cached/persisted or serialized.
    values = _probes.get()
    if values is not None and tool_id == 'semgrep':
        values[tool_id] = identity


def diagnostics():
    return dict(first_scan_attribution_attempted=False, pre_edit_targeted_scan_run=False,
                pre_edit_targeted_scan_count=0, first_scan_attribution_status='NOT_APPLICABLE',
                pre_existing_risk_count=None, newly_attributed_risk_count=None,
                attribution_scanner_equivalent=None, first_scan_attribution_reason=None)


def file_digest(key, content):
    return hmac.new(key, b'hook-file-v1' + content, hashlib.sha256).hexdigest()


def recover_bytes(root, name, expected, key):
    from .hook_runtime import _git, safe_path
    from .target import TargetDetector
    safe_path(name)
    if name not in TargetDetector().detect(root, [name]).files:
        raise ValueError('TARGET_IDENTITY_NOT_PROVEN')
    for spec in (':' + name, 'HEAD:' + name):
        try:
            # cat-file has no textconv/filter/checkout or project command effects.
            oid = _git(root, 'rev-parse', '--verify', spec).decode('ascii').strip()
            if not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', oid):
                continue
            size = int(_git(root, 'cat-file', '-s', oid))
            if not 0 <= size <= MAX_FILE:
                continue
            raw = _git(root, 'cat-file', 'blob', oid)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            continue
        if len(raw) != size:
            continue
        # Recover standard checkout CRLF bytes only when the EXACT HMAC matches.
        # Never normalize the scanned bytes or treat normalized equality as proof.
        for content in (raw, raw.replace(b'\n', b'\r\n') if b'\r' not in raw else raw):
            if len(content) <= MAX_FILE and hmac.compare_digest(file_digest(key, content), expected):
                return content
    raise ValueError('NO_TRUSTED_PRE_EDIT_BYTES')


def detector_stamp(registry, plan, version, workspace):
    """Ephemeral equivalence identity, not output, persisted metadata or proof cache."""
    from .scanners import SemgrepAdapter, PatternSASTScanner
    from .sast import SemgrepEngineProvider
    from .toolchain import ToolStatus
    from .progress import NullProgressReporter, progress_context
    from .scanner_observation import observation
    adapter = next((a for a in registry.adapters if type(a) is SemgrepAdapter), None)
    if (adapter is None or type(adapter.engine_provider) is not SemgrepEngineProvider
            or adapter.normalize.__func__ is not PatternSASTScanner.normalize
            or not plan.pack.descriptor.bundled):
        return None
    # Use one context for both stamps; the temporary source directory must not
    # change tool/config selection. Resolution never installs anything.
    with progress_context(NullProgressReporter()), observation(str(workspace)):
        resolved = adapter.tool_manager.resolve('semgrep')
        if resolved.status != ToolStatus.READY or resolved.version != version:
            return None
        engine = adapter.tool_manager._probe_identity('semgrep', Path(resolved.path))
    pack = adapter.rule_packs.resolve()
    if engine is None or (pack.path, pack.checksum, pack.descriptor) != (plan.pack.path, plan.pack.checksum, plan.pack.descriptor):
        return None
    return (engine, version, pack.checksum,
            tuple(sorted((r.rule_id, r.rule_version) for r in plan.rules)))


def capture_detector(registry, observed, workspace):
    plan = observed['plans'].get('semgrep')
    run = next((r for r in observed['runs'] if r.scanner == 'semgrep'), None)
    if plan is None or run is None:
        return None
    try:
        return detector_stamp(registry, plan, run.version, workspace)
    except (ValueError, OSError, AttributeError):
        return None


def matched_occurrences(old, new, before, after):
    """Map exact unchanged source spans; moving lines do not invent new risk.

    Ambiguous or edited old spans are inconclusive, not a new occurrence. No
    source fragment/semantic digest is persisted in the family model.
    """
    a, b = before.splitlines(), after.splitlines()
    if len(a) + len(b) > 10000 or len(a) * len(b) > 4_000_000:
        raise ValueError('ATTRIBUTION_BUDGET_EXCEEDED')
    blocks = difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks()
    available = {(p['line_start'], p['line_end']) for p in new['occurrences']}
    for point in old['occurrences']:
        start, end = point['line_start'] - 1, point['line_end']
        if not 0 <= start < end <= len(a):
            raise ValueError('OCCURRENCE_IDENTITY_UNPROVEN')
        target = next(((start - i + j + 1, end - i + j) for i, j, length in blocks
                       if i <= start and end <= i + length), None)
        if target not in available:
            raise ValueError('OCCURRENCE_IDENTITY_UNPROVEN')
        available.remove(target)
    return len(old['occurrences']), len(available)


def attribute(core, root, previous, changed, current_digests, observation, result):
    """Return real pre-edit families only after complete equivalent detector proof."""
    from .findings import FindingNormalizer
    from .hook_runtime import covered, family_multiset
    from .models import ScanContext, ScanMode, RunStatus
    from .verification_policy import local_recheck
    result['first_scan_attribution_attempted'] = True
    result['first_scan_attribution_status'] = 'FIRST_SCAN_ATTRIBUTION_INCONCLUSIVE'
    started = time.perf_counter()
    try:
        risks = observation['families']
        targets = sorted({f['file_path'] for f in risks.values()})
        if not changed or not set(targets).issubset(changed):
            raise ValueError('TARGET_IDENTITY_NOT_PROVEN')
        if len(targets) > MAX_TARGETS:
            raise ValueError('ATTRIBUTION_BUDGET_EXCEEDED')
        plan = observation['plans'].get('semgrep')
        stamp = observation.get('attribution_detector')
        if (stamp is None or any(f['scanner_sources'] != ['semgrep'] or
                not covered(f, observation['runs'], observation['plans']) for f in risks.values())):
            raise ValueError('DETECTOR_NOT_EQUIVALENT')
        registry = core.managed_registry()
        if capture_detector(registry, observation, root) != stamp:
            raise ValueError('DETECTOR_NOT_EQUIVALENT')
        key = core.store.key(root)
        old_digests = previous.get('file_digests') or {}
        if any(name not in old_digests or name not in current_digests for name in targets):
            raise ValueError('TARGET_IDENTITY_NOT_PROVEN')
        before, after, total = {}, {}, 0
        for name in targets:
            before[name] = recover_bytes(root, name, old_digests[name], key)
            with (root / name).open('rb') as source:
                after[name] = source.read(MAX_FILE + 1)
            total += len(before[name]) + len(after[name])
            if len(after[name]) > MAX_FILE or total > MAX_TOTAL:
                raise ValueError('ATTRIBUTION_BUDGET_EXCEEDED')
        if any(file_digest(key, after[name]) != current_digests[name] for name in targets):
            raise ValueError('SOURCE_CHANGED_DURING_ATTRIBUTION')
        # Reuse the current selected rule/config set and normalization implementation.
        # Only risk-bearing changed files are materialized; no repo/manifests copied.
        pre_plan = replace(plan, files=tuple(targets),
            language_files={k:tuple(f for f in v if f in targets) for k,v in plan.language_files.items()},
            confirmed_rules=set(), scanned_files=set(), errored_files=set(), skipped_files={}, unscoped_error=False)
        adapter = next(a for a in registry.adapters if a.name == 'semgrep')
        with TemporaryDirectory(prefix='security-runtime-attribution-') as temporary:
            scoped = Path(temporary)
            for name, content in before.items():
                destination = scoped / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            context = ScanContext(str(scoped), ScanMode.QUICK, tuple(targets), rule_plan=pre_plan)
            expected_pre = detector_stamp(registry, plan, stamp[1], scoped)
            if expected_pre is None or expected_pre[1:] != stamp[1:]:
                raise ValueError('DETECTOR_NOT_EQUIVALENT')
            if 'scanner_invocation_count' in result:
                result['scanner_invocation_count'] += 1
            with local_recheck() as ledger, probe_scope() as prepared:
                findings, run = adapter.scan(context, FindingNormalizer(scoped))
            result['pre_edit_targeted_scan_run'] = ledger['engine_process_observed']
            result['pre_edit_targeted_scan_count'] = int(result['pre_edit_targeted_scan_run'])
            if (prepared.get('semgrep') != expected_pre[0] or
                    detector_stamp(registry, plan, run.version, scoped) != expected_pre):
                raise ValueError('DETECTOR_NOT_EQUIVALENT')
            run.provider = adapter.engine_provider.engine_id
            pre = {'families': family_multiset(findings, [run], {'semgrep':pre_plan}),
                   'runs':[run], 'plans':{'semgrep':pre_plan}}
        if (run.status != RunStatus.SUCCESS or not result['pre_edit_targeted_scan_run'] or
                run.version != stamp[1]):
            raise ValueError('PRE_EDIT_SCAN_INCOMPLETE')
        if capture_detector(registry, observation, root) != stamp:
            raise ValueError('DETECTOR_NOT_EQUIVALENT')
        result['attribution_scanner_equivalent'] = True
        existing, new = 0, 0
        for family_key, family in risks.items():
            if not covered(family, pre['runs'], pre['plans']):
                raise ValueError('PRE_EDIT_SCAN_INCOMPLETE')
            old = pre['families'].get(family_key)
            if old:
                a, b = matched_occurrences(old, family, before[family['file_path']], after[family['file_path']])
                existing += a; new += b
            else:
                new += family['count']
        result.update(pre_existing_risk_count=existing, newly_attributed_risk_count=new,
            first_scan_attribution_status='FIRST_SCAN_NEW_RISK_ATTRIBUTED' if new else 'FIRST_SCAN_EXISTING_RISK',
            first_scan_attribution_reason='ATTRIBUTION_VERIFIED')
        # Pre-only disappeared families are outside this presence-attribution task.
        return {k:v for k,v in pre['families'].items() if k in risks}
    except (ValueError, OSError, KeyError, AttributeError, TypeError) as exc:
        result['first_scan_attribution_reason'] = str(exc) if str(exc) in REASONS else 'PRE_EDIT_SCAN_INCOMPLETE'
        if result['first_scan_attribution_reason'] == 'DETECTOR_NOT_EQUIVALENT':
            result['attribution_scanner_equivalent'] = False
        return None
    finally:
        result['first_scan_attribution_ms'] = round((time.perf_counter()-started)*1000, 3)
