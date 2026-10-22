"""Bounded, source-free projections of existing scan execution receipts.

This optional module never executes checks or inspects a workspace. Counts
describe the captured check scope, not language or vulnerability completeness.
"""
from itertools import islice

CHECK_STATES = {'COMPLETED', 'PARTIAL', 'FAILED', 'NOT_RUN', 'IN_PROGRESS', 'UNKNOWN'}
EXECUTION_STATES = {'EXECUTED', 'FAILED', 'UNAVAILABLE', 'TIMEOUT', 'NO_CHANGES',
                    'NOT_APPLICABLE', 'NOT_COVERED', 'SKIPPED', 'CANCELLED', 'NOT_STARTED', 'RUNNING', 'UNKNOWN'}
COVERAGES = {'FULL', 'PARTIAL', 'MINIMAL', 'SCOPED', 'NONE', 'UNKNOWN'}
RULE_STATES = {'EXECUTED', 'PARTIAL', 'PLANNED', 'FAILED', 'UNAVAILABLE',
               'NOT_COVERED', 'NOT_APPLICABLE', 'SKIPPED', 'UNKNOWN'}
CAPABILITIES = {'CODE_SAST', 'SECRET_SCAN', 'DEPENDENCY_VULN', 'IAC_MISCONFIG',
    'CONTAINER_VULN', 'LICENSE_SCAN', 'SBOM', 'PACKAGE_RISK', 'AI_SKILL_SECURITY',
    'MCP_SECURITY_STATIC', 'MCP_SECURITY_DYNAMIC', 'AGENT_DYNAMIC_SECURITY',
    'AI_INFRA_VULN', 'LLM_JAILBREAK', 'MODEL_API_INTEGRITY', 'AGENT_RUNTIME_SECURITY',
    'AI_APP_SECURITY', 'OTHER'}
LANGUAGES = {'java', 'python', 'javascript', 'typescript', 'vue', 'go', 'php',
    'c', 'cpp', 'csharp', 'ruby', 'rust', 'kotlin', 'scala', 'swift', 'html',
    'xml', 'yaml', 'json', 'dockerfile', 'terraform', 'other'}
REASONS = {'NO_EXECUTION_EVIDENCE', 'NO_CHANGES', 'NOT_APPLICABLE', 'CHECK_FAILED',
    'CHECK_CANCELLED', 'SCANNER_UNAVAILABLE', 'SCANNER_TIMEOUT', 'SCANNER_FAILED',
    'SCANNER_SKIPPED', 'RULES_NOT_COVERED', 'RULES_PARTIAL', 'RULES_NOT_EXECUTED',
    'SOURCE_NOT_CURRENT', 'FILES_SKIPPED', 'SCOPED_CHECK', 'CAPABILITY_INCOMPLETE',
    'VUE_TEMPLATE_NOT_COVERED', 'VUE_SCRIPT_BLOCKS_ONLY', 'OBSERVATION_LIMIT',
    'PROVIDER_PARTIAL', 'OTHER_DIAGNOSTIC', 'TASK_NOT_STARTED', 'TASK_REVIEW_PENDING',
    'TASK_REVIEW_INCOMPLETE', 'SNAPSHOT_FILE_LIMIT', 'SNAPSHOT_BYTE_LIMIT',
    'BASELINE_INCOMPLETE', 'TASK_SCOPE_UNVERIFIED', 'REVIEW_CONTEXT_UNREAD',
    'REVIEW_CAPACITY_REQUIRED', 'TASK_STATIC_NOT_EXECUTED', 'TASK_STATIC_PARTIAL',
    'TASK_STATIC_EVIDENCE_UNKNOWN', 'TASK_CONTEXT_GAPS'}
SCOPES = {'SCRIPT_BLOCKS_ONLY', 'PLANNED_FILES', 'UNKNOWN'}
SCOPE_COUNTS = {'target_files','selected_files','skipped_files','changed_files',
                'unverified_files','review_units','reviewed_units','unread_ranges'}
MAX_ROWS = 24


def get(value, key, default=None):
    return value.get(key, default) if isinstance(value, dict) else getattr(value, key, default)


def count(value):
    return value if type(value) is int and 0 <= value <= 10**9 else None


def enum(value, values, default='UNKNOWN'):
    return value if isinstance(value, str) and value in values else default


def scan_check(scan):
    execution = enum(get(scan, 'execution_state'), EXECUTION_STATES)
    raw_status = get(scan, 'status')
    coverage = enum(get(scan, 'coverage'), COVERAGES)
    rules = get(scan, 'rule_coverage', {}) or {}
    rule_status = enum(get(rules, 'status'), RULE_STATES)
    reasons = set()
    if execution == 'UNKNOWN':
        reasons.add('NO_EXECUTION_EVIDENCE')
    if execution in {'NO_CHANGES', 'NOT_APPLICABLE'}:
        reasons.add(execution)
    if execution == 'FAILED':
        reasons.add('CHECK_FAILED')
    if execution == 'CANCELLED':
        reasons.add('CHECK_CANCELLED')
    if execution in {'UNAVAILABLE','TIMEOUT'}:
        reasons.add('SCANNER_'+execution)
    if coverage == 'SCOPED':
        reasons.add('SCOPED_CHECK')
    if rule_status == 'NOT_COVERED':
        reasons.add('RULES_NOT_COVERED')
    elif rule_status == 'PARTIAL':
        reasons.add('RULES_PARTIAL')
    elif rule_status in {'PLANNED', 'FAILED', 'UNAVAILABLE'}:
        reasons.add('RULES_NOT_EXECUTED')
    fixed = get(get(scan, 'scan_context', {}) or {}, 'fixed_input', {}) or {}
    if get(fixed, 'applicability') not in (None, 'CURRENT'):
        reasons.add('SOURCE_NOT_CURRENT')
    capabilities = []
    caps = get(scan, 'capability_results', {}) or {}
    limited = len(caps) > MAX_ROWS
    for name, state in islice(caps.items(), MAX_ROWS):
        state = enum(state, RULE_STATES)
        capabilities.append(dict(capability=enum(name, CAPABILITIES, 'OTHER'), status=state))
        if state not in {'EXECUTED', 'NOT_APPLICABLE'}:
            reasons.add('CAPABILITY_INCOMPLETE')
    runs = get(scan, 'scanner_runs', []) or []
    limited |= len(runs) > MAX_ROWS
    for run in runs[:MAX_ROWS]:
        reason = {'UNAVAILABLE':'SCANNER_UNAVAILABLE', 'TIMEOUT':'SCANNER_TIMEOUT',
                  'FAILED':'SCANNER_FAILED', 'SKIPPED':'SCANNER_SKIPPED',
                  'NOT_COVERED':'RULES_NOT_COVERED'}.get(get(run, 'status'))
        if reason:
            reasons.add(reason)
        if get(run, 'coverage_contract') == 'PARTIAL':
            reasons.add('PROVIDER_PARTIAL')
    languages = []
    providers = get(rules, 'providers', None)
    limited |= isinstance(providers, dict) and len(providers)>MAX_ROWS
    providers = list(islice(providers.values(), MAX_ROWS)) if isinstance(providers, dict) else [rules]
    # Keep provider receipts separate: a successful supplemental provider must
    # not mask an unavailable primary one. Only fixed enum language names leave.
    for provider in providers:
        per_language = get(provider, 'per_language', {}) or {}
        for language, value in islice(per_language.items(), MAX_ROWS+1):
            if len(languages) >= MAX_ROWS:
                limited = True
                break
            state = enum(get(value, 'status'), RULE_STATES)
            scope = enum(get(value, 'scope', 'PLANNED_FILES'), SCOPES)
            template = enum(get(value, 'template_status'), RULE_STATES)
            if language == 'vue' and template == 'NOT_COVERED':
                reasons.add('VUE_TEMPLATE_NOT_COVERED')
            if scope == 'SCRIPT_BLOCKS_ONLY':
                reasons.add('VUE_SCRIPT_BLOCKS_ONLY')
            languages.append(dict(language=enum(language, LANGUAGES, 'other'), status=state,
                scope=scope, template_status=template, **{key:count(get(value,key)) for key in
                ('selected_rules','executed_rules','target_files','scanned_files')}))
    profile = get(scan, 'target_profile', {}) or {}
    skipped = get(profile, 'skipped_files', None)
    if skipped:
        reasons.add('FILES_SKIPPED')
    profile_files = get(profile, 'files', None)
    if limited:
        reasons.add('OBSERVATION_LIMIT')
    status = ('NOT_RUN' if execution in {'NO_CHANGES','NOT_APPLICABLE','NOT_COVERED','SKIPPED'}
        else 'FAILED' if execution in {'FAILED','UNAVAILABLE','TIMEOUT','CANCELLED'}
        else 'PARTIAL' if raw_status == 'PARTIAL' or coverage in {'PARTIAL','MINIMAL','SCOPED'}
            or rule_status == 'PARTIAL' or reasons - {'NOT_APPLICABLE'}
        else 'COMPLETED' if raw_status == 'COMPLETED' and execution == 'EXECUTED'
        else 'UNKNOWN')
    if execution == 'UNKNOWN' and raw_status not in {'COMPLETED','PARTIAL'}:
        status = 'UNKNOWN'
    return dict(status=status, execution_state=execution, coverage=coverage,
        rule_status=rule_status, reason_codes=sorted(reasons), capabilities=capabilities,
        languages=languages, limited=limited, scope_counts=dict(
            target_files=len(profile_files) if isinstance(profile_files, (list,tuple)) else None,
            selected_files=count(get(rules, 'total_files')),
            skipped_files=len(skipped) if isinstance(skipped, (list,tuple)) else None))


def task_check(view):
    """Only the already-built task view; no authority lookup or source read."""
    static = view.get('static') or {}
    check = scan_check(static)
    phase = view.get('status')
    reasons = set(check['reason_codes']) - {'NO_EXECUTION_EVIDENCE'}
    progress = view.get('review_progress') or {}
    context = view.get('context_read_coverage') or {}
    limits = view.get('limitations') or []
    for limitation in limits[:MAX_ROWS]:
        code = limitation.get('reason') if isinstance(limitation, dict) else None
        if code in {'SNAPSHOT_READ_FILE_BUDGET','SNAPSHOT_INVENTORY_FILE_BUDGET',
                    'TASK_PREIMAGE_FILE_COUNT_BUDGET','SNAPSHOT_INVENTORY_ENTRY_BUDGET'}:
            reasons.add('SNAPSHOT_FILE_LIMIT')
        elif code in {'SNAPSHOT_READ_BYTE_BUDGET','SNAPSHOT_INLINE_TEXT_BYTE_BUDGET',
                      'TASK_PREIMAGE_TASK_BYTE_BUDGET','DIFF_BYTE_BUDGET'}:
            reasons.add('SNAPSHOT_BYTE_LIMIT')
        elif code in {'TASK_BEFORE_SOURCE_CAPTURE_INCOMPLETE','PREIMAGE_OR_TEXT_BUDGET_UNAVAILABLE',
                      'TASK_PREIMAGE_STORE_UNAVAILABLE','TASK_PREIMAGE_CONTENT_UNVERIFIED'}:
            reasons.add('BASELINE_INCOMPLETE')
        else:
            reasons.add('TASK_SCOPE_UNVERIFIED')
    if view.get('unverified_file_count'):
        reasons.add('TASK_SCOPE_UNVERIFIED')
    if context.get('unread_range_count'):
        reasons.add('REVIEW_CONTEXT_UNREAD')
    if context.get('gaps'):
        reasons.add('TASK_CONTEXT_GAPS')
    if static.get('status') == 'NOT_EXECUTED':
        reasons.add('TASK_STATIC_NOT_EXECUTED')
    if static and (static.get('coverage') in {'PARTIAL','MINIMAL','SCOPED'}
                   or static.get('status') in {'PARTIAL','FAILED','CANCELLED'}):
        reasons.add('TASK_STATIC_PARTIAL')
    if phase == 'ACTIVE':
        status, execution = 'IN_PROGRESS', 'NOT_STARTED'
        reasons.add('TASK_NOT_STARTED')
    elif phase in {'READY','REVIEWING','STATIC_RUNNING'}:
        status, execution = 'IN_PROGRESS', 'RUNNING'
        reasons.add('TASK_REVIEW_PENDING')
    elif phase == 'CAPACITY_REQUIRED':
        status, execution = 'PARTIAL', 'NOT_STARTED'
        reasons.add('REVIEW_CAPACITY_REQUIRED')
    elif phase == 'NO_CHANGES':
        status, execution = 'NOT_RUN', 'NO_CHANGES'
        reasons.add('NO_CHANGES')
    elif phase == 'COMPLETE':
        if not static:
            reasons.add('TASK_STATIC_NOT_EXECUTED')
        elif static.get('status') not in {'NO_CHANGES','NOT_APPLICABLE'} and (
                static.get('coverage') not in {'FULL','PARTIAL','MINIMAL','SCOPED'}
                or static.get('status') not in {'COMPLETED','SUCCESS','PARTIAL','FAILED','CANCELLED'}):
            reasons.add('TASK_STATIC_EVIDENCE_UNKNOWN')
        review = view.get('host_review') or {}
        partial = (bool(reasons) or review.get('coverage') not in {'FULL','REVIEWED'}
                   or bool(review.get('limitations'))
                   or progress.get('coverage') not in (None, 'FULL','REVIEWED'))
        status, execution = ('PARTIAL' if partial else 'COMPLETED'), 'EXECUTED'
        if partial:
            reasons.add('TASK_REVIEW_INCOMPLETE')
    elif phase in {'STALE','INCOMPLETE'}:
        status, execution = ('FAILED','FAILED') if static.get('status') in {'FAILED','CANCELLED'} else ('PARTIAL','UNKNOWN')
        reasons.add('TASK_REVIEW_INCOMPLETE')
    else:
        status, execution = 'UNKNOWN', 'UNKNOWN'
        reasons.add('NO_EXECUTION_EVIDENCE')
    limited = check['limited'] or len(limits)>MAX_ROWS or view.get('change_scope_truncated') is True
    if limited:
        reasons.add('OBSERVATION_LIMIT')
    check.update(status=status, execution_state=execution,
        coverage='FULL' if status=='COMPLETED' else 'PARTIAL' if status=='PARTIAL' else 'UNKNOWN',
        limited=limited, reason_codes=sorted(reasons))
    check['scope_counts'].update(changed_files=count(view.get('changed_file_count')),
        unverified_files=count(view.get('unverified_file_count')),
        review_units=count(progress.get('unit_count')), reviewed_units=count(progress.get('reviewed_unit_count')),
        unread_ranges=count(context.get('unread_range_count')))
    if isinstance(static.get('scope_files'),(list,tuple)):
        check['scope_counts']['selected_files']=len(static['scope_files'])
    return check


def validate_check(value):
    from .context_cost_worker import _mapping, _number
    value = _mapping(value, {'status','execution_state','coverage','rule_status',
        'reason_codes','capabilities','languages','scope_counts','limited'})
    out = {}
    for name, allowed in (('status', CHECK_STATES), ('execution_state', EXECUTION_STATES),
                           ('coverage', COVERAGES), ('rule_status', RULE_STATES)):
        if value.get(name) not in allowed:
            raise ValueError('INVALID_CHECK_STATE')
        out[name] = value[name]
    if type(value.get('limited')) is not bool:
        raise ValueError('INVALID_CHECK_LIMIT')
    out['limited'] = value['limited']
    reasons = value.get('reason_codes')
    if type(reasons) is not list or len(reasons) > len(REASONS) or any(r not in REASONS for r in reasons):
        raise ValueError('INVALID_CHECK_REASON')
    out['reason_codes'] = list(reasons)
    out['scope_counts'] = {}
    scope = _mapping(value['scope_counts'], SCOPE_COUNTS)
    for key in scope:
        out['scope_counts'][key] = None if scope.get(key) is None else _number(scope[key],10**9)
    out['capabilities'], out['languages'] = [], []
    for field in ('capabilities','languages'):
        rows = value[field]
        if type(rows) is not list or len(rows) > MAX_ROWS:
            raise ValueError('INVALID_CHECK_ROWS')
        for row in rows:
            if field == 'capabilities':
                row = _mapping(row, {'capability','status'})
                if row.get('capability') not in CAPABILITIES or row.get('status') not in RULE_STATES:
                    raise ValueError('INVALID_CHECK_CAPABILITY')
                out[field].append(dict(row))
            else:
                row = _mapping(row, {'language','status','scope','template_status',
                    'selected_rules','executed_rules','target_files','scanned_files'})
                for name, allowed in (('language',LANGUAGES),('status',RULE_STATES),
                                      ('scope',SCOPES),('template_status',RULE_STATES)):
                    if row.get(name) not in allowed:
                        raise ValueError('INVALID_CHECK_LANGUAGE')
                out[field].append({k:row[k] for k in ('language','status','scope','template_status')} |
                    {k:None if row.get(k) is None else _number(row[k],10**9) for k in
                        ('selected_rules','executed_rules','target_files','scanned_files')})
    return out
