"""Bounded first-party lexical checks for dynamic ECMAScript Function bodies.

This provider checks explicit local files, without starting an external engine.
It establishes a dangerous syntax candidate, not input reachability, the runtime
builtin binding, or arbitrary JavaScript semantics. Comments, quoted strings and
regular expression literals are not executable syntax. Template interpolations
are inspected separately so executable expressions inside templates remain in
scope. Rule absence is evidence about these canonical constructor spellings only.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import time

from .capabilities import Capability
from .equivalence import equivalence_key
from .findings import FindingNormalizer
from .local_evidence import WorkspaceReader
from .models import Finding, RunStatus, ScanContext, ScannerRun
from .progress import checkpoint
from .rule_catalog import RuleRecord
from .rulepacks import ResolvedRulePack, RulePackClass, RulePackDescriptor, RuleProvenance


RULE_ID = 'ai-security.javascript.dynamic-function'
VERSION = '1.0.0'
PACK_ID = 'ai-security-native-js'
EXTENSIONS = frozenset({'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'})
MAX_FILES = 1_000
MAX_TOTAL_BYTES = 8_000_000
MAX_TOKENS = 200_000
MAX_TEMPLATE_DEPTH = 32
MAX_CANDIDATE_WORK = 1_000_000
MAX_CANDIDATES = 1_000
REFERENCES = ('https://cwe.mitre.org/data/definitions/95.html',
              'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function')

DESCRIPTOR = RulePackDescriptor(
    PACK_ID, 'AI Security Runtime native JavaScript checks', VERSION,
    'AI Security Runtime', 'Copyright AI Security Runtime contributors',
    'Apache-2.0', 'https://www.apache.org/licenses/LICENSE-2.0',
    True, True, True, True, 'bundled first-party local Python provider',
    RuleProvenance('FIRST_PARTY', 'AI Security Runtime contributors', '2026-10-12',
                   REFERENCES, 'Apache-2.0'), True, RulePackClass.FIRST_PARTY)
RULE = RuleRecord(
    RULE_ID, 'javascript', ('javascript', 'typescript'), 'code-injection',
    ('CWE-95',), 'WARNING', 'HIGH', 'BETA', 'ECMAScript Function constructor and direct eval',
    PACK_ID, VERSION, REFERENCES,
    {'origin': 'FIRST_PARTY', 'author': 'AI Security Runtime contributors',
     'created_at': '2026-10-12', 'references': list(REFERENCES),
     'license': 'Apache-2.0', 'derived_from': ''},
    'bounded-lexical-candidate', 'security_runtime/dynamic_function.py',
    tuple(sorted(EXTENSIONS)), 'tests/test_dynamic_function.py')


def rule_pack():
    # Implementation bytes are part of the identity. A code/config change must
    # not turn a prior provider's absence into proof under a different rule.
    try:
        implementation = Path(__file__).read_bytes()
    except OSError:
        raise ValueError('NATIVE_RULE_IMPLEMENTATION_UNAVAILABLE') from None
    metadata = json.dumps(asdict(RULE), sort_keys=True, separators=(',', ':')).encode()
    checksum = hashlib.sha256(implementation + metadata).hexdigest()
    return ResolvedRulePack(DESCRIPTOR, Path(__file__).parent, checksum, (RULE,))


@dataclass
class NativeFunctionRulePlan:
    pack: ResolvedRulePack
    files: tuple[str, ...]
    rules: tuple[RuleRecord, ...] = (RULE,)
    confirmed_rules: set[str] = field(default_factory=set)
    scanned_files: set[str] = field(default_factory=set)
    errored_files: set[str] = field(default_factory=set)
    skipped_files: dict[str, str] = field(default_factory=dict)
    unscoped_error: bool = False

    def coverage(self, status='PLANNED'):
        clean = self.scanned_files - self.errored_files - set(self.skipped_files)
        executed = RULE_ID in self.confirmed_rules and bool(clean)
        complete = set(self.files) == clean and not self.unscoped_error
        state = ('NOT_APPLICABLE' if not self.files else 'PLANNED' if status == 'PLANNED'
                 else 'EXECUTED' if executed and complete else 'PARTIAL' if executed else 'FAILED')
        per_language = {}
        for language, extensions in (('javascript', {'.js', '.jsx', '.mjs', '.cjs'}),
                                     ('typescript', {'.ts', '.tsx'})):
            targets = {name for name in self.files if Path(name).suffix.lower() in extensions}
            if targets:
                per_language[language] = {
                    'language': language, 'available_rules': 1, 'selected_rules': 1,
                    'executed_rules': int(executed and bool(clean & targets)),
                    'selected_rule_ids': [RULE_ID],
                    'executed_rule_ids': [RULE_ID] if executed and clean & targets else [],
                    'applicable_categories': ['code-injection'],
                    'target_files': len(targets), 'scanned_files': len(clean & targets),
                    'status': 'EXECUTED' if targets <= clean else 'PARTIAL' if clean & targets else state}
        return {'engine': 'native-js-function', 'rule_pack_id': PACK_ID,
                'rule_pack_version': VERSION, 'rule_pack_checksum': self.pack.checksum,
                'status': state, 'detected_languages': list(per_language),
                'per_language': per_language, 'total_available': 1,
                'total_selected': int(bool(self.files)), 'total_executed': int(executed),
                'total_files': len(self.files), 'scope_files': list(self.files),
                'engine_skipped_count': len(self.skipped_files),
                'engine_skipped_targets': [{'path': name, 'reason': reason, 'source': 'SCANNER'}
                                           for name, reason in sorted(self.skipped_files.items())[:20]],
                'execution_evidence': 'Fresh bounded local read and lexical traversal of each explicit file.',
                'limitations': ['Canonical Function/globalThis.Function/window.Function/global.Function and direct eval calls only.',
                                'No cross-file input reachability, alias analysis or builtin binding proof.',
                                'Literal-only constructor arguments are outside this dynamic-input rule.']}


class LexicalLimit(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int
    dynamic: bool = False
    children: tuple[tuple['Token', ...], ...] = ()


_REGEX_PREFIX = frozenset({'=', '(', '[', '{', ':', ',', ';', 'return', 'throw',
                           'case', '=>', '!', '&&', '||', '?', '??'})


def _constant(tokens):
    """Only a conservative literal/parentheses/+ subset; never evaluate code."""
    return bool(tokens) and any(t.kind in {'STRING', 'NUMBER', 'TEMPLATE'} for t in tokens) and all(
        t.kind in {'STRING', 'NUMBER'} or t.kind == 'TEMPLATE' and not t.dynamic or
        t.value in {'+', '(', ')'} for t in tokens)


class _Lexer:
    def __init__(self, source):
        self.source = source
        self.count = 0

    def _quoted(self, index, quote):
        source, end = self.source, index + 1
        while end < len(source):
            if source[end] == '\\':
                end += 2
            elif source[end] == quote:
                return end + 1
            elif source[end] in '\r\n':
                raise LexicalLimit('UNTERMINATED_STRING')
            else:
                end += 1
        raise LexicalLimit('UNTERMINATED_STRING')

    def tokens(self, index=0, *, template_expression=False, depth=0):
        if depth > MAX_TEMPLATE_DEPTH:
            raise LexicalLimit('TEMPLATE_DEPTH_EXCEEDED')
        source, output, braces = self.source, [], 0
        while index < len(source):
            start, char = index, source[index]
            if char.isspace():
                index += 1
                continue
            if source.startswith('//', index):
                newline = source.find('\n', index + 2)
                index = len(source) if newline < 0 else newline + 1
                continue
            if source.startswith('/*', index):
                closing = source.find('*/', index + 2)
                if closing < 0:
                    raise LexicalLimit('UNTERMINATED_COMMENT')
                index = closing + 2
                continue
            if char == '}' and template_expression and braces == 0:
                return tuple(output), index + 1
            if char in ('"', "'"):
                index = self._quoted(index, char)
                token = Token('STRING', '', start, index)
            elif char == '`':
                index += 1
                children = []
                while index < len(source):
                    if source[index] == '\\':
                        index += 2
                    elif source[index] == '`':
                        index += 1
                        break
                    elif source.startswith('${', index):
                        child, index = self.tokens(index + 2, template_expression=True, depth=depth + 1)
                        children.append(child)
                    else:
                        index += 1
                else:
                    raise LexicalLimit('UNTERMINATED_TEMPLATE')
                token = Token('TEMPLATE', '', start, index,
                              any(not _constant(child) for child in children), tuple(children))
            elif char == '/' and (not output or output[-1].value in _REGEX_PREFIX):
                index += 1
                in_class = False
                while index < len(source):
                    if source[index] == '\\':
                        index += 2
                    elif source[index] in '\r\n':
                        raise LexicalLimit('UNTERMINATED_REGEX')
                    elif source[index] == '[':
                        in_class = True
                        index += 1
                    elif source[index] == ']':
                        in_class = False
                        index += 1
                    elif source[index] == '/' and not in_class:
                        index += 1
                        while index < len(source) and source[index].isalpha():
                            index += 1
                        break
                    else:
                        index += 1
                else:
                    raise LexicalLimit('UNTERMINATED_REGEX')
                token = Token('REGEX', '', start, index)
            elif char.isalpha() or char in '_$':
                index += 1
                while index < len(source) and (source[index].isalnum() or source[index] in '_$'):
                    index += 1
                token = Token('IDENTIFIER', source[start:index], start, index)
            elif char.isdigit():
                index += 1
                while index < len(source) and (source[index].isalnum() or source[index] in '._'):
                    index += 1
                token = Token('NUMBER', '', start, index)
            else:
                index += 1
                if source[start:index + 1] in {'?.', '=>', '&&', '||', '??'}:
                    index += 1
                value = source[start:index]
                if value == '{':
                    braces += 1
                elif value == '}':
                    braces -= 1
                    if braces < 0:
                        raise LexicalLimit('UNBALANCED_BRACES')
                token = Token('PUNCTUATION', value, start, index)
            output.append(token)
            self.count += 1
            if self.count > MAX_TOKENS:
                raise LexicalLimit('TOKEN_BUDGET_EXCEEDED')
        if template_expression:
            raise LexicalLimit('UNTERMINATED_TEMPLATE_EXPRESSION')
        return tuple(output), index


def _arguments(tokens, opening, budget):
    arguments, current, stack = [], [], []
    pairs = {')': '(', ']': '[', '}': '{'}
    # Iterate indices rather than slicing the remaining file for every call.
    # Nested/adversarial calls share a work budget with all template children.
    for index in range(opening + 1, len(tokens)):
        token = tokens[index]
        budget[0] += 1
        if budget[0] > MAX_CANDIDATE_WORK:
            raise LexicalLimit('CALL_ANALYSIS_BUDGET_EXCEEDED')
        if token.value == ')' and not stack:
            arguments.append(tuple(current))
            return arguments, token
        if token.value == ',' and not stack:
            arguments.append(tuple(current))
            current = []
            continue
        if token.value in {'(', '[', '{'}:
            stack.append(token.value)
        elif token.value in pairs:
            if not stack or stack.pop() != pairs[token.value]:
                raise LexicalLimit('UNBALANCED_FUNCTION_ARGUMENTS')
        current.append(token)
    raise LexicalLimit('UNTERMINATED_FUNCTION_CALL')


def _identifiers(tokens):
    values = []
    for token in tokens:
        if token.kind == 'IDENTIFIER' and token.value not in {'return', 'true', 'false', 'null', 'undefined'}:
            values.append(token.value)
        for child in token.children:
            values.extend(_identifiers(child))
    return sorted(set(values))[:16]


def _candidates(tokens, budget=None):
    budget = budget if budget is not None else [0, 0]
    for index, token in enumerate(tokens):
        for child in token.children:
            yield from _candidates(child, budget)
        if token.kind != 'IDENTIFIER' or token.value not in {'Function', 'eval'}:
            continue
        previous = tokens[index - 1].value if index else ''
        start = token
        api = token.value
        if previous == 'function':
            continue
        if previous in {'.', '?.'}:
            if token.value == 'eval':
                continue
            qualifier = tokens[index - 2].value if index >= 2 else ''
            if qualifier not in {'globalThis', 'window', 'global'}:
                continue
            if index >= 3 and tokens[index - 3].value in {'.', '?.'}:
                continue
            start, api = tokens[index - 2], qualifier + '.Function'
        elif previous == 'new':
            start = tokens[index - 1]
        opening = index + 1
        if opening < len(tokens) and tokens[opening].value == '?.':
            opening += 1
        if opening >= len(tokens) or tokens[opening].value != '(':
            continue
        arguments, end = _arguments(tokens, opening, budget)
        dynamic = [argument for argument in arguments if argument and not _constant(argument)]
        if not dynamic:
            continue
        budget[1] += 1
        if budget[1] > MAX_CANDIDATES:
            raise LexicalLimit('CANDIDATE_BUDGET_EXCEEDED')
        identifiers = _identifiers(tuple(t for argument in dynamic for t in argument))
        yield {'start': start.start, 'end': end.end, 'api': api,
               'inputs': identifiers, 'argument_kind': 'TEMPLATE_INTERPOLATION' if any(
                   t.kind == 'TEMPLATE' and t.dynamic for arg in dynamic for t in arg) else 'DYNAMIC_EXPRESSION'}


class NativeFunctionScanner:
    """Local canonical-call candidate provider with exact-file recheck evidence."""
    name = scanner_id = engine_id = 'native-js-function'
    display_name = 'JavaScript 动态代码快速检查'
    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({'JavaScript', 'TypeScript'})
    supported_ecosystems = frozenset()
    filter_changed_lines = True
    verification_offline = True
    verification_scope_complete = True

    def required_engines(self):
        return ()

    def version(self):
        return VERSION

    def input_bindings(self):
        from .scan_request import ScanBinding
        checksum = rule_pack().checksum
        return (ScanBinding('RULES', PACK_ID, checksum),
                ScanBinding('TOOL', self.engine_id, checksum))

    def supports(self, profile, context):
        return any(Path(name).suffix.lower() in EXTENSIONS for name in context.files)

    def plan_rules(self, profile, context):
        return NativeFunctionRulePlan(rule_pack(), tuple(dict.fromkeys(
            name for name in context.files if Path(name).suffix.lower() in EXTENSIONS)))

    def normalize(self, raw, normalizer):
        raise ValueError('Native Function provider only accepts freshly read local files')

    def scan(self, context: ScanContext, normalizer: FindingNormalizer):
        started = time.monotonic()
        try:
            plan = context.rule_plan if isinstance(context.rule_plan, NativeFunctionRulePlan) else self.plan_rules(None, context)
            if plan.pack.checksum != rule_pack().checksum:
                raise ValueError('NATIVE_RULE_IDENTITY_CHANGED')
            if context.input_view is not None and any(binding not in context.input_view.request.bindings
                    for binding in self.input_bindings()):
                raise ValueError('NATIVE_CAPTURED_IDENTITY_CHANGED')
        except (OSError, ValueError):
            return [], ScannerRun(self.name, VERSION, RunStatus.FAILED,
                round((time.monotonic() - started) * 1000), error_code='NATIVE_RULE_IDENTITY_UNAVAILABLE',
                error_summary='本地动态代码规则身份无法核对，本次未完成检查。',
                remediation='恢复匹配的内建规则文件后重新检查。',
                coverage_contract='NONE', capabilities=(Capability.CODE_SAST,), provider=self.engine_id,
                provider_role='SUPPLEMENTAL')
        findings = []
        total_bytes = 0
        errors = {}
        try:
            reader = WorkspaceReader(context.root)
        except (OSError, ValueError) as exc:
            plan.unscoped_error = True
            return [], self._run(plan, started, [], 'WORKSPACE_UNAVAILABLE')
        for index, name in enumerate(plan.files):
            checkpoint()
            try:
                if index >= MAX_FILES:
                    raise LexicalLimit('FILE_BUDGET_EXCEEDED')
                raw, text = reader.read(name)
                total_bytes += len(raw)
                if total_bytes > MAX_TOTAL_BYTES:
                    raise LexicalLimit('TOTAL_BYTE_BUDGET_EXCEEDED')
                candidates = []
                if 'Function' in text or 'eval' in text:
                    tokens, _ = _Lexer(text).tokens()
                    candidates = list(_candidates(tokens))
                file_hash = hashlib.sha256(raw).hexdigest()
                for candidate in candidates:
                    findings.append(self._finding(candidate, text, name, file_hash, plan, normalizer))
                plan.scanned_files.add(name)
                plan.confirmed_rules.add(RULE_ID)
            except (OSError, ValueError) as exc:
                reason = str(exc) if isinstance(exc, LexicalLimit) else getattr(exc, 'reason', 'LOCAL_READ_FAILED')
                errors[name] = reason
                plan.errored_files.add(name)
                plan.skipped_files[name] = reason
        identity_verified = plan.pack.checksum == rule_pack().checksum
        if not identity_verified:
            plan.unscoped_error = True
        run = self._run(plan, started, findings,
            'NATIVE_RULE_IDENTITY_CHANGED' if not identity_verified else 'LOCAL_SCOPE_INCOMPLETE' if errors else '')
        run.scanner_diagnostics.update(bytes_read=total_bytes,
            skipped_targets=[{'path': name, 'reason': reason} for name, reason in sorted(errors.items())[:20]])
        if context.input_view is not None:
            run.scanner_diagnostics['execution_binding'] = dict(contract='scanner-execution-binding-v1',
                tool=plan.pack.checksum, data=None, data_required=False,
                verified=identity_verified, data_status='VERIFIED')
        return findings, run

    def _run(self, plan, started, findings, error=''):
        coverage = plan.coverage('SUCCESS')
        status = RunStatus.SUCCESS if plan.scanned_files and not plan.unscoped_error else (
            RunStatus.NOT_APPLICABLE if not plan.files else RunStatus.FAILED)
        return ScannerRun(self.name, VERSION, status, round((time.monotonic() - started) * 1000),
            len(findings), error_code=error,
            error_summary='部分目标未完成动态代码检查，不能据此确认规则已消除。' if error else '',
            remediation='检查文件可读性、语法和扫描范围后重新检查。' if error else '',
            capabilities=(Capability.CODE_SAST,), provider=self.engine_id, provider_role='SUPPLEMENTAL',
            coverage_contract='FULL' if coverage['status'] == 'EXECUTED' else 'PARTIAL' if plan.scanned_files else 'NONE',
            coverage_notes=coverage['limitations'], rule_coverage=coverage,
            scanner_diagnostics={'local_read_observed': bool(plan.scanned_files),
                                 'engine_process_observed': False,
                                 'rule_execution': 'FRESH_LOCAL_LEXICAL_TRAVERSAL'})

    def _finding(self, candidate, text, name, file_hash, plan, normalizer):
        line = text.count('\n', 0, candidate['start']) + 1
        end_line = text.count('\n', 0, candidate['end']) + 1
        start_column = candidate['start'] - text.rfind('\n', 0, candidate['start'])
        end_column = candidate['end'] - text.rfind('\n', 0, candidate['end'])
        values = '、'.join(candidate['inputs']) or '动态表达式'
        direct_eval = candidate['api'] == 'eval'
        description = (f'eval 将含 {values} 的动态参数直接作为 JavaScript 执行；'
                       '如果外部输入能够到达这里，可能造成任意 JavaScript 代码执行。' if direct_eval else
                       f'{candidate["api"]} 将含 {values} 的动态参数编译为可执行代码；'
                       '如果外部输入能够到达这里且生成的函数被执行，可能造成任意 JavaScript 代码执行。')
        finding = normalizer.make(scanner=self.name, category='code-injection',
            title='动态字符串被编译为 JavaScript 代码',
            description=description,
            severity='HIGH', confidence='HIGH', file_path=name, line=line,
            evidence=f'{candidate["api"]}(<dynamic input: {values}>)', rule_id=RULE_ID)
        finding.line_end = end_line
        finding.plain_title = '输入内容可能被当作代码执行'
        finding.impact = ('若用户可控制 eval 的动态参数，可能执行服务进程可访问的 JavaScript 操作。' if direct_eval else
                          '若用户可控制动态参数，且生成的函数随后执行，可能执行服务进程可访问的 JavaScript 操作。')
        finding.fix_advice = '算术场景改用限定运算符和语法的解析器，并明确支持的表达式范围；'
        finding.fix_advice += '不要只过滤几个字符。修改后复查原位置的安全风险。'
        finding.technical_details.update(
            rule_pack=PACK_ID, rule_pack_version=VERSION, rule_pack_checksum=plan.pack.checksum,
            rule_version=VERSION, engine=self.engine_id, dangerous_api=candidate['api'],
            dynamic_inputs=candidate['inputs'], sink_argument_kind=candidate['argument_kind'],
            source_reachability='NOT_ANALYZED', builtin_binding='NOT_PROVEN',
            confidence_scope='DYNAMIC_ARGUMENT_SYNTAX_ONLY', exploitability='UNCONFIRMED',
            candidate_basis='CANONICAL_DYNAMIC_CODE_API_WITH_NON_LITERAL_ARGUMENT',
            execution_conditions=['External input reaches a dynamic constructor argument.',
                                  'The referenced API is the ECMAScript builtin.'] + (
                                      [] if direct_eval else ['The generated function is executed.']),
            evidence_locator={'start_column': start_column, 'end_column': end_column,
                              'file_sha256': file_hash, 'snapshot_reason': None})
        finding.equivalence_key = equivalence_key(finding)
        return finding


def quick_function_candidate_scope(root, files, *, has_native_family=False):
    """Conservatively select a limited fast Hook scope; never claim full SAST.

    Retained native findings keep their original provider after a fix even when
    the constructor has disappeared. Other files/checks require the normal plan.
    Any unreadable or lexically unsupported scope falls back to that normal plan.
    """
    names = tuple(dict.fromkeys(files))
    result = {'eligible': False, 'scope_files': list(names),
              'coverage_scope': 'CANONICAL_DYNAMIC_CODE_ONLY',
              'omitted_code_checks': 'Other Semgrep JavaScript/TypeScript rules are not executed by this provider.',
              'reason': 'NON_JAVASCRIPT_SCOPE', 'candidate_files': []}
    if not names or any(Path(name).suffix.lower() not in EXTENSIONS for name in names):
        return result
    if len(names) > MAX_FILES:
        result['reason'] = 'FILE_BUDGET_EXCEEDED'
        return result
    total = 0
    try:
        reader = WorkspaceReader(root)
        for name in names:
            checkpoint()
            raw, text = reader.read(name)
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise LexicalLimit('TOTAL_BYTE_BUDGET_EXCEEDED')
            if 'Function' in text or 'eval' in text:
                tokens, _ = _Lexer(text).tokens()
                if next(_candidates(tokens), None) is not None:
                    result['candidate_files'].append(name)
        result['eligible'] = has_native_family or bool(result['candidate_files'])
        result['reason'] = ('RECHECK_ORIGINAL_NATIVE_FAMILY' if has_native_family
                            else 'DYNAMIC_CODE_CANDIDATE' if result['eligible'] else 'NO_NATIVE_CANDIDATE')
    except (OSError, ValueError) as exc:
        result['reason'] = str(exc) if isinstance(exc, LexicalLimit) else getattr(exc, 'reason', 'LOCAL_READ_FAILED')
    return result
