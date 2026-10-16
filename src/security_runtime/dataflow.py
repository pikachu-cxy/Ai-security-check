"""Supplemental bounded AST dataflow. Never a whole-program or fix-absence proof."""
from dataclasses import dataclass, field, replace
import hashlib
import importlib.metadata
from pathlib import Path
import time

from .capabilities import Capability
from .flow_core import Analysis, Limit
from .models import ScannerRun
from .progress import checkpoint
from .rule_catalog import RuleRecord
from .rulepacks import ResolvedRulePack, RulePackDescriptor, RulePackClass, RuleProvenance


VERSION = '1.2.0'
PACK_ID = 'ai-security-bounded-dataflow'
CATEGORIES = {'sql-injection': 'CWE-89', 'path-traversal': 'CWE-22', 'command-injection': 'CWE-78'}
DEFAULT_CATEGORIES = frozenset({'sql-injection', 'path-traversal'})
DEFAULT_RULES = frozenset({('java','sql-injection'), ('python','sql-injection'), ('python','path-traversal')})
REFERENCES = tuple('https://cwe.mitre.org/data/definitions/' + cwe[4:] + '.html' for cwe in CATEGORIES.values())
RULES = tuple(RuleRecord(
    f'ai-security.dataflow.{language}.{category}', language, (language,), category, (cwe,),
    'ERROR', 'MEDIUM', 'BETA', 'Bounded resolved local calls', PACK_ID, VERSION, REFERENCES,
    {'origin': 'FIRST_PARTY', 'author': 'AI Security Runtime contributors', 'created_at': '2026-10-16',
     'references': list(REFERENCES), 'license': 'Apache-2.0', 'derived_from': ''},
    'bounded-ast-dataflow', 'security_runtime/dataflow.py', (extension,), 'tests/test_bounded_dataflow.py')
    for language, extension in (('java', '.java'), ('python', '.py')) for category, cwe in CATEGORIES.items())


def rule_pack():
    base = Path(__file__).parent
    identity = b''.join((base / name).read_bytes() for name in
                        ('dataflow.py', 'flow_core.py', 'flow_python.py', 'flow_java.py'))
    identity += ('javalang=' + importlib.metadata.version('javalang') + ';six=' + importlib.metadata.version('six')).encode()
    return ResolvedRulePack(RulePackDescriptor(
        PACK_ID, 'Bounded Java/Python dataflow', VERSION, 'AI Security Runtime',
        'AI Security Runtime contributors', 'Apache-2.0', 'https://www.apache.org/licenses/LICENSE-2.0',
        True, True, True, True, 'first-party local AST provider',
        RuleProvenance('FIRST_PARTY', 'AI Security Runtime contributors', '2026-10-16', REFERENCES, 'Apache-2.0'),
        True, RulePackClass.FIRST_PARTY), base, hashlib.sha256(identity).hexdigest(), RULES)


@dataclass
class DataflowPlan:
    pack: object
    files: tuple
    categories: frozenset = DEFAULT_CATEGORIES
    experimental: bool = False
    scanned_files: set = field(default_factory=set)
    errors: set = field(default_factory=set)

    @property
    def rules(self):
        return tuple(r for r in RULES if r.category in self.categories and
            (self.experimental or (r.language,r.category) in DEFAULT_RULES) and
            any(Path(f).suffix in r.target_extensions for f in self.files))

    def coverage(self, status='PLANNED'):
        per = {}
        for language, extension in (('java', '.java'), ('python', '.py')):
            targets = {f for f in self.files if f.endswith(extension)}
            if not targets: continue
            clean = targets & self.scanned_files - self.errors
            rules = [r.rule_id for r in self.rules if r.language == language]
            per[language] = {'available_rules': 3, 'selected_rules': len(rules),
                'executed_rules': len(rules) if clean else 0, 'selected_rule_ids': rules,
                'executed_rule_ids': rules if clean else [], 'target_files': len(targets), 'scanned_files': len(clean),
                'status': 'EXECUTED' if clean == targets else 'PARTIAL' if clean else 'NOT_COVERED'}
        state = 'PLANNED' if status == 'PLANNED' else 'EXECUTED' if self.files and set(self.files) <= self.scanned_files - self.errors else 'PARTIAL'
        return {'engine': 'native-dataflow', 'rule_pack_id': PACK_ID, 'rule_pack_version': VERSION,
                'rule_pack_checksum': self.pack.checksum, 'status': state, 'per_language': per,
                'total_selected': len(self.rules), 'total_executed': len(self.rules) if state == 'EXECUTED' else 0,
                'scope_files': list(self.files), 'total_files': len(self.files),
                'failed_files': sorted(self.errors),
                'whole_program_reachability': 'NOT_IMPLEMENTED', 'verification_scope_complete': False,
                'enabled_categories': sorted({r.category for r in self.rules}),
                'experimental_disabled_categories': sorted(set(CATEGORIES) - {r.category for r in self.rules}),
                'python_path_scope': 'EXPERIMENTAL_ALL_RESOLVED_PATHS' if self.experimental else 'RESOLVED_CROSS_FILE_CALLS_OR_IO_CODECS_OPEN',
                'limitations': ['Java 8 syntax; bounded local functions/imports and selected SDK APIs only.',
                    'Per batch: 80 targets, 256 context files, 8 MB, 1,000,000 abstract steps and call depth 6; exceeded scopes remain partial.',
                    'Large scans use bounded batches and stop starting new batches after 30 seconds; no full-program claim.',
                    'Reflection, dynamic imports, ambiguous overloads and unmodelled code remain unknown.',
                    'Default Python paths require resolved cross-file calls or an exact io.open/codecs.open sink; other intrafile paths remain experimental.',
                    'Execution of this analysis subset is not proof of complete dataflow or production exploitability.']}


class BoundedDataflowScanner:
    name = scanner_id = engine_id = 'native-dataflow'
    display_name = 'Java/Python 有界数据流分析'
    capabilities = frozenset({Capability.CODE_SAST})
    supported_languages = frozenset({'Java', 'Python'})
    supported_ecosystems = frozenset()
    filter_changed_lines = False
    verification_offline = True
    verification_scope_complete = False

    def __init__(self, *, experimental=False):
        # Broad path and command models remain experimental. The default path
        # extension promotes Python cross-file calls and exact io/codecs streams.
        self.experimental = experimental
        self.categories = frozenset(CATEGORIES) if experimental else DEFAULT_CATEGORIES

    def required_engines(self): return ()
    def version(self): return VERSION
    def supports(self, profile, context):
        return context.mode in {'release', 'feature'} and any(Path(f).suffix in {'.java', '.py'} for f in context.files)
    def plan_rules(self, profile, context):
        return DataflowPlan(rule_pack(), tuple(f for f in context.files if Path(f).suffix in {'.java', '.py'}), self.categories, self.experimental)
    def normalize(self, raw, normalizer):
        raise ValueError('Only freshly parsed local AST evidence is accepted')

    def scan(self, context, normalizer):
        started = time.monotonic()
        plan = context.rule_plan if isinstance(context.rule_plan, DataflowPlan) else self.plan_rules(None, context)
        if len(plan.files) > 80:
            found, runs, hashes = [], [], {}
            conflicting = False
            for start in range(0, len(plan.files), 80):
                checkpoint()
                if time.monotonic() - started > 30:
                    plan.errors.update(plan.files[start:])
                    break
                batch = plan.files[start:start + 80]
                part = DataflowPlan(plan.pack, batch, plan.categories, plan.experimental)
                added, receipt = self.scan(replace(context, files=batch, rule_plan=part), normalizer)
                found.extend(added)
                runs.append(receipt)
                plan.scanned_files.update(part.scanned_files)
                plan.errors.update(part.errors)
                for item in added:
                    for name, digest in item.technical_details['context_hashes'].items():
                        conflicting |= name in hashes and hashes[name] != digest
                        hashes[name] = digest
            stable = not conflicting and Analysis(Path(context.root).resolve(), hashes=hashes).stable()
            stable &= all(r.scanner_diagnostics['source_stable'] for r in runs)
            if not stable:
                found.clear()
                plan.errors.update(plan.files)
            coverage = plan.coverage('SUCCESS')
            return found, ScannerRun(self.name, VERSION, 'PARTIAL' if plan.errors else 'SUCCESS',
                round((time.monotonic()-started)*1000), len(found), provider=self.name,
                capabilities=(Capability.CODE_SAST,), coverage_contract='PARTIAL', rule_coverage=coverage,
                coverage_notes=coverage['limitations'], scanner_diagnostics={
                    'batches':len(runs), 'parsed_files':len(plan.scanned_files), 'source_stable':stable,
                    'abstract_steps':sum(r.scanner_diagnostics['abstract_steps'] for r in runs),
                    'context_gaps':[g for r in runs for g in r.scanner_diagnostics['context_gaps']][:30]})
        analysis = Analysis(Path(context.root).resolve(), targets=set(plan.files))
        from .flow_python import PythonFlow
        python = PythonFlow(analysis)
        java = None
        found = []
        for file in plan.files:
            checkpoint()
            try:
                if file.endswith('.py'): python.analyze(file)
                else:
                    if java is None:
                        from .flow_java import JavaFlow
                        java = JavaFlow(analysis)
                    java.analyze(file)
                plan.scanned_files.add(file)
            except (Limit, OSError, UnicodeError, RecursionError, ValueError, TypeError, IndexError, AttributeError) as exc:
                plan.errors.add(file)
                analysis.gaps.add((file, type(exc).__name__))
        stable = analysis.stable()
        if stable:
            for (file, line, category), trace in sorted(analysis.issues.items()):
                if category not in plan.categories or file in plan.errors: continue
                language = 'java' if file.endswith('.java') else 'python'
                rule = next((r for r in plan.rules if r.language == language and r.category == category), None)
                if rule is None: continue
                if category == 'path-traversal' and not plan.experimental and not (
                    (file,line,category) in analysis.stream_path_issues or
                    len({f for f,_,_ in trace}) > 1 and any(k == 'RESOLVED_CALL' for _,_,k in trace)):
                    continue
                finding = normalizer.make(scanner=self.name, category=category,
                    title='已解析的外部输入到达敏感操作', description='有界 AST 分析追踪到外部输入进入敏感参数；调用链和文件版本见证据，实际部署与可利用性仍需复核。',
                    severity='HIGH', confidence='MEDIUM', file_path=file, line=line,
                    evidence='source -> resolved local calls -> ' + category, rule_id=rule.rule_id)
                finding.technical_details.update(engine=self.name, rule_pack=PACK_ID,
                    rule_pack_version=VERSION, rule_pack_checksum=plan.pack.checksum, rule_version=VERSION,
                    cwe=list(rule.cwe), analysis_basis='BOUNDED_AST_ABSTRACT_INTERPRETATION',
                    path_default_basis=('EXACT_IO_CODECS_OPEN' if (file,line,category) in analysis.stream_path_issues else 'RESOLVED_CROSS_FILE_CALLS') if category == 'path-traversal' else None,
                    dataflow_trace=[{'file':f,'line':n,'kind':k} for f,n,k in trace],
                    context_hashes=dict(analysis.hashes), verification_scope_complete=False,
                    evidence_locator={'file_sha256':analysis.hashes.get(file), 'snapshot_reason':None})
                found.append(finding)
        else:
            plan.errors.update(plan.files)
        coverage = plan.coverage('SUCCESS')
        receipt = ScannerRun(self.name, VERSION, 'SUCCESS' if not plan.errors else 'PARTIAL',
            round((time.monotonic()-started)*1000), len(found), provider=self.name,
            capabilities=(Capability.CODE_SAST,), coverage_contract='PARTIAL', rule_coverage=coverage,
            coverage_notes=coverage['limitations'], scanner_diagnostics={
                'parsed_files':len(plan.scanned_files), 'context_files':len(analysis.hashes),
                'abstract_steps':analysis.steps, 'context_gaps':[{'file':f,'reason':r} for f,r in sorted(analysis.gaps)][:30],
                'context_gaps_truncated':len(analysis.gaps)>30, 'source_stable':stable})
        return found, receipt
