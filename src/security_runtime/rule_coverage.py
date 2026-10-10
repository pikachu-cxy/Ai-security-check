"""Plan applicable rules/files before preparation; account for engine evidence."""
from dataclasses import dataclass, field
from pathlib import Path
from .rule_catalog import EXTENSIONS, supports_language


@dataclass
class SASTRulePlan:
    pack: object
    rules: tuple
    files: tuple[str, ...]
    detected_languages: tuple[str, ...]
    language_files: dict[str, tuple[str, ...]]
    confirmed_rules: set[str] = field(default_factory=set)
    scanned_files: set[str] = field(default_factory=set)
    errored_files: set[str] = field(default_factory=set)
    unscoped_error: bool = False
    planning_diagnostics: dict = field(default_factory=dict)
    skipped_files: dict[str, str] = field(default_factory=dict)

    def observe(self, data, batch):
        def relative(value):
            return str(value).replace('\\','/')
        self.scanned_files.update(relative(name) for name in data.get('paths',{}).get('scanned',[]) if relative(name) in batch)
        selected={rule.rule_id for rule in self.rules}
        self.confirmed_rules.update(rule for rule in data.get('time',{}).get('rules',[]) if rule in selected)
        for skipped in data.get('paths', {}).get('skipped', []):
            path = relative(skipped.get('path', ''))
            if path not in batch or skipped.get('rule_id') not in (None, *selected):
                continue
            reason = skipped.get('reason')
            # Never persist engine details/prose: they may contain source or
            # credentials. A relevant skipped (file, rule) conservatively lowers
            # file proof even if the engine also lists that file as scanned.
            self.skipped_files[path] = reason if reason in {
                'binary', 'too_big', 'exceeded_size_limit', 'minified', 'wrong_language',
                'analysis_failed_parser_or_internal_error', 'insufficient_permissions',
                'semgrepignore_patterns_match', 'cli_include_flags_do_not_match',
                'cli_exclude_flags_match', 'excluded_by_config', 'irrelevant_rule',
                'too_many_matches', 'Gitignore_patterns_match', 'Nonexistent_file',
                'Dotfile', 'always_skipped'} else 'OTHER'
        for error in data.get('errors',[]):
            path=relative(error.get('path',''))
            if path in batch:
                self.errored_files.add(path)
            else:
                self.unscoped_error=True
        if data.get('skipped_rules'):
            self.unscoped_error=True

    def coverage(self, status='PLANNED'):
        per_language={}
        for language in self.detected_languages:
            available=[r for r in self.pack.catalog if supports_language(r, language) and (r.maturity!='EXPERIMENTAL' or not self.pack.descriptor.bundled)]
            selected=[r for r in self.rules if supports_language(r, language)]
            targets=set(self.language_files[language])
            clean=(self.scanned_files-self.errored_files-set(self.skipped_files))&targets
            executed=[r for r in selected if r.rule_id in self.confirmed_rules and any(Path(p).suffix.lower() in r.target_extensions for p in clean)]
            if self.unscoped_error:
                executed=[]
            if not selected:
                state='NOT_COVERED'
            elif status=='PLANNED':
                state='PLANNED'
            elif status=='UNAVAILABLE':
                state='UNAVAILABLE'
            elif status=='SUCCESS' and len(executed)==len(selected) and clean==targets and not self.unscoped_error:
                state='EXECUTED'
            elif executed:
                state='PARTIAL'
            else:
                state='FAILED'
            per_language[language]={'language':language,'available_rules':len(available),'selected_rules':len(selected),
                'executed_rules':len(executed),'selected_rule_ids':[r.rule_id for r in selected],
                'executed_rule_ids':[r.rule_id for r in executed],'applicable_categories':sorted({r.category for r in selected}),
                'frameworks':sorted({r.framework for r in selected if r.framework}), 'status':state,
                'target_files':len(targets),'scanned_files':len(clean)}
        states=[row['status'] for row in per_language.values()]
        aggregate=('NOT_APPLICABLE' if not states else 'EXECUTED' if all(s=='EXECUTED' for s in states)
            else 'PARTIAL' if any(s in {'EXECUTED','PARTIAL'} for s in states)
            else 'NOT_COVERED' if all(s=='NOT_COVERED' for s in states)
            else 'UNAVAILABLE' if any(s=='UNAVAILABLE' for s in states) and not any(s=='FAILED' for s in states)
            else 'PLANNED' if any(s=='PLANNED' for s in states) else 'FAILED')
        program = getattr(self.pack, 'program', None)
        capabilities = [c for c in program.capabilities if c.scanner_engine == 'semgrep' and
            any(r.rule_id in c.underlying_rule_ids for r in self.rules)] if program else []
        return {'engine':'semgrep','rule_pack_id':self.pack.descriptor.rule_pack_id,
            'rule_pack_version':self.pack.descriptor.version,'rule_pack_checksum':self.pack.checksum,
            'detected_languages':list(self.detected_languages),'per_language':per_language,'status':aggregate,
            'total_available':len({r.rule_id for r in self.pack.catalog}),'total_selected':len({r.rule_id for r in self.rules}),
            'total_executed':len({rid for row in per_language.values() for rid in row['executed_rule_ids']}),
            'total_files':len(self.files),'scope_files':list(self.files),
            'engine_skipped_count':len(self.skipped_files),
            'engine_skipped_targets':[{'path': name, 'reason': reason, 'source': 'SCANNER'}
                for name, reason in sorted(self.skipped_files.items())[:20]],
            'engine_skips_truncated':len(self.skipped_files)>20,
            'capability_program_version':program.version if program else None,
            'applicable_capabilities':len(capabilities),
            'capabilities':[{'capability_id':c.capability_id,'title':c.title,'maturity':c.maturity,
                'auto_fix_eligible':c.auto_fix_eligible,
                'frameworks':list(c.frameworks),
                'framework_applicability':'ENGINE_TYPED_PATTERNS; CONSERVATIVE_LANGUAGE_EXTENSION_PLAN',
                'selected_rule_ids':[r.rule_id for r in self.rules if r.rule_id in c.underlying_rule_ids]}
                for c in capabilities],
            'execution_evidence':'Semgrep time.rules and paths.scanned; errors/skipped targets/rules lower coverage'}


def plan_rules(pack, files):
    language_files={language:tuple(name for name in files if Path(name).suffix.lower() in extensions)
                    for language,extensions in EXTENSIONS.items()}
    language_files={language:names for language,names in language_files.items() if names}
    # An explicit mapper XML edit can have applicable framework rules even
    # when no .java file changed. Typed mapper patterns decide the match;
    # never expand the file scope merely to infer the repository framework.
    xml=tuple(name for name in files if Path(name).suffix.lower()=='.xml')
    if xml and any(r.language=='java' and '.xml' in r.target_extensions for r in pack.catalog):
        language_files['java']=language_files.get('java',())+xml
    program = getattr(pack, 'program', None)
    selected=tuple(rule for rule in pack.catalog if (rule.maturity!='EXPERIMENTAL' or not pack.descriptor.bundled)
        and (program is None or program.enabled(rule.rule_id))
        and any(supports_language(rule, language) and
                any(Path(name).suffix.lower() in rule.target_extensions for name in names)
                for language, names in language_files.items()))
    targets=tuple(name for name in files if any(Path(name).suffix.lower() in rule.target_extensions for rule in selected))
    # Uncovered files are described in the plan but never passed to the engine.
    # Keep recognized inputs without an applicable parser/rule in the coverage
    # denominator (for example .vue beside .js); never silently discard them.
    return SASTRulePlan(pack,selected,targets,tuple(sorted(language_files)),language_files)
