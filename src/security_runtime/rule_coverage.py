"""Plan applicable rules/files before preparation; account for engine evidence."""
from dataclasses import dataclass, field
from .rule_catalog import supports_language, supports_file, is_vue_template_rule
from .sast_file_types import NATIVE, TEXT, TEXT_LANGUAGES, TS_PROJECTION, VUE_SCRIPT, file_type


def _relative(value):
    return str(value).replace('\\', '/')


def _rule_for_language(rule, language, classified):
    capability, _ = classified
    if language in TEXT_LANGUAGES:
        return language in rule.engine_languages and capability.mode != VUE_SCRIPT
    if language == 'template':
        return TEXT_LANGUAGES.issuperset(rule.engine_languages)
    return supports_language(rule, language) and (
        language == 'vue' or capability.mode != TEXT or capability.language == 'xml')


@dataclass
class BatchProof:
    """Engine timing lists rule IDs per invocation, never per file."""
    clean: dict
    timed: set
    hits: dict
    allowed_rules: set | None
    mode: str


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
    embedded_coverage: dict = field(default_factory=dict)
    engine_id: str = 'opengrep'
    file_types: dict = field(default_factory=dict)
    rule_gaps: dict = field(default_factory=dict)
    proof_index: dict = field(default_factory=dict)

    def observe(self, data, batch, *, sources=None, allowed_rules=None, mode=NATIVE, path_key=_relative):
        """Record one process before merging paths, retaining its exact inputs."""
        sources = sources if sources is not None else {path_key(name): (name, None) for name in batch}
        source = lambda name: sources.get(path_key(name))
        scanned = {path_key(name) for name in data.get('paths',{}).get('scanned',[]) if source(name)}
        self.scanned_files.update(sources[key][0] for key in scanned)
        selected={rule.rule_id for rule in self.rules}
        timed = selected.intersection(data.get('time',{}).get('rules',[]))
        self.confirmed_rules.update(timed)
        failed = set()
        unscoped = bool(data.get('skipped_rules'))
        for skipped in data.get('paths', {}).get('skipped', []):
            item = source(skipped.get('path', ''))
            if item is None or (skipped.get('rule_id') is not None and skipped['rule_id'] not in selected):
                continue
            path, _ = item
            failed.add(path_key(skipped['path']))
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
            item = source(error.get('path', ''))
            if item:
                failed.add(path_key(error['path']))
                self.errored_files.add(item[0])
            else:
                unscoped = True
        self.unscoped_error |= unscoped
        clean = {}
        clean_keys = scanned - failed
        for key in clean_keys:
            name, analyzer = sources[key]
            # A second block may share the original name. Receipts are first
            # assessed against the actual projected target.
            clean.setdefault(name, set()).add(analyzer)
        hits = {}
        for finding in data.get('results', []):
            item = source(finding.get('path', ''))
            if item and path_key(finding['path']) in clean_keys:
                hits.setdefault(item[0], set()).add(finding.get('check_id'))
        if not unscoped:
            receipt = BatchProof(clean, timed, hits, allowed_rules, mode)
            for name in clean:
                self.proof_index.setdefault(name, []).append(receipt)

    def proves(self, rule, name):
        classified = self.file_types.get(name) or file_type(name)
        capability, _ = classified
        if capability is None or not supports_file(rule, name, classified=classified):
            return False
        if capability.mode != VUE_SCRIPT and name in self.errored_files:
            return False
        for receipt in self.proof_index.get(name, ()):
            analyzers = receipt.clean.get(name)
            if not analyzers or (receipt.allowed_rules is not None and rule.rule_id not in receipt.allowed_rules):
                continue
            if capability.mode == VUE_SCRIPT and (
                    is_vue_template_rule(rule) != (receipt.mode == NATIVE)):
                continue
            if capability.mode == TS_PROJECTION and (
                    TEXT_LANGUAGES.issuperset(rule.engine_languages) != (receipt.mode == TEXT)):
                continue
            if not any(supports_file(rule, name, analyzer=analyzer, classified=classified)
                       for analyzer in analyzers):
                continue
            if rule.rule_id in receipt.hits.get(name, ()):
                return True
            # paths can filter one file while another reports a successful
            # match/time. Without positive per-file evidence do not infer it.
            # A dedicated single-rule invocation also binds the engine's
            # scanned paths to that rule, including engine-native filters.
            if (not rule.has_paths or receipt.allowed_rules == {rule.rule_id}) and rule.rule_id in receipt.timed:
                return True
        return False

    def coverage(self, status='PLANNED'):
        per_language={}
        for language in self.detected_languages:
            targets=set(self.language_files[language])
            groups = {}
            for name in targets:
                languages = self.embedded_coverage.get(name, {}).get('script_languages', ())
                groups.setdefault((self.file_types[name], tuple(languages)), []).append(name)

            def applies(rule, group):
                classified, analyzers = group
                if not _rule_for_language(rule, language, classified):
                    return False
                if analyzers and not is_vue_template_rule(rule):
                    return any(supports_file(rule, '', analyzer=analyzer, classified=classified)
                               for analyzer in analyzers)
                return supports_file(rule, '', classified=classified)

            available = [r for r in self.pack.catalog if (r.maturity != 'EXPERIMENTAL' or not self.pack.descriptor.bundled)
                         and any(applies(r, group) for group in groups)]
            applicable = [(r, tuple(group for group in groups if applies(r, group))) for r in self.rules]
            applicable = [(r, types) for r, types in applicable if types]
            selected = [r for r, _ in applicable]
            clean=(self.scanned_files-self.errored_files-set(self.skipped_files))&targets
            if language == 'vue':
                clean = {p for p in self.scanned_files & targets if
                    (detail := self.embedded_coverage.get(p, {})).get('scanned_script_blocks', 0)
                    or detail.get('template_status') == 'TEXT_EXECUTED'}
            executed, all_pairs, covered_types = [], True, set()
            for rule, types in applicable:
                covered_types.update(types)
                if status == 'PLANNED' or self.unscoped_error:
                    all_pairs = False
                    continue
                proved = total = 0
                for group in types:
                    for name in groups[group]:
                        total += 1
                        proved += self.proves(rule, name)
                if proved:
                    executed.append(rule)
                all_pairs &= proved == total
            if not selected:
                state='NOT_COVERED'
            elif status=='PLANNED':
                state='PLANNED'
            elif status=='UNAVAILABLE':
                state='UNAVAILABLE'
            elif (status=='SUCCESS' and all_pairs and clean==targets and covered_types==groups.keys()
                    and not self.unscoped_error
                    and language != 'template'
                    and not any(self.file_types[p][0].mode == TEXT for p in targets
                                if language not in TEXT_LANGUAGES)):
                state='EXECUTED'
            elif executed:
                state='PARTIAL'
            else:
                state='FAILED'
            if language == 'vue' and status not in {'PLANNED', 'UNAVAILABLE'}:
                # Script extraction is deliberately not template/CSS coverage.
                state='PARTIAL' if executed or clean else 'NOT_COVERED'
            elif language == 'template' and status == 'SUCCESS' and clean:
                state='PARTIAL'
            per_language[language]={'language':language,'available_rules':len(available),'selected_rules':len(selected),
                'executed_rules':len(executed),'selected_rule_ids':[r.rule_id for r in selected],
                'executed_rule_ids':[r.rule_id for r in executed],'applicable_categories':sorted({r.category for r in selected}),
                'frameworks':sorted({r.framework for r in selected if r.framework}), 'status':state,
                'target_files':len(targets),'scanned_files':len(clean)}
            if language == 'vue':
                template = any(d['template_status'] == 'TEXT_EXECUTED' for d in self.embedded_coverage.values())
                per_language[language].update(template_status='TEXT_EXECUTED' if template else 'NOT_COVERED',
                    scope='SCRIPT_AND_LIMITED_TEMPLATE_TEXT' if template else 'SCRIPT_BLOCKS_ONLY',
                    files=dict(self.embedded_coverage))
            if language == 'template':
                per_language[language]['scope'] = 'LIMITED_TEMPLATE_TEXT'
        gaps = dict(self.rule_gaps)
        planned = set(self.files)
        for name, (capability, _) in self.file_types.items():
            if name not in planned:
                gaps.setdefault(name, capability.reason or 'NO_APPLICABLE_RULE')
            elif name in self.errored_files:
                gaps.setdefault(name, 'ENGINE_PARSE_OR_FILE_ERROR')
            elif name not in self.scanned_files and status == 'SUCCESS':
                gaps.setdefault(name, self.skipped_files.get(name, 'ENGINE_FILE_EXECUTION_NOT_OBSERVED'))
            elif capability.mode == TEXT and capability.reason:
                gaps.setdefault(name, capability.reason)
            elif name in self.skipped_files:
                gaps.setdefault(name, self.skipped_files[name])
        for name, detail in self.embedded_coverage.items():
            if detail['issues']:
                gaps.setdefault(name, detail['issues'][0])
        # Record lack of evidence separately from known projection skips.
        # Only files with executed receipts enter this cheap path-filter check.
        if status == 'SUCCESS':
            constrained = [rule for rule in self.rules if rule.has_paths]
            for name in self.proof_index:
                if name in gaps or not constrained:
                    continue
                if any(supports_file(rule, name, classified=self.file_types[name])
                       and not self.proves(rule, name) for rule in constrained):
                    gaps[name] = 'RULE_FILE_EXECUTION_NOT_PROVEN'
        states=[row['status'] for row in per_language.values()]
        aggregate=('NOT_APPLICABLE' if not states else 'EXECUTED' if all(s=='EXECUTED' for s in states)
            else 'PARTIAL' if any(s in {'EXECUTED','PARTIAL'} for s in states)
            else 'NOT_COVERED' if all(s=='NOT_COVERED' for s in states)
            else 'UNAVAILABLE' if any(s=='UNAVAILABLE' for s in states) and not any(s=='FAILED' for s in states)
            else 'PLANNED' if any(s=='PLANNED' for s in states) else 'FAILED')
        program = getattr(self.pack, 'program', None)
        capabilities = [c for c in program.capabilities if c.scanner_engine == 'semgrep' and
            any(r.rule_id in c.underlying_rule_ids for r in self.rules)] if program else []
        from .owasp_coverage import owasp_coverage
        return {'engine':self.engine_id,'rule_pack_id':self.pack.descriptor.rule_pack_id,
            'rule_pack_version':self.pack.descriptor.version,'rule_pack_checksum':self.pack.checksum,
            'detected_languages':list(self.detected_languages),'per_language':per_language,'status':aggregate,
            'total_available':len({r.rule_id for r in self.pack.catalog}),'total_selected':len({r.rule_id for r in self.rules}),
            'total_executed':len({rid for row in per_language.values() for rid in row['executed_rule_ids']}),
            'owasp_top10':owasp_coverage(self.pack, (r.rule_id for r in self.rules),
                {rid for row in per_language.values() for rid in row['executed_rule_ids']}),
            'total_files':len(self.files),'scope_files':list(self.files),
            'file_modes': {mode: sum(cap.mode == mode for cap, _ in self.file_types.values())
                           for mode in sorted({cap.mode for cap, _ in self.file_types.values()})},
            'file_gaps': [{'path': name, 'reason': reason} for name, reason in sorted(gaps.items())[:20]],
            'file_gaps_truncated':len(gaps)>20,
            'engine_skipped_count':len(self.skipped_files),
            'engine_skipped_targets':[{'path': name, 'reason': reason, 'source': 'SCANNER'}
                for name, reason in sorted(self.skipped_files.items())[:20]],
            'engine_skips_truncated':len(self.skipped_files)>20,
            'capability_program_version':program.version if program else None,
            'applicable_capabilities':len(capabilities),
            'capabilities':[{'capability_id':c.capability_id,'title':c.title,'maturity':c.maturity,
                'auto_fix_eligible':c.auto_fix_eligible,
                'owasp_mapping':list(c.owasp_mapping),
                'frameworks':list(c.frameworks),
                'framework_applicability':'ENGINE_TYPED_PATTERNS; CONSERVATIVE_LANGUAGE_EXTENSION_PLAN',
                'selected_rule_ids':[r.rule_id for r in self.rules if r.rule_id in c.underlying_rule_ids]}
                for c in capabilities],
            'execution_evidence':self.engine_id+' invocation-local rules, scanned paths and findings; gaps lower coverage'}


def plan_rules(pack, files):
    classified = {name: result for name in files if (result := file_type(name))[0] is not None}
    language_files = {}
    for name, (capability, _) in classified.items():
        if capability.language != 'xml':
            language_files.setdefault(capability.language, []).append(name)
    # An explicit mapper XML edit can have applicable framework rules even
    # when no .java file changed. Typed mapper patterns decide the match;
    # never expand the file scope merely to infer the repository framework.
    xml=[name for name, (capability, _) in classified.items() if capability.language == 'xml']
    if xml and any(r.language=='java' and '.xml' in r.target_extensions for r in pack.catalog):
        language_files.setdefault('java', []).extend(xml)
    elif xml and not any(TEXT_LANGUAGES.intersection(r.engine_languages) for r in pack.catalog):
        language_files['xml'] = xml
    # Generic rules operate only on files recognized by the typed target plan;
    # they do not make arbitrary prose or unknown files code scan targets.
    # XML is a recognized configuration input handled by generic/regex rules
    # even when this pack has no Java-owned mapper rules or native XML parser.
    code_files = tuple(classified)
    for language in ('generic', 'regex'):
        if code_files and any(language in r.engine_languages for r in pack.catalog):
            names = [name for name in code_files if classified[name][0].mode != VUE_SCRIPT
                     and classified[name][0].language != 'template']
            if names:
                language_files[language] = names
    program = getattr(pack, 'program', None)
    types = set(classified.values())
    selected=tuple(rule for rule in pack.catalog if (rule.maturity!='EXPERIMENTAL' or not pack.descriptor.bundled)
        and (program is None or program.enabled(rule.rule_id))
        and any(supports_file(rule, '', classified=kind) for kind in types))
    enabled = {kind for kind in types if any(supports_file(rule, '', classified=kind) for rule in selected)}
    targets = tuple(name for name in code_files if classified[name] in enabled)
    # Uncovered files are described in the plan but never passed to the engine.
    # Keep recognized inputs without an applicable parser/rule in the coverage
    # denominator (for example .vue beside .js); never silently discard them.
    return SASTRulePlan(pack,selected,targets,tuple(sorted(language_files)),
                        {language: tuple(names) for language, names in language_files.items()},
                        file_types=classified)
