"""Plan applicable rules/files before preparation; account for engine evidence."""
from dataclasses import dataclass, field
from pathlib import Path
from .rule_catalog import EXTENSIONS


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

    def observe(self, data, batch):
        def relative(value):
            return str(value).replace('\\','/')
        self.scanned_files.update(relative(name) for name in data.get('paths',{}).get('scanned',[]) if relative(name) in batch)
        selected={rule.rule_id for rule in self.rules}
        self.confirmed_rules.update(rule for rule in data.get('time',{}).get('rules',[]) if rule in selected)
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
            available=[r for r in self.pack.catalog if r.language==language and (r.maturity!='EXPERIMENTAL' or not self.pack.descriptor.bundled)]
            selected=[r for r in self.rules if r.language==language]
            targets=set(self.language_files[language])
            clean=(self.scanned_files-self.errored_files)&targets
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
        return {'engine':'semgrep','rule_pack_id':self.pack.descriptor.rule_pack_id,
            'rule_pack_version':self.pack.descriptor.version,'rule_pack_checksum':self.pack.checksum,
            'detected_languages':list(self.detected_languages),'per_language':per_language,'status':aggregate,
            'total_available':len({r.rule_id for r in self.pack.catalog}),'total_selected':len({r.rule_id for r in self.rules}),
            'total_executed':len({rid for row in per_language.values() for rid in row['executed_rule_ids']}),
            'total_files':len(self.files),'scope_files':list(self.files),
            'execution_evidence':'Semgrep time.rules and paths.scanned; errors/skipped rules lower coverage'}


def plan_rules(pack, files):
    language_files={language:tuple(name for name in files if Path(name).suffix.lower() in extensions)
                    for language,extensions in EXTENSIONS.items()}
    language_files={language:names for language,names in language_files.items() if names}
    # MyBatis mapper XML belongs to Java coverage only with a Java scope.
    if 'java' in language_files:
        language_files['java']+=tuple(name for name in files if Path(name).suffix.lower()=='.xml')
    selected=tuple(rule for rule in pack.catalog if rule.language in language_files and (rule.maturity!='EXPERIMENTAL' or not pack.descriptor.bundled)
        and any(Path(name).suffix.lower() in rule.target_extensions for name in language_files[rule.language]))
    targets=tuple(name for name in files if any(Path(name).suffix.lower() in rule.target_extensions for rule in selected))
    # Uncovered files are described in the plan but never passed to the engine.
    covered_languages={r.language for r in selected}
    for language in covered_languages:
        extensions={ext for r in selected if r.language==language for ext in r.target_extensions}
        language_files[language]=tuple(name for name in language_files[language] if Path(name).suffix.lower() in extensions)
    return SASTRulePlan(pack,selected,targets,tuple(sorted(language_files)),language_files)
