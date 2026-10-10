"""Explicit, validated rule capabilities; YAML is execution syntax, not the catalog."""
from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re


LANGUAGES = {'python', 'java', 'javascript', 'typescript', 'go', 'php', 'generic'}
EXTENSIONS = {'python': {'.py'}, 'java': {'.java'}, 'javascript': {'.js', '.jsx', '.vue'},
              'typescript': {'.ts', '.tsx'}, 'go': {'.go'}, 'php': {'.php'}}


@dataclass(frozen=True)
class RuleRecord:
    rule_id: str
    language: str
    engine_languages: tuple[str, ...]
    category: str
    cwe: tuple[str, ...]
    severity: str
    confidence: str
    maturity: str
    framework: str
    rule_pack: str
    rule_version: str
    references: tuple[str, ...]
    provenance: dict
    mode: str
    path: str
    target_extensions: tuple[str, ...]
    fixture: str = ''
    additional_fixtures: tuple[str, ...] = ()


def supports_language(record, language):
    """A shared execution rule can cover several separately reported languages.

    The canonical catalog language remains its identity, including Java-owned
    generic mapper rules. Engine languages do not duplicate the rule ID.
    """
    return language == record.language or language in record.engine_languages


def validate_rule(rule, descriptor, *, first_party=True):
    if not isinstance(rule, dict) or not isinstance(rule.get('id'), str):
        raise ValueError('Invalid rule entry')
    languages=rule.get('languages')
    if not isinstance(languages,list) or not languages or any(lang not in LANGUAGES for lang in languages):
        raise ValueError('Invalid rule language')
    if rule.get('severity') not in {'ERROR','WARNING','INFO','INVENTORY','EXPERIMENT'}:
        raise ValueError('Invalid rule severity')
    if not first_party:
        return
    md=rule.get('metadata',{})
    required={'publisher','rule_pack','rule_version','language','category','cwe','confidence','maturity','framework','license','references','provenance'}
    if not isinstance(md,dict) or not required.issubset(md):
        raise ValueError('Rule license or provenance metadata missing')
    if (not rule['id'].startswith('ai-security.') or md['license']!=descriptor.license
        or md['rule_pack']!=descriptor.rule_pack_id
        or md['publisher']!=descriptor.publisher):
        raise ValueError('Rule license or pack identity mismatch')
    # Pack releases can add rules without rewriting unchanged execution rules.
    # The catalog cross-checks each rule version; scanner proof binds both the
    # pack checksum/version and the exact execution rule version.
    if not isinstance(md['rule_version'], str) or not re.fullmatch(r'\d{1,6}\.\d{1,6}\.\d{1,6}', md['rule_version']):
        raise ValueError('Rule version invalid')
    if md['language'] not in LANGUAGES or not isinstance(md['category'],str) or not md['category']:
        raise ValueError('Rule language/category missing')
    if not isinstance(md['cwe'],list) or not md['cwe'] or any(not re.fullmatch(r'CWE-\d+',str(cwe)) for cwe in md['cwe']):
        raise ValueError('Rule CWE missing or invalid')
    if md['confidence'] not in {'LOW','MEDIUM','HIGH'} or md['maturity'] not in {'EXPERIMENTAL','BETA','STABLE'}:
        raise ValueError('Rule confidence/maturity invalid')
    if not isinstance(md['references'],list) or not md['references'] or any(not str(ref).startswith('https://') for ref in md['references']):
        raise ValueError('Rule references missing')
    provenance=md['provenance']
    if (not isinstance(provenance,dict) or not {'origin','author','created_at','references','license','derived_from'}.issubset(provenance)
        or not provenance['author'] or not provenance['created_at'] or not provenance['references']):
        raise ValueError('Rule provenance incomplete')
    if provenance['derived_from']:
        raise ValueError('Derived rule requires source license review')
    if provenance['origin']!='FIRST_PARTY' or provenance['license']!=descriptor.license:
        raise ValueError('Rule provenance does not match first-party pack')


def load_catalog(path, descriptor, definitions, *, first_party=True):
    """Cross-check an explicit manifest against every execution rule, fail closed."""
    if not first_party:
        records=[]
        for rule,relative in definitions.values():
            md=rule.get('metadata',{})
            for language in rule['languages']:
                records.append(RuleRecord(rule['id'],language,(language,),md.get('category','code'),
                    tuple(md.get('cwe',())),rule['severity'],md.get('confidence','MEDIUM'),'EXPERIMENTAL',
                    md.get('framework',''),descriptor.rule_pack_id,descriptor.version,(),{},rule.get('mode','search'),relative,
                    tuple(EXTENSIONS.get(language,{'.xml'}))))
        return tuple(records)
    file=path/'catalog.json'
    if not file.is_file() or file.is_symlink() or file.stat().st_size>1_000_000:
        raise ValueError('Rule Catalog missing or oversized')
    data=json.loads(file.read_text(encoding='utf-8'))
    if data.get('rule_pack')!=descriptor.rule_pack_id or data.get('version')!=descriptor.version:
        raise ValueError('Rule Catalog identity mismatch')
    records=[];seen=set()
    for value in data.get('rules',[]):
        if value.get('rule_id') in seen:
            raise ValueError('Duplicate rule id in catalog')
        seen.add(value.get('rule_id'))
        for field in ('engine_languages','cwe','references','target_extensions'):
            value[field]=tuple(value[field])
        companions=value.get('additional_fixtures', [])
        if (not isinstance(companions, list) or len(companions)>4 or
                any(not isinstance(name, str) or not name for name in companions)):
            raise ValueError('Rule additional fixtures invalid')
        if len(set(companions)) != len(companions) or value.get('fixture') in companions:
            raise ValueError('Duplicate rule fixture')
        value['additional_fixtures']=tuple(companions)
        record=RuleRecord(**value)
        if record.rule_id not in definitions:
            raise ValueError('Catalog rule has no execution definition')
        rule,relative=definitions[record.rule_id];md=rule['metadata']
        expected={key:md[key] for key in ('language','category','cwe','confidence','maturity','framework','rule_pack','rule_version','references','provenance')}
        expected.update(rule_id=rule['id'],engine_languages=rule['languages'],severity=rule['severity'],mode=rule.get('mode','search'),path=relative)
        actual=asdict(record)
        if any(list(actual[key])!=val if isinstance(val,list) else actual[key]!=val for key,val in expected.items()):
            raise ValueError('Rule Catalog metadata mismatch')
        if not record.target_extensions or any(not re.fullmatch(r'\.[a-z0-9]+',ext) for ext in record.target_extensions):
            raise ValueError('Rule Catalog target extensions invalid')
        if not record.fixture:
            raise ValueError('Default rule has no fixture declaration')
        records.append(record)
    if seen!=set(definitions):
        raise ValueError('Rule Catalog count mismatch')
    return tuple(records)
