"""Evidence validation, conservative policy, cache and independent triage views."""
import hashlib
import re
from dataclasses import replace

from .triage_models import (TriageRecord,TriageBudget,RESULT_SCHEMA,INSTRUCTIONS,PROMPT_VERSION,
    category,dependency_groups,iac_classification)
from .triage_evidence import EvidenceBuilder,encoded
from .triage_providers import AgentNativeProvider
from .progress import emit,progress_context,NullProgressReporter,checkpoint


def validate_schema(value,schema=RESULT_SCHEMA):
    if 'enum' in schema and value not in schema['enum']: raise ValueError('Invalid triage enum')
    kind=schema.get('type')
    if kind=='object':
        if not isinstance(value,dict) or set(schema.get('required',[]))-set(value): raise ValueError('Missing structured triage fields')
        if schema.get('additionalProperties') is False and set(value)-set(schema['properties']): raise ValueError('Unexpected triage fields')
        for name,item in value.items(): validate_schema(item,schema['properties'][name])
    elif kind=='array':
        if not isinstance(value,list) or len(value)>schema.get('maxItems',20): raise ValueError('Invalid triage array')
        for item in value: validate_schema(item,schema['items'])
    elif kind=='string':
        if not isinstance(value,str) or not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',10000): raise ValueError('Invalid triage string')
        if schema.get('pattern') and not re.fullmatch(schema['pattern'],value): raise ValueError('Invalid context hash')
    elif kind=='integer':
        if type(value) is not int or value<schema.get('minimum',0): raise ValueError('Invalid triage line number')


class TriagePolicy:
    def apply(self,record,packet,severity):
        if packet.get('local_evidence',{}).get('evidence_status')=='STALE':
            record.verdict='NEEDS_REVIEW'
            record.exploitability='UNKNOWN'
            record.policy_notes.append('Source changed since scan; rescan before validating the original detector claim.')
        if record.verdict=='FALSE_POSITIVE':
            counter=packet['enrichment']['verified_counterevidence']
            proven=any(any(ref['file']==proof['file'] and ref['start_line']<=proof['start_line']
                and ref['end_line']>=proof['end_line'] for ref in record.evidence_refs) for proof in counter)
            if record.confidence!='HIGH' or not proven or record.preconditions_unknown:
                record.verdict='NEEDS_REVIEW'
                record.policy_notes.append('FALSE_POSITIVE requires HIGH confidence, validated explicit counterevidence and no unknown preconditions.')
        if packet['category']=='dependency' and record.exploitability in {'CONFIRMED','LIKELY'}:
            record.exploitability='CONDITIONAL'
            record.policy_notes.append('Bounded dependency context does not establish a reachable attack path.')
        if record.verdict=='FALSE_POSITIVE': record.priority='SUPPRESSED'
        elif record.verdict=='UNLIKELY': record.priority='LOWER_PRIORITY'
        elif (record.verdict=='CONFIRMED' or record.verdict=='LIKELY' and record.confidence=='HIGH') and record.exploitability not in {'UNKNOWN','CONDITIONAL','UNLIKELY'} and severity in {'CRITICAL','HIGH','MEDIUM'}:
            record.priority='ACTIONABLE'
        else: record.priority='REVIEW'
        return record


def cache_key(finding,packet,provider):
    return hashlib.sha256(encoded([finding['fingerprint'],packet['context_hash'],
        provider.provider_type,provider.provider_name,provider.model,PROMPT_VERSION])).hexdigest()


class TriageService:
    def __init__(self,store,budget=None):
        self.store=store
        self.budget=budget or TriageBudget()

    def builder(self,scan):
        return EvidenceBuilder(scan,self.budget,revision_key=self.store.evidence_key())

    def scan(self,scan_id):
        scan=self.store.get_scan(scan_id)
        if scan is None: raise ValueError('Scan does not exist')
        try:
            from .observation import bind_product, bind_workspace
            bind_product('scan', scan_id, relation='SCAN_RECORD_READ')
            bind_workspace(scan.get('target_profile', {}).get('path'))
        except Exception:
            pass
        return scan

    def prepare(self,scan_id,finding_ids=None,categories=None,limit=None,severities=None,provider=None,
                *,pending_only=False,retry_failed=False):
        scan=self.scan(scan_id);budget=self.budget
        limit=budget.max_findings_per_batch if limit is None else limit
        if type(limit) is not int or not 1<=limit<=budget.max_findings_per_batch:
            raise ValueError('Triage limit exceeds batch budget')
        if categories and set(categories)-{'code','secret','dependency'}: raise ValueError('Unsupported triage category')
        if severities and set(severities)-{'CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'}: raise ValueError('Unsupported severity')
        available={f['id'] for f in scan['findings']}
        if finding_ids is not None and (not isinstance(finding_ids,list) or len(finding_ids)>1000 or set(finding_ids)-available):
            raise ValueError('Triage finding IDs must belong to this scan')
        selected=[f for f in scan['findings'] if category(f) in {'code','secret','dependency'}
            and (finding_ids is None or f['id'] in finding_ids)
            and (not categories or category(f) in categories) and (not severities or f['severity'] in severities)]
        order={'CRITICAL':5,'HIGH':4,'MEDIUM':3,'LOW':2,'UNKNOWN':1}
        selected.sort(key=lambda f:(-order.get(f['severity'],0),{'code':0,'secret':1,'dependency':2}[category(f)],
            -{'HIGH':3,'MEDIUM':2,'LOW':1}.get(f['confidence'],0),f['file_path'],f['line_start'],f['id']))
        retained=[];deferred=[]
        if pending_only and selected:
            from .storage import ReadOnlySQLiteStore
            readonly=TriageService(ReadOnlySQLiteStore(self.store.path),self.budget)
            rows={row['finding_id']:row for row in readonly.view(scan_id,persist_stale=False)['findings']}
            retained=[f['id'] for f in selected if rows[f['id']]['triage_status']=='VALID']
            deferred=[f['id'] for f in selected if rows[f['id']]['triage_status']=='FAILED' and not retry_failed]
            selected=[f for f in selected if f['id'] not in retained and f['id'] not in deferred]
            rank={'UNTRIAGED':0,'STALE':1,'FAILED':2}
            selected.sort(key=lambda f:rank[rows[f['id']]['triage_status']])
        provider=provider or AgentNativeProvider()
        packets=[];cached=[];errors=[];examined=[]
        try: builder=self.builder(scan) if selected else None
        except (ValueError,OSError): builder=None
        # Cache reuse is not a new model analysis. Bound local preparation work
        # separately so cache-heavy scans cannot cause an unbounded request.
        for finding in selected[:1000]:
            if len(packets)+len(errors)>=limit: break
            examined.append(finding)
            try:
                if builder is None: raise ValueError('Evidence unavailable')
                packet=builder.build(finding)
                key=cache_key(finding,packet,provider)
                old=self.store.cached_triage(key)
                if old:
                    record=TriageRecord(**old);record.scan_id=scan_id;record.finding_id=finding['id']
                    self.store.save_triage(record,key);cached.append(finding['id'])
                else: packets.append(packet)
            except (ValueError,OSError) as exc:
                errors.append({'finding_id':finding['id'],'error':'Evidence unavailable or violates workspace/size/line bounds',
                    'reason':getattr(exc,'reason','FILE_MISSING' if isinstance(exc,FileNotFoundError) else 'EVIDENCE_UNAVAILABLE')})
        result={'scan_id':scan_id,'packets':packets,'cached_finding_ids':cached,'errors':errors,
            'required_output_schema':RESULT_SCHEMA,'triage_instructions':INSTRUCTIONS,'prompt_version':PROMPT_VERSION,
            'provider':{'provider_type':provider.provider_type,'provider_name':provider.provider_name,'model':provider.model},
            'dependency_groups':dependency_groups(examined),'selected':len(examined),
            'remaining':max(0,len(selected)-len(examined)),
            'retained_finding_ids':retained,'deferred_failed_finding_ids':deferred}
        if provider.provider_type=='AGENT_NATIVE':
            from .triage_handoff import bound_handoff
            # Keep only current packet groups in host navigation, avoiding an
            # unbounded replay of cached finding/advisory metadata.
            included={packet['finding_id'] for packet in packets}
            result['dependency_groups']=dependency_groups([f for f in examined if f['id'] in included])
            result=bound_handoff(result,budget.max_handoff_bytes)
        return result

    def submit(self,scan_id,results,*,provider=None,compact=False):
        provider=provider or AgentNativeProvider()
        if not isinstance(results,list) or not 1<=len(results)<=self.budget.max_findings_per_batch:
            raise ValueError('Invalid triage submission batch size')
        if len(encoded(results))>self.budget.max_response_bytes: raise ValueError('Triage submission exceeds size budget')
        scan=self.scan(scan_id);findings={f['id']:f for f in scan['findings']}
        builder=self.builder(scan);records=[];seen=set()
        for value in results:
            validate_schema(value)
            fid=value['finding_id']
            if fid not in findings or fid in seen: raise ValueError('Unknown or duplicate triage finding ID')
            seen.add(fid);finding=findings[fid];packet=builder.build(finding)
            if value['context_hash']!=packet['context_hash']: raise ValueError('Triage context is stale; prepare evidence again')
            refs=value['evidence_refs'];allowed=packet['context']+packet['related_evidence']
            for ref in refs:
                if not any(ref['file']==item['file'] and item['start_line']<=ref['start_line']<=ref['end_line']<=item['end_line'] for item in allowed):
                    raise ValueError('Fabricated or out-of-bounds evidence reference')
            if value['verdict'] in {'CONFIRMED','LIKELY','FALSE_POSITIVE'} and not refs:
                if value['verdict']!='FALSE_POSITIVE': raise ValueError('Positive validation requires evidence references')
            # The schema prevents arbitrary tool/shell/network fields. No model
            # output is executed. Evidence prose is bounded without masking source values.
            def safe(item):
                if isinstance(item,str): return builder.safe_text(item)
                if isinstance(item,list): return [safe(i) for i in item]
                if isinstance(item,dict): return {k:safe(v) for k,v in item.items()}
                return item
            cleaned=safe(value)
            record=TriageRecord(scan_id=scan_id,finding_fingerprint=finding['fingerprint'],
                provider_type=provider.provider_type,provider_name=provider.provider_name,model=provider.model,
                prompt_version=PROMPT_VERSION,**cleaned)
            TriagePolicy().apply(record,packet,finding['severity'])
            records.append((record,cache_key(finding,packet,provider)))
        # Validate the entire batch first; invalid later items cannot partially
        # publish earlier model claims. Raw scans/findings are never written.
        for record,key in records: self.store.save_triage(record,key)
        if compact:
            from collections import Counter
            return {'scan_id':scan_id, 'accepted':len(records),
                'finding_ids':[record.finding_id for record,key in records],
                'verdict_counts':dict(Counter(record.verdict for record,key in records)),
                'priority_counts':dict(Counter(record.priority for record,key in records)),
                'results_access':{'tool':'get_triage','arguments':{'scan_id':scan_id}},
                'raw_findings_changed':False, 'scan_coverage_changed':False,
                'quality_reviews_changed':False}
        return {'accepted':len(records),'records':[record.to_dict() for record,key in records],
            'view':self.view(scan_id)}

    def view(self,scan_id,*,persist_stale=True):
        scan=self.scan(scan_id);records=self.store.triage_records(scan_id)
        coverage=dict(total_candidates=len(scan['findings']),eligible_for_triage=0,triaged=0,
            actionable=0,review=0,lower_priority=0,suppressed=0,failed=0,stale=0,untriaged=0)
        try: builder=self.builder(scan)
        except (ValueError,OSError): builder=None
        rows=[]
        for finding in scan['findings']:
            eligible=category(finding) in {'code','secret','dependency'}
            coverage['eligible_for_triage']+=eligible
            record=records.get(finding['id'])
            freshness='PREVIOUSLY_STALE' if record and record['status']=='STALE' else 'NOT_CHECKED'
            if record and record['status']=='VALID':
                try:
                    if builder is None: raise ValueError('Workspace unavailable')
                    current=builder.build(finding)
                    if record['context_hash']!=current['context_hash'] or record['prompt_version']!=PROMPT_VERSION:
                        record=replace(TriageRecord(**record),status='STALE',priority='UNTRIAGED').to_dict()
                        freshness='CHANGED'
                    else: freshness='CURRENT'
                except (ValueError,OSError):
                    record=replace(TriageRecord(**record),status='STALE',priority='UNTRIAGED').to_dict()
                    freshness='UNVERIFIABLE'
                if record['status']=='STALE' and persist_stale:
                    key=hashlib.sha256(encoded([finding['fingerprint'],record['context_hash'],record['provider_type'],
                        record['provider_name'],record['model'],record['prompt_version']])).hexdigest()
                    self.store.save_triage(TriageRecord(**record),key)
            state=record['status'] if record else 'UNTRIAGED'
            if state=='VALID':
                coverage['triaged']+=1;coverage[record['priority'].lower()]+=1
            elif state=='STALE': coverage['stale']+=1
            elif state=='FAILED': coverage['failed']+=1
            else: coverage['untriaged']+=1
            row={'finding_id':finding['id'],'category':category(finding),'severity':finding['severity'],
                'title':finding['plain_title'],'file':finding['file_path'],'line':finding['line_start'],
                'triage_status':state,'triage':record,'freshness':freshness}
            if category(finding)=='iac': row['classification']=iac_classification(finding)
            rows.append(row)
        return {'scan_id':scan_id,'scan_coverage':scan.get('coverage'),'capability_results':scan.get('capability_results'),
            'triage_coverage':coverage,'findings':rows,'dependency_groups':dependency_groups(scan['findings'])}

    def run(self,scan_id,provider,*,progress=None,**selection):
        with progress_context(progress or NullProgressReporter()):
            checkpoint();emit('TRIAGE_STARTED',message='AI Risk Validation')
            prepared=self.prepare(scan_id,provider=provider,**selection)
            done=0;failures=[]
            batches=[];dependency_batches={}
            for packet in prepared['packets']:
                if packet['category']=='dependency' and callable(getattr(provider,'triage_batch',None)):
                    md=packet['enrichment'];group=tuple(md.get(k) for k in ('ecosystem','package','package_version','manifest'))
                    if group not in dependency_batches:
                        dependency_batches[group]=[];batches.append(dependency_batches[group])
                    dependency_batches[group].append(packet)
                else: batches.append([packet])
            for batch in batches:
                checkpoint();emit('TRIAGE_RUNNING',message=f"正在分析 {done+1}/{len(prepared['packets'])}")
                try:
                    values=provider.triage_batch(batch) if len(batch)>1 else [provider.triage(batch[0])]
                    if not isinstance(values,list) or any(not isinstance(v,dict) for v in values):
                        raise ValueError('Malformed AI batch response')
                    if {v.get('finding_id') for v in values}!={p['finding_id'] for p in batch}:
                        raise ValueError('AI batch returned unexpected finding IDs')
                    self.submit(scan_id,values,provider=provider)
                except (ValueError,OSError,TimeoutError):
                    # No response/request/key/error body is stored or logged.
                    for packet in batch:
                        failures.append({'finding_id':packet['finding_id'],'error':'Provider or structured evidence validation failed'})
                        finding=next(f for f in self.scan(scan_id)['findings'] if f['id']==packet['finding_id'])
                        record=TriageRecord(scan_id,packet['finding_id'],finding['fingerprint'],'NEEDS_REVIEW','LOW','UNKNOWN',
                            'Provider or structured evidence validation failed.','',[],[],[],'Review raw finding.',
                            provider.provider_type,provider.provider_name,provider.model,PROMPT_VERSION,packet['context_hash'],
                            priority='UNTRIAGED',status='FAILED')
                        self.store.save_triage(record,cache_key(finding,packet,provider))
                done+=len(batch);emit('TRIAGE_ITEM_COMPLETED',message=f"已完成 {done}/{len(prepared['packets'])}")
            emit('TRIAGE_COMPLETED',message=f'已完成 {done}；失败 {len(failures)}')
        return {'view':self.view(scan_id),'failures':failures,'evidence_errors':prepared['errors'],
                'cache_hits':len(prepared['cached_finding_ids']),'completed':done}


try:
    from .context_cost_sync import observed
    TriageService.run = observed('run_triage')(TriageService.run)
except Exception:
    pass  # Optional observation is removable, including at import time.
