"""Reconcile retained optional observations; never consult product authority.

A missing finding in a later scan is not proof of resolution. A replay of an
old scan cannot reopen a risk, and an old reference cannot close a newer one.
"""
from collections import Counter

HANDLING_STATES = {'OPEN', 'EXCLUDED', 'DEFERRED', 'RESOLVED', 'UNKNOWN'}
RISK_REASONS = {'NO_RISK_OBSERVATIONS', 'IDENTITY_UNAVAILABLE', 'ITEMS_OMITTED',
    'HISTORICAL_ORDER_UNKNOWN', 'STATE_WITHOUT_FINDING', 'OLDER_REFERENCE_STATE',
    'HANDLING_NOT_OBSERVED', 'STATE_UNKNOWN', 'WORKSPACE_UNAVAILABLE', 'CHECK_INCOMPLETE'}


def current_risks(events):
    aliases, risks, seen, reasons = {}, {}, set(), set()
    missing = set()
    checks = {}
    # Resolve scoped references before state events, including legacy assessment
    # imports encountered before their scan. Identity never crosses workspace.
    for event in events:
        fact = event['product_fact']
        if fact['kind'] in {'SCAN','CHECK'}:
            key = (event.get('workspace_hash'),fact['kind'],fact['reference'])
            old = checks.get(key)
            if old is None or (fact['kind']=='CHECK' and
                (fact.get('revision',0),fact.get('projection_rank',0))>
                (old[0].get('revision',0),old[0].get('projection_rank',0))):
                checks[key] = (fact,event.get('finished_at') or 0)
        if fact['kind'] not in {'SCAN','PROPOSAL'}:
            continue
        workspace = event.get('workspace_hash')
        for item in fact['items']:
            alias = (workspace, fact['reference'], item['id'])
            if workspace and item.get('risk_key'):
                aliases[alias] = (workspace, item['risk_key'])
            else:
                missing.add(alias)
                reasons.add('IDENTITY_UNAVAILABLE' if workspace else 'WORKSPACE_UNAVAILABLE')
    for event in sorted(events, key=lambda row: row.get('finished_at') or 0):
        fact = event['product_fact']
        workspace = event.get('workspace_hash')
        scope = (workspace, fact['reference'])
        if fact.get('omitted'):
            reasons.add('ITEMS_OMITTED')
        for item in fact['items']:
            alias = (*scope, item['id'])
            identity = aliases.get(alias)
            if identity is None:
                if fact['kind'] not in {'SCAN','PROPOSAL'}:
                    missing.add(alias)
                    reasons.add('STATE_WITHOUT_FINDING')
                continue
            if fact['kind'] in {'SCAN','PROPOSAL'}:
                # The same persisted occurrence may be imported/read repeatedly.
                if alias in seen:
                    if fact['source']=='LIVE' and risks.get(identity,{}).get('reference')==fact['reference']:
                        risks[identity]['source']='LIVE'
                    continue
                seen.add(alias)
                prior = risks.get(identity)
                if fact['source'] == 'HISTORY':
                    reasons.add('HISTORICAL_ORDER_UNKNOWN')
                    if prior and prior['source'] == 'LIVE':
                        continue
                # Existing manual pauses need a fresh handling receipt before
                # treating a reappearing occurrence as actionable or suppressed.
                risks[identity] = dict(state='OPEN', reference=fact['reference'],
                    source=fact['source'], handling='UNKNOWN')
                continue
            risk = risks.get(identity)
            if risk is None:
                missing.add(alias)
                reasons.add('STATE_WITHOUT_FINDING')
                continue
            if fact['source'] == 'HISTORY' and risk['source'] == 'LIVE':
                continue
            if risk['reference'] != fact['reference']:
                reasons.add('OLDER_REFERENCE_STATE')
                continue
            if fact['kind'] == 'ASSESSMENT':
                verdict = item['verdict']
                if verdict == 'FALSE_POSITIVE':
                    risk['state'] = 'FALSE_POSITIVE'
                elif verdict in {'CONFIRMED','LIKELY'}:
                    risk['state'] = 'OPEN'
                elif verdict in {'UNKNOWN','NEEDS_REVIEW'}:
                    if risk['state'] != 'RESOLVED':
                        risk['state'] = 'UNKNOWN'
            elif fact['kind'] == 'VERIFICATION':
                outcome = item['outcome']
                if outcome in {'SCANNER_VERIFIED_RESOLVED','CODE_REVIEWED_RESOLVED'}:
                    risk['state'] = 'RESOLVED'
                elif outcome in {'OPEN','STILL_PRESENT'}:
                    risk['state'] = 'OPEN'
                else:
                    risk['state'] = 'UNKNOWN'
            elif fact['kind'] == 'HANDLING':
                # A view has no resolution authority. Only already-validated
                # technical outcomes above may clear a scanner finding.
                state = item['handling']
                if state == 'RESOLVED':
                    if risk['state'] != 'RESOLVED':
                        risk['state'] = 'UNKNOWN'
                risk['handling'] = state
    states = Counter(r['state'] for r in risks.values())
    if not risks and not missing:
        # An executed zero-finding scan is evidence of an empty observed set.
        complete_zero = any(e['product_fact']['kind']=='SCAN' and e['product_fact']['total']==0
            and e['product_fact'].get('check', {}).get('status')=='COMPLETED' for e in events)
        if not complete_zero:
            reasons.add('NO_RISK_OBSERVATIONS')
    unknown_handling = sum(r['handling']=='UNKNOWN' and r['state']=='OPEN' for r in risks.values())
    if unknown_handling:
        reasons.add('HANDLING_NOT_OBSERVED')
    if states['UNKNOWN']:
        reasons.add('STATE_UNKNOWN')
    latest_checks = {}
    for (workspace,kind,_), (fact,at) in checks.items():
        key = (workspace,kind)
        priority = (fact['source']=='LIVE',at)
        if key not in latest_checks or priority > latest_checks[key][0]:
            latest_checks[key] = (priority,fact)
    if any(fact.get('check',{}).get('status') not in {'COMPLETED','NOT_RUN'}
           for _,fact in latest_checks.values()):
        reasons.add('CHECK_INCOMPLETE')
    unavailable = reasons & {'NO_RISK_OBSERVATIONS','IDENTITY_UNAVAILABLE','ITEMS_OMITTED',
        'HISTORICAL_ORDER_UNKNOWN','STATE_WITHOUT_FINDING','WORKSPACE_UNAVAILABLE','STATE_UNKNOWN',
        'CHECK_INCOMPLETE','HANDLING_NOT_OBSERVED'}
    has_handling = any(r['handling']!='UNKNOWN' for r in risks.values())
    unresolved = [r for r in risks.values() if r['state'] not in {'RESOLVED','FALSE_POSITIVE'}]
    pending = sum(r['state']=='OPEN' and r['handling'] not in {'EXCLUDED','DEFERRED'} for r in unresolved)
    return dict(pending=None if unavailable else pending, observed_pending=pending,
        resolved=states['RESOLVED'], false_positive=states['FALSE_POSITIVE'],
        excluded=sum(r['handling']=='EXCLUDED' for r in unresolved) if has_handling else None,
        deferred=sum(r['handling']=='DEFERRED' for r in unresolved) if has_handling else None,
        unknown=len(missing)+states['UNKNOWN']+unknown_handling, known_identities=len(risks),
        coverage='UNKNOWN' if not risks and reasons else 'PARTIAL' if reasons else 'OBSERVED',
        reason_codes=sorted(reasons),
        scope='LATEST_RETAINED_OBSERVATIONS_NOT_CURRENT_SOURCE_VALIDATION')
