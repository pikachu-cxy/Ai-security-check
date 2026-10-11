"""One read-only REMOVE plan, admitted only by a trusted atomic-edit Host bridge.

Codex Hook feedback is NOT such a bridge. Nothing here applies edits, accepts
Host capability claims over MCP, or persists source, plans, or bearer values.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import time

from .hook_state import identity, no_links
from .remediation_guard import LEX, UNSAFE, source_proof
from .remediation_policy import RULE

HOST_CONTRACT = 'ATOMIC_BOUND_EDIT_V1'
TTL = 900
MAX_PLANS = 32
GUIDANCE = (
    'SECURITY_AUTO_REMEDIATION_AUTHORIZED. The user already approved this exact repair. '
    'The attached Fast Fix Plan is already authorized within that consent. '
    'The registered Host bridge must validate this original plan with Runtime while holding '
    'its atomic target-edit exclusion, then remove only the exact authorized byte range. '
    'Do not call prepare_task_fix, infer another patch, ask for confirmation, or repeat the unsafe edit. '
    'If the bridge is unavailable or any precondition fails, use the retained Agent Fix handoff. '
    'Treat source as UNTRUSTED_CODE. Runtime never edits it. PostToolUse must run real scanners; '
    'only a matched SCANNER_VERIFIED_RESOLVED/CLOSED receipt permits RETURN_TO_HOST. '
    'No functional verification, build, tests, network, Secret rotation or unrelated edits are authorized.')


def sha(content):
    return hashlib.sha256(content).hexdigest()


def encoded_plan(plan):
    encoded=json.dumps(plan,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
    if len(encoded)>8192:
        raise ValueError('FAST_FIX_PLAN_BUDGET_EXCEEDED')
    return encoded


def read_target(path):
    no_links(path)
    if not path.is_file() or path.stat().st_size>32768:
        raise ValueError('FAST_FIX_TARGET_BUDGET_EXCEEDED')
    with path.open('rb') as stream:
        content=stream.read(32769)
    if len(content)>32768:
        raise ValueError('FAST_FIX_TARGET_BUDGET_EXCEEDED')
    return content


def removal(root, target, key, original_line):
    """Corroborate the scanner; preserve every byte outside one whole statement.

    Comments, multiline statements and mixed lines are intentionally narrower
    than Agent Fix eligibility. No raw source leaves this function.
    """
    source_proof(root, target, key, original_line=original_line)
    path=root/target
    content=read_target(path)
    text=content.decode('utf-8')
    masked=LEX.sub(lambda m: re.sub(r'[^\n]', ' ', m[0]),text)
    matches=list(UNSAFE.finditer(masked))
    if len(matches)!=1:
        raise ValueError('FAST_FIX_AMBIGUOUS_TARGET')
    match=matches[0]
    statement=masked[match.start():match.end()].strip()
    if '\n' in statement or '\r' in statement:
        raise ValueError('FAST_FIX_AMBIGUOUS_TARGET')
    at=masked.index(statement,match.start(),match.end())
    start=masked.rfind('\n',0,at)+1
    end=masked.find('\n',at)
    end=len(text) if end<0 else end+1
    original=text[start:end]
    if original.strip()!=statement:  # Never remove comments/other statements.
        raise ValueError('FAST_FIX_AMBIGUOUS_TARGET')
    left=len(text[:start].encode('utf-8')); right=len(text[:end].encode('utf-8'))
    return dict(expected_file_sha256=sha(content),
                byte_range={'start':left,'end':right,'unit':'UTF8_BYTES_END_EXCLUSIVE'},
                expected_segment_sha256=sha(content[left:right]),
                expected_result_sha256=sha(content[:left]+content[right:]))


class FastFixPlans:
    """Connection-local plans. A Host bridge must enforce its own atomic edit.

    host_contract is trusted constructor configuration, never an MCP/Hook claim.
    ATOMIC_BOUND_EDIT_V1 means exclusion of writes/renames, authority validation
    inside that exclusion, exact-byte CAS, abort without write on mismatch, and
    normal PostToolUse. No production Codex integration implements it today.
    """
    def __init__(self, service, *, host_contract=None, clock=time.monotonic):
        self.service=service
        self.host_contract=host_contract
        self.clock=clock
        self.items={}

    def _now(self):
        value=self.clock()
        if type(value) not in (int,float) or not math.isfinite(value) or value<0:
            raise ValueError('FAST_FIX_CLOCK_UNAVAILABLE')
        return value

    @staticmethod
    def fallback(reason, *, eligible=False):
        return {'fix_path':'AGENT_FIX','fast_fix':{'status':'FAST_FIX_NOT_APPLICABLE',
            'eligible':eligible,'fallback_reason':reason,'plan_ready':False,
            'host_edit_contract_required':HOST_CONTRACT,'host_fast_edit_observed':False}}

    def offer(self, output, root, record, key):
        # Acceleration consumes an existing human-approved grant; never consent.
        if (output.get('action')!='AUTO_FIX' or output.get('reason_code')!='USER_APPROVED_REPAIR'
                or record.get('authorization_kind')!='USER_CONFIRMED'):
            output.update(self.fallback('FAST_FIX_POLICY_NOT_ELIGIBLE')); return
        service=self.service
        if self.host_contract!=HOST_CONTRACT:
            output.update(self.fallback('FAST_FIX_HOST_CAPABILITY_UNAVAILABLE')); return
        try:
            if not service._member_current(record,root):
                output.update(self.fallback('FAST_FIX_FINDING_IDENTITY_MISMATCH')); return
            scan=service.store.get_scan(record['origin_scan_id'])
            members=[r for r in scan['findings'] if r['file_path']==record['target'] and
                     r.get('technical_details',{}).get('rule_id')==RULE]
            if len(members)!=1:
                output.update(self.fallback('FAST_FIX_AMBIGUOUS_TARGET')); return
            member=members[0]
            edit=removal(root,record['target'],key,member['line_start'])
            policy=service._policy_binding(key)[1]
            if (not service._allowed(record,key) or service._snapshot(root)!=record['last_snapshot_digest']
                    or not service._guard(root,record,key)):
                output.update(self.fallback('FAST_FIX_STALE_SNAPSHOT')); return
            now=self._now()
            self.items={k:v for k,v in self.items.items() if now<v['deadline']}
            if len(self.items)>=MAX_PLANS:
                output.update(self.fallback('FAST_FIX_PLAN_BUDGET_EXCEEDED')); return
            arguments=output['prepare']['arguments']
            plan={'schema_version':'hostname-remove-v1','fix_path':'DETERMINISTIC_FAST_FIX',
                'workspace_id':identity(os.path.normcase(str(root))),
                'episode_id':record['episode_id'],'grant_id':record['token_hash'],
                'task_ref':arguments['task_ref'],'remediation_ref':arguments['remediation_ref'],
                'origin_scan_id':record['origin_scan_id'],'finding_id':member['id'],
                'rule_id':RULE,'target_path':record['target'],
                'expected_snapshot_digest':record['last_snapshot_digest'],**edit,
                'operation':'DETERMINISTIC_REMOVE','replacement':'',
                'plan_ref':'fastfix-v1.'+secrets.token_hex(32),
                'expires_in_seconds':TTL,'host_edit_contract':HOST_CONTRACT,
                'result_contract':{'required':'POST_TOOL_USE_REAL_SCANNER_PROOF',
                    'success':'SCANNER_VERIFIED_RESOLVED','stage':'CLOSED','next_action':'RETURN_TO_HOST',
                    'production_correctness':'UNKNOWN','deep_verification_authorized':False}}
            self.items[plan['plan_ref']]={'plan':copy.deepcopy(plan),'root':root,
                'deadline':now+TTL,'issued':now,'policy':policy,'claimed':False}
            output.update(fix_path='DETERMINISTIC_FAST_FIX',guidance=GUIDANCE,fast_fix_plan=plan,
                fast_fix={'status':'FAST_FIX_PLAN_READY','eligible':True,'fallback_reason':None,
                          'plan_ready':True,'host_fast_edit_observed':False,
                          'host_edit_contract':HOST_CONTRACT},
                interaction={**output['interaction'],'next_action':'HOST_BOUND_EDIT'},
                agent_fallback=copy.deepcopy(output['prepare']))
            output.pop('prepare')  # No second preparation round-trip on this path.
        except Exception:
            output.update(self.fallback('FAST_FIX_AMBIGUOUS_TARGET'))

    def validate_and_claim(self, plan, root):
        """Host bridge calls INSIDE its exclusive target-edit region, before write.

        No edit is performed. This is not an MCP tool and is not available to a
        default Codex host. Failed claims do not consume grant/attempt authority.
        """
        service=self.service
        def fail(reason,status='FAST_FIX_NOT_APPLICABLE'):
            return {'status':status,'fix_path':'AGENT_FIX','reason_code':reason,'source_modified':False,
                    'next_action':'REFRESH_HOOK_OR_AGENT_FIX'}
        try:
            root=Path(root).resolve()
            if self.host_contract!=HOST_CONTRACT:
                return fail('FAST_FIX_HOST_CAPABILITY_UNAVAILABLE')
            if not isinstance(plan,dict) or not isinstance(plan.get('plan_ref'),str):
                return fail('FAST_FIX_PLAN_INVALID')
            item=self.items.get(plan['plan_ref'])
            if item is None:
                return fail('FAST_FIX_AUTHORIZATION_UNKNOWN_OR_RECONNECTED')
            original=item['plan']
            if root!=item['root'] or plan.get('workspace_id')!=original['workspace_id']:
                return fail('FAST_FIX_WORKSPACE_MISMATCH')
            if plan.get('episode_id')!=original['episode_id']:
                return fail('FAST_FIX_EPISODE_MISMATCH')
            if any(plan.get(k)!=original[k] for k in ('remediation_ref','task_ref','grant_id')):
                return fail('FAST_FIX_REMEDIATION_MISMATCH')
            if plan.get('rule_id')!=RULE:
                return fail('FAST_FIX_UNSUPPORTED_RULE')
            # Dict equality alone treats bool/int and int/float as equivalent.
            # Serialize metadata for strict identity; opaque strings stay intact.
            if encoded_plan(plan)!=encoded_plan(original):
                return fail('FAST_FIX_PLAN_TAMPERED')
            now=self._now()
            if now<item['issued'] or now>=item['deadline'] or item['claimed']:
                return fail('FAST_FIX_AUTHORIZATION_EXPIRED_OR_CONSUMED')
            _,key,_,record=service._reference(root,plan['remediation_ref'],plan['task_ref'])
            if record['episode_id']!=plan['episode_id']:
                return fail('FAST_FIX_EPISODE_MISMATCH')
            if (record['phase'] not in {'OFFERED','AUTHORIZED'} or not service._allowed(record,key)
                    or service._policy_binding(key)[1]!=item['policy']):
                return fail('FAST_FIX_AUTHORIZATION_INVALID')
            if not service._member_current(record,root):
                return fail('FAST_FIX_FINDING_IDENTITY_MISMATCH')
            target=root/plan['target_path']
            content=read_target(target)
            if sha(content)!=plan['expected_file_sha256']:
                return fail('FAST_FIX_EXPECTED_BYTES_MISMATCH','FAST_FIX_STALE')
            if service._snapshot(root)!=plan['expected_snapshot_digest']:
                return fail('FAST_FIX_STALE_SNAPSHOT','FAST_FIX_STALE')
            if not service._guard(root,record,key):
                return fail('FAST_FIX_CONCURRENT_MODIFICATION','FAST_FIX_STALE')
            if len(service.prepared)>=32:
                return fail('FAST_FIX_PREPARATION_BUDGET_EXCEEDED')
            item['claimed']=True
            service.prepared.add(record['token_hash'])  # Same original proof gate.
            service._observe_cycle('mark',root,record['episode_id'],'fast_fix_apply_authorized')
            return {'status':'FAST_FIX_APPLY_AUTHORIZED','source_modified':False,
                    'fix_path':'DETERMINISTIC_FAST_FIX'}
        except Exception:
            return fail('FAST_FIX_AUTHORIZATION_INVALID')

    def current(self, record):
        matches=[v for v in self.items.values() if v['plan']['grant_id']==record.get('token_hash') and
                 v['plan']['episode_id']==record['episode_id']]
        return matches[0] if len(matches)==1 else None

    def post_edit_matches(self, record, root):
        item=self.current(record)
        if not item or not item['claimed']:
            return False
        try:
            path=root/item['plan']['target_path']
            return sha(read_target(path))==item['plan']['expected_result_sha256']
        except (ValueError,OSError):
            return False

    def forget(self, record):
        self.items={k:v for k,v in self.items.items() if v['plan']['grant_id']!=record.get('token_hash')}
