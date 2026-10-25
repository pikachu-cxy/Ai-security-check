"""Finite file-local JavaScript parts, with exact-input scanner fact recovery.

Only the canonical lexical provider is split. Project/cross-file providers keep
their existing complete context. No task evidence or risk decisions are reused.
"""
from dataclasses import asdict, replace
import hashlib
import hmac
import math
import sqlite3
import time

from .closeout_state import encode
from .models import Finding
from .progress import checkpoint, ScanCancelled
from .tasks.durable import SignedRecords

CONTRACT = 'native-js-file-partitions-v1'
FILES = 256
BYTES = 8_000_000


class NativeParts(SignedRecords):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'native-js-parts.db', **kwargs)

    def identity(self, context, plan, names, normalizer):
        from .build_identity import build_identity
        view = context.input_view
        if view is None or not view._key:
            raise ValueError('Original fixed input required for partition recovery')
        value = dict(contract=CONTRACT, source=view.source_revision,
            provider=plan.pack.checksum, build=build_identity()['build_id'],
            mode=str(context.mode), files=names, identity_root=str(normalizer.identity_root))
        return hmac.new(self._key(), encode(value), hashlib.sha256).hexdigest()

    def facts(self, identity, names, checksum):
        from .dynamic_function import RULE_ID
        row = self.read(identity)
        if row is None:
            return None
        if (set(row) != {'contract', 'files', 'checksum', 'findings', 'rules', 'created_at', 'expires_at', 'key', 'workspace'}
                or row.get('contract') != CONTRACT or row.get('files') != list(names)
                or row.get('checksum') != checksum
                or row.get('rules') != [RULE_ID] or not isinstance(row.get('findings'), list)
                or any(type(row.get(key)) not in {int, float} or not math.isfinite(row[key]) for key in ('created_at', 'expires_at'))
                or row['expires_at'] != row['created_at']+86400
                or any(not isinstance(f, dict) or f.get('file_path') not in names or f.get('status') != 'OPEN'
                       for f in row['findings'])):
            raise ValueError('Original partition facts cannot be verified')
        if row['expires_at'] <= self.now():
            return None
        return row

    def save_facts(self, identity, names, plan, findings):
        if (set(plan.scanned_files) != set(names) or plan.errored_files or plan.skipped_files
                or plan.unscoped_error or plan.coverage('SUCCESS')['status'] != 'EXECUTED'):
            raise ValueError('Incomplete partition cannot be saved as complete')
        with self.transaction() as db:
            for row in self._all(db):
                if row['expires_at'] <= self.now():
                    db.execute('DELETE FROM records WHERE key=?', (row['key'],))
            instant = self.now()
            self._put(db, identity, dict(contract=CONTRACT, files=list(names),
                checksum=plan.pack.checksum, findings=[asdict(f) for f in findings],
                rules=sorted(plan.confirmed_rules), created_at=instant, expires_at=instant+86400))


def groups(context, names):
    # Uncaptured SDK calls use the reader's worst-case one-MB file allowance;
    # planning must not stat arbitrary caller paths outside the workspace.
    entries = context.input_view.source_entries if context.input_view is not None else {}
    group, size = [], 0
    for name in names:
        weight = entries[name].size if name in entries else 1_000_000
        if group and (len(group) >= FILES or size+weight > BYTES):
            yield tuple(group)
            group, size = [], 0
        group.append(name)
        size += weight
    if group:
        yield tuple(group)


def scan(scanner, context, normalizer, *, state=None):
    from .dynamic_function import NativeFunctionRulePlan, RULE_ID, rule_pack
    from .scan_input import CapturedScanInput
    started = time.monotonic()
    try:
        plan = context.rule_plan if isinstance(context.rule_plan, NativeFunctionRulePlan) else scanner.plan_rules(None, context)
    except (OSError, ValueError):
        return scanner._scan_page(context, normalizer)
    if context.input_view is not None and not isinstance(context.input_view, CapturedScanInput):
        plan.unscoped_error = True
        return [], scanner._run(plan, started, [], 'NATIVE_CAPTURED_IDENTITY_CHANGED')
    if context.input_view is not None:
        try:
            context.input_view._require_active()
            if any(binding not in context.input_view.request.bindings for binding in scanner.input_bindings()):
                raise ValueError('Captured rule identity changed')
        except (OSError, ValueError):
            plan.unscoped_error = True
            return [], scanner._run(plan, started, [], 'NATIVE_CAPTURED_IDENTITY_CHANGED')
    parts = list(groups(context, plan.files))
    if state is None and len(parts) <= 1:
        return scanner._scan_page(replace(context, rule_plan=plan), normalizer)
    store = NativeParts(state.hooks, state.root, now=state.now) if state is not None else None
    findings, receipts = [], []
    failure = ''
    for number, names in enumerate(parts):
        checkpoint()
        part = NativeFunctionRulePlan(plan.pack, names)
        identity, cached = None, None
        executed = False
        try:
            # A changed implementation must not reuse facts from an earlier
            # in-memory plan, even if its old stored key still matches.
            if plan.pack.checksum != rule_pack().checksum:
                raise ValueError('Rule identity changed')
            if store is not None:
                identity = store.identity(context, plan, names, normalizer)
                cached = store.facts(identity, names, plan.pack.checksum)
            if cached is not None:
                found = [Finding(**value) for value in cached['findings']]
                part.scanned_files.update(names)
                part.confirmed_rules.update(cached['rules'])
                complete = RULE_ID in part.confirmed_rules
                if not complete:
                    raise ValueError('Partition rule receipt missing')
            else:
                executed = True
                found, run = scanner._scan_page(replace(context, files=names, rule_plan=part), normalizer)
                complete = run.status == 'SUCCESS' and run.coverage_contract == 'FULL'
            findings.extend(found)
            plan.scanned_files.update(part.scanned_files)
            plan.confirmed_rules.update(part.confirmed_rules)
            plan.errored_files.update(part.errored_files)
            plan.skipped_files.update(part.skipped_files)
            plan.unscoped_error |= part.unscoped_error
            if complete and store is not None and cached is None:
                store.save_facts(identity, names, part, found)
            if not complete:
                missing = set(names)-part.scanned_files
                plan.errored_files.update(missing)
                plan.skipped_files.update({name: 'PARTITION_INCOMPLETE' for name in missing})
                failure = failure or 'LOCAL_SCOPE_INCOMPLETE'
            receipts.append(dict(index=number, files=len(names), state='COMPLETE' if complete else 'INCOMPLETE',
                reused=cached is not None, scanner_run=cached is None))
        except ScanCancelled:
            raise
        except (OSError, ValueError, TypeError, KeyError, sqlite3.DatabaseError) as error:
            # Capacity/control failures retain every earlier committed part;
            # an uncommitted part is retried, never counted as durable progress.
            full = (isinstance(error, sqlite3.OperationalError) and getattr(error, 'sqlite_errorcode', None) == sqlite3.SQLITE_FULL
                or isinstance(error, ValueError) and str(error) in {'Task operation storage capacity exceeded',
                    'Task operation record too large', 'Task operation capacity exceeded'})
            failure = 'SCAN_PARTITION_WAITING_CAPACITY' if full else 'SCAN_PARTITION_STATE_UNAVAILABLE'
            plan.unscoped_error = True
            for remaining in parts[number:]:
                for name in remaining:
                    plan.errored_files.add(name)
                    plan.skipped_files[name] = failure
            receipts.append(dict(index=number, files=len(names), state='PAUSED', reused=False, scanner_run=executed))
            break
    try:
        verified = plan.pack.checksum == rule_pack().checksum
    except (OSError, ValueError):
        verified = False
    if not verified:
        plan.unscoped_error = True
        failure = 'NATIVE_RULE_IDENTITY_CHANGED'
    run = scanner._run(plan, started, findings, failure)
    reused = sum(part['reused'] for part in receipts)
    fresh = sum(part['scanner_run'] for part in receipts)
    run.scanner_diagnostics.update(partitions=dict(contract=CONTRACT, total=len(parts),
        complete=sum(part['state']=='COMPLETE' for part in receipts), reused=reused, fresh=fresh,
        durable=store is not None, receipts=receipts), local_read_observed=bool(fresh),
        rule_execution='VERIFIED_PARTITION_FACTS' if reused else 'FRESH_LOCAL_LEXICAL_TRAVERSAL')
    if reused:
        run.rule_coverage['execution_evidence'] = 'Exact-input signed partition facts; fresh and reused parts are reported separately.'
    if context.input_view is not None:
        run.scanner_diagnostics['execution_binding'] = dict(contract='scanner-execution-binding-v1',
            tool=plan.pack.checksum, data=None, data_required=False, verified=verified,
            data_status='VERIFIED' if verified else 'UNVERIFIABLE')
    return findings, run
