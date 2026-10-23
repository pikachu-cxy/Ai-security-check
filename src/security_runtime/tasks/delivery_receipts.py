"""Versioned response facts, separate from tasks, risk truth and authorization.

RESPONSE_PREPARED does not prove that a transport wrote the response, a host
submitted its report, or a person consumed it. No consumption attestation is
supported. Original task records and budgets are never modified here.
"""
from __future__ import annotations

import re
import sqlite3

from ..host_event_journal import _SignedRows, JournalError, digest, valid_digest
from .ownership import record_owner, valid_owner
from ..task_review.protocol import require_record_protocol

CONTRACT = 'task-delivery-receipt-v1'
DELIVERY_REF = re.compile(r'tdr1-[a-f0-9]{64}')
INTENTS = {'TASK_FINAL_SUMMARY', 'TASK_CLOSEOUT'}
CATEGORIES = {'POST_TOOL_CONTEXT', 'STOP_FOLLOWUP', 'TASK_RESULT'}


def result_version(record):
    require_record_protocol(record)
    # Generation, leases, token values, evidence reads and delivery bookkeeping
    # do not create a new result. Only a digest leaves this function.
    static = record.get('static') or {}
    review = record.get('review') or {}
    return digest(dict(task_ref=record['task_ref'], phase=record['phase'], protocol=3,
        hashes=(record.get('end') or record.get('baseline') or {}).get('hashes'),
        static={key: static.get(key) for key in ('scan_id', 'status', 'coverage', 'findings', 'scope_files')},
        review={key: review.get(key) for key in ('coverage', 'status', 'findings', 'limitations')},
        review_revision=record.get('review_revision'),
        hook_revision=record.get('finished_hook_revision'),
        hook={key: record.get(key) for key in ('hook_checks', 'hook_checks_omitted',
            'hook_pending_scope_files', 'hook_recheck_files', 'hook_pending_paths_omitted',
            'hook_recheck_paths_omitted')},
        projection=(record.get('ledger_projection') or {}).get('state')))


def _owner(record, owner):
    if record_owner(record) != owner:
        raise JournalError('Delivery task owner mismatch')
    if owner is not None and not valid_owner(owner):
        raise JournalError('Invalid delivery owner')
    return owner


def unavailable():
    return dict(contract=CONTRACT, delivery_ref=None, result_version=None,
        response_prepared=False, transport_written=False, host_report_submitted='NOT_OBSERVED',
        user_consumption='UNKNOWN', recording='UNAVAILABLE')


class TaskDeliveryReceipts(_SignedRows):
    def __init__(self, hooks, root, **kwargs):
        super().__init__(hooks, root, 'task-deliveries.db', 'task_deliveries', **kwargs)

    def _validate(self, value):
        if value is not None and (value.get('contract') != CONTRACT
                or not isinstance(value.get('ref'), str) or not DELIVERY_REF.fullmatch(value['ref'])
                or not isinstance(value.get('task_ref'), str) or not re.fullmatch(r'ts1-[a-f0-9]{32}', value['task_ref'])
                or value.get('owner') is not None and not valid_owner(value['owner'])
                or not valid_digest(value.get('result_version'))
                or value.get('state') not in {'PREPARED', 'REPORTED', 'SUPERSEDED'}
                or value.get('intent') not in INTENTS or value.get('category') not in CATEGORIES
                or any(type(value.get(field)) is not bool for field in
                       ('response_prepared', 'transport_written', 'host_report_submitted'))):
            raise JournalError('Invalid delivery receipt contract')
        return value

    @staticmethod
    def facts(value):
        return dict(contract=CONTRACT, delivery_ref=value['ref'], result_version=value['result_version'],
            response_prepared=value['response_prepared'], transport_written=value['transport_written'],
            host_report_submitted='REPORTED' if value['host_report_submitted'] else 'NOT_OBSERVED',
            user_consumption='UNKNOWN', recording='RECORDED')

    def prepare(self, record, owner, *, intent, category):
        require_record_protocol(record)
        _owner(record, owner)
        if intent not in INTENTS or category not in CATEGORIES:
            raise JournalError('Invalid delivery intent or category')
        if not re.fullmatch(r'ts1-[a-f0-9]{32}', record.get('task_ref', '')):
            raise JournalError('Invalid delivery task reference')
        version = result_version(record)
        subject = dict(workspace=self.workspace, owner=owner, task_ref=record['task_ref'],
                       result_version=version, intent=intent, category=category)
        reference = 'tdr1-'+digest(subject)
        with self._transaction() as (db, key):
            old = self._validate(self._get(db, reference, key))
            if old is not None:
                return self.facts(old)
            for item in self._all(db, key):
                self._validate(item)
                if (item['owner'] == owner and item['task_ref'] == record['task_ref']
                        and item['intent'] == intent and item['category'] == category
                        and item['result_version'] != version and item['state'] != 'SUPERSEDED'):
                    self._put(db, item['ref'], dict(item, state='SUPERSEDED'), key)
            value = dict(subject, contract=CONTRACT, ref=reference, state='PREPARED',
                         response_prepared=True, transport_written=False, host_report_submitted=False,
                         created_at=self.now(), revision=0)
            return self.facts(self._put(db, reference, value, key, new=True))

    def get(self, reference, owner):
        if not isinstance(reference, str) or not DELIVERY_REF.fullmatch(reference):
            raise JournalError('Invalid delivery reference')
        value = self._validate(self._read(reference))
        if value is not None and value['owner'] != owner:
            raise JournalError('Delivery owner mismatch')
        return self.facts(value) if value else None

    def observe(self, reference, owner, version, *, stage):
        if (not isinstance(reference, str) or not DELIVERY_REF.fullmatch(reference)
                or not valid_digest(version) or stage not in {'TRANSPORT_WRITTEN', 'HOST_REPORT_SUBMITTED'}):
            raise JournalError('Invalid delivery observation')
        with self._transaction() as (db, key):
            value = self._validate(self._get(db, reference, key))
            if value is None or value['owner'] != owner or value['result_version'] != version:
                raise JournalError('Delivery observation binding mismatch')
            field = 'transport_written' if stage == 'TRANSPORT_WRITTEN' else 'host_report_submitted'
            if not value[field]:
                value = self._put(db, reference, dict(value, **{field: True},
                    state='REPORTED' if stage == 'HOST_REPORT_SUBMITTED' and value['state'] != 'SUPERSEDED' else value['state']), key)
            return self.facts(value)


class DeliveryWriteObserver:
    """In-memory binding passed by the validated handler to its local writer.

    The writer calls ``written`` only after a successful write AND flush. No
    executable/control text is parsed and no task/scanner effect is retried.
    """
    def __init__(self):
        self._binding = None

    def bind(self, hooks, root, owner, receipt):
        if (not isinstance(receipt, dict) or receipt.get('contract') != CONTRACT
                or receipt.get('recording') != 'RECORDED' or receipt.get('response_prepared') is not True
                or not isinstance(receipt.get('delivery_ref'), str)
                or not DELIVERY_REF.fullmatch(receipt['delivery_ref'])
                or not valid_digest(receipt.get('result_version'))
                or owner is not None and not valid_owner(owner)):
            raise JournalError('Invalid prepared response binding')
        store = TaskDeliveryReceipts(hooks, root)
        binding = (store, dict(owner) if owner is not None else None,
                   receipt['delivery_ref'], receipt['result_version'])
        if self._binding is not None:
            old = self._binding
            if old[0].path != store.path or old[1:] != binding[1:]:
                raise JournalError('Prepared response binding changed')
            return
        self._binding = binding

    def written(self):
        if self._binding is None:
            return False
        store, owner, reference, version = self._binding
        try:
            store.observe(reference, owner, version, stage='TRANSPORT_WRITTEN')
            return True
        except (ValueError, OSError, sqlite3.DatabaseError):
            return False  # Response may already be written; retain pending ACK.
