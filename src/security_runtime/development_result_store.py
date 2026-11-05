"""One signed development result containing scanner facts and subsequent decisions.

Legacy risk files are read-only migration sources, never a second write target.
The embedded object and check publication share the same SQLite transaction.
"""
from contextlib import contextmanager
from contextvars import ContextVar

from .tasks.durable import SignedRecords


class DevelopmentResultStore:
    def __init__(self, checks):
        self.checks = checks
        self.path = checks.path
        self.legacy = SignedRecords(checks.hooks, checks.root, 'development-risks.db')
        self.active = ContextVar('development_result_transaction', default=None)

    @contextmanager
    def transaction(self):
        with self.checks.transaction() as db:
            token = self.active.set(db)
            try:
                yield db
            finally:
                self.active.reset(token)

    def _get(self, db, ref):
        check = self.checks._get(db, ref)
        if check is not None and 'security_result' in check:
            return check['security_result']
        return self.legacy.read(ref)

    def read(self, ref):
        check = self.checks.read(ref)
        if check is not None and 'security_result' in check:
            return check['security_result']
        return self.legacy.read(ref)

    def _put(self, db, ref, result):
        check = self.checks._get(db, ref)
        if check is None:
            raise ValueError('DEVELOPMENT_CHECK_UNAVAILABLE')
        self.checks._put(db, ref, dict(check, security_result=result,
                                      result_storage='embedded-development-result-v1'))
        return result
