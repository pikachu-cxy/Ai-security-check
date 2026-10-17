"""The first editing task waits for a short preparation publication lock."""
from contextlib import contextmanager
from threading import Event, Thread

from test_task_security import service  # noqa: F401; shared fixture


def test_task_start_waits_for_short_seed_publication_instead_of_returning_busy(service, monkeypatch):
    s, root, _ = service
    original = s.hooks.lock
    waiting, release = Event(), Event()
    results, errors = [], []

    @contextmanager
    def observed_lock(path, **kwargs):
        waiting.set()
        with original(path, **kwargs) as acquired:
            yield acquired

    def begin():
        try:
            results.append(s.begin(root, 'start-during-short-publication'))
        except BaseException as exc:
            errors.append(exc)
        finally:
            release.set()

    with original(root) as held:
        assert held
        monkeypatch.setattr(s.hooks, 'lock', observed_lock)
        worker = Thread(target=begin, daemon=True)
        worker.start()
        assert waiting.wait(2)
        # A zero-wait begin would finish BUSY while the publication lock is held.
        assert not release.wait(.1)
    worker.join(5)
    assert not worker.is_alive() and not errors
    assert results[0]['status'] == 'ACTIVE'
    assert results[0]['task_ref'].startswith('ts1-')
    assert len(s.store(root).records(active=True)) == 1
