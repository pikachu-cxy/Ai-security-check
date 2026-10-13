"""ETA follows measured transfer, with bounded sampling and honest unknowns."""
import pytest

from security_runtime.download_estimate import DownloadEstimate


def test_stable_transfer_estimates_remaining_and_tracks_speed_changes():
    model = DownloadEstimate()
    assert model.update(0, 1000, 0) is None
    assert model.update(200, 1000, 2) is None
    estimate = model.update(400, 1000, 4)
    assert estimate == dict(bytes_per_second=100., remaining_seconds=6)
    assert model.estimate(8) == estimate  # No invented countdown without more bytes.
    for timestamp in range(5, 41):
        received = 400 + (timestamp - 4) * 10
        estimate = model.update(received, 1000, timestamp)
    assert estimate['bytes_per_second'] == 10
    assert estimate['remaining_seconds'] == 24


def test_duplicate_counts_do_not_refresh_a_stalled_estimate():
    model = DownloadEstimate()
    model.update(0, 1000, 0)
    assert model.update(400, 1000, 4)['remaining_seconds'] == 6
    assert model.update(400, 1000, 15) is None
    assert model.estimate(15) is None


@pytest.mark.parametrize('received,total,now', [(10, 1000, 5), (400, 2000, 5), (500, 1000, 1)])
def test_count_rollback_total_change_or_clock_change_restarts_estimation(received, total, now):
    model = DownloadEstimate()
    model.update(0, 1000, 0)
    model.update(400, 1000, 4)
    assert model.update(received, total, now) is None


@pytest.mark.parametrize('received,total,now', [(True, 100, 0), (-1, 100, 0), (101, 100, 0),
    (0, 0, 0), (10, 100, float('nan')), (10, 100, float('inf'))])
def test_invalid_values_never_produce_estimates(received, total, now):
    assert DownloadEstimate().update(received, total, now) is None


def test_high_frequency_input_retains_bounded_samples_and_can_estimate():
    model = DownloadEstimate()
    for n in range(10000):
        estimate = model.update(n, 20000, n / 1000)
    assert len(model._samples) <= 128
    assert estimate['remaining_seconds'] == 11
