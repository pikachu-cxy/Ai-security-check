"""Bounded estimates from real byte deltas, never a synthetic countdown."""
from collections import deque
import math


class DownloadEstimate:
    def __init__(self, *, window_seconds=30, minimum_seconds=3, stale_seconds=10):
        self.window_seconds = window_seconds
        self.minimum_seconds = minimum_seconds
        self.stale_seconds = stale_seconds
        self.reset()

    def reset(self):
        self._samples = deque(maxlen=128)
        self._total = None
        self._received = None
        self._last_progress = None

    def update(self, received, total, now):
        if (type(received) is not int or type(total) is not int
                or not 0 <= received <= total <= 8_000_000_000 or total == 0
                or isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now)):
            return None
        if (total != self._total or self._received is not None and received < self._received
                or self._last_progress is not None and now < self._last_progress):
            self.reset()
        if self._received is None or received > self._received:
            self._last_progress = now
            self._received, self._total = received, total
            if not self._samples or now - self._samples[-1][0] >= .25 or received == total:
                self._samples.append((now, received))
            while len(self._samples) > 2 and self._samples[1][0] <= now - self.window_seconds:
                self._samples.popleft()
        return self.estimate(now)

    def estimate(self, now):
        if (len(self._samples) < 2 or self._last_progress is None
                or not isinstance(now, (int, float)) or not math.isfinite(now)
                or now < self._last_progress or now - self._last_progress > self.stale_seconds):
            return None
        elapsed = self._last_progress - self._samples[0][0]
        delta = self._received - self._samples[0][1]
        if elapsed < self.minimum_seconds or delta <= 0:
            return None
        rate = delta / elapsed
        return dict(bytes_per_second=rate, remaining_seconds=math.ceil((self._total - self._received) / rate))
