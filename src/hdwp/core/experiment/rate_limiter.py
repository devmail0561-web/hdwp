# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import asyncio
import time


class TokenBucket:
    """Async rate limiter using the token bucket algorithm."""

    def __init__(self, rate: float, capacity: int | None = None) -> None:
        """
        Args:
            rate: Tokens added per second (e.g. 1.0 for 60 req/min).
            capacity: Maximum burst size.  Defaults to ``max(1, int(rate))``.
        """
        self._rate = rate
        self._capacity = capacity if capacity is not None else max(1, int(rate))
        self._tokens = float(self._capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    async def acquire(self) -> None:
        """Block until a token is available, then consume it."""
        while True:
            async with self._lock:
                self._refill()
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self._rate
            await asyncio.sleep(wait)

    @property
    def max_rate(self) -> float:
        """Returns the rate in tokens per second."""
        return self._rate

    @classmethod
    def from_rpm(cls, requests_per_minute: int) -> "TokenBucket":
        """Create a bucket calibrated to *requests_per_minute*."""
        rate = requests_per_minute / 60.0
        return cls(rate=rate, capacity=max(1, requests_per_minute // 10))
