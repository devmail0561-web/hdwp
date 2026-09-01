# Copyright (c) 2026 M. TENDENG
# Licensed under the MIT License. See LICENSE file for details.

import asyncio

import pytest

from hdwp.core.experiment.rate_limiter import TokenBucket


@pytest.mark.asyncio
async def test_acquire_succeeds_when_tokens_available():
    bucket = TokenBucket(rate=10.0, capacity=5)
    await bucket.acquire()


@pytest.mark.asyncio
async def test_acquire_blocks_when_empty():
    bucket = TokenBucket(rate=1.0, capacity=1)
    await bucket.acquire()  # consume the single token
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(bucket.acquire(), timeout=0.05)


@pytest.mark.asyncio
async def test_tokens_refill_over_time():
    bucket = TokenBucket(rate=100.0, capacity=1)
    await bucket.acquire()  # empty the bucket
    await asyncio.sleep(0.02)  # let ~2 tokens refill at 100/s
    await asyncio.wait_for(bucket.acquire(), timeout=0.05)


@pytest.mark.asyncio
async def test_burst_capacity():
    bucket = TokenBucket(rate=1.0, capacity=3)
    await bucket.acquire()
    await bucket.acquire()
    await bucket.acquire()
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(bucket.acquire(), timeout=0.05)


@pytest.mark.asyncio
async def test_from_rpm():
    bucket = TokenBucket.from_rpm(60)
    assert bucket._rate == pytest.approx(1.0)
    await bucket.acquire()
