"""Tests for Watchtower's AbuseIPDB integration."""

import asyncio
import json

import httpx
import pytest

from watchtower.threat_intel import (
    ThreatIntelConfigurationError,
    ThreatIntelRateLimited,
    ThreatIntelUnavailable,
    clear_cache,
    lookup_ip_reputation,
    normalize_public_ip,
)


def test_normalizes_public_ip():
    assert normalize_public_ip(" 8.8.8.8 ") == "8.8.8.8"


@pytest.mark.parametrize("value", ["not-an-ip", "127.0.0.1", "10.0.0.1", "::1", "192.168.1.5"])
def test_rejects_invalid_or_non_public_ip(value):
    with pytest.raises(ValueError):
        normalize_public_ip(value)


def test_missing_api_key_fails_closed():
    async def run():
        with pytest.raises(ThreatIntelConfigurationError):
            await lookup_ip_reputation("8.8.8.8", api_key="")
    asyncio.run(run())


def test_lookup_normalizes_and_caches_provider_response():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.url.params["ipAddress"] == "8.8.8.8"
        assert request.headers["Key"] == "test-key"
        return httpx.Response(200, json={"data": {
            "ipAddress": "8.8.8.8",
            "ipVersion": 4,
            "abuseConfidenceScore": 12,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Example ISP",
            "domain": "example.net",
            "totalReports": 4,
            "numDistinctUsers": 3,
            "lastReportedAt": "2026-10-01T12:00:00+00:00",
            "isWhitelisted": False,
        }})

    async def run():
        await clear_cache()
        transport = httpx.MockTransport(handler)
        first = await lookup_ip_reputation("8.8.8.8", api_key="test-key", transport=transport)
        second = await lookup_ip_reputation("8.8.8.8", api_key="test-key", transport=transport)
        assert first.abuse_confidence_score == 12
        assert first.cached is False
        assert second.cached is True
        assert calls == 1
        await clear_cache()

    asyncio.run(run())


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (429, ThreatIntelRateLimited),
        (503, ThreatIntelUnavailable),
        (401, ThreatIntelConfigurationError),
    ],
)
def test_upstream_errors_are_not_reported_as_clean(status_code, expected):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": "provider error"})

    async def run():
        await clear_cache()
        with pytest.raises(expected):
            await lookup_ip_reputation(
                "8.8.4.4", api_key="test-key", transport=httpx.MockTransport(handler)
            )
        await clear_cache()

    asyncio.run(run())
