"""AbuseIPDB threat-intelligence client with bounded in-process caching."""

import asyncio
import ipaddress
import os
import time
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_SECONDS = 900
CACHE_MAX_ENTRIES = 1000


class ThreatIntelError(Exception):
    """Safe, user-facing threat-intelligence integration error."""


class ThreatIntelConfigurationError(ThreatIntelError):
    """The provider is not configured or its credentials are invalid."""


class ThreatIntelUnavailable(ThreatIntelError):
    """The provider could not return a trustworthy result."""


class ThreatIntelRateLimited(ThreatIntelError):
    """The upstream provider quota has been exhausted."""


class IPReputation(BaseModel):
    """Normalized, provider-neutral IP reputation response."""

    model_config = ConfigDict(extra="ignore")

    provider: str = "abuseipdb"
    ip_address: str
    ip_version: int
    is_public: bool = True
    abuse_confidence_score: int = Field(ge=0, le=100)
    country_code: str | None = None
    usage_type: str | None = None
    isp: str | None = None
    domain: str | None = None
    total_reports: int = Field(ge=0)
    num_distinct_users: int = Field(ge=0)
    last_reported_at: str | None = None
    is_whitelisted: bool | None = None
    cached: bool = False


# Cache is deliberately bounded and short-lived. It stores only public IP reputation,
# never API keys or user/workspace data. A multi-worker deployment should later use Redis.
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_cache_lock = asyncio.Lock()


def normalize_public_ip(value: str) -> str:
    """Validate and canonicalize a public IP before sending it to a third party."""
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("A valid IPv4 or IPv6 address is required") from exc
    if not parsed.is_global:
        raise ValueError("Only public, globally routable IP addresses can be checked")
    return str(parsed)


async def clear_cache() -> None:
    """Clear the process cache (primarily useful for deterministic tests)."""
    async with _cache_lock:
        _cache.clear()


async def lookup_ip_reputation(
    value: str,
    *,
    api_key: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> IPReputation:
    """Look up a public IP using AbuseIPDB; failures never masquerade as clean results."""
    ip_address = normalize_public_ip(value)
    key = api_key if api_key is not None else os.getenv("ABUSEIPDB_API_KEY", "")
    if not key.strip():
        raise ThreatIntelConfigurationError(
            "AbuseIPDB is not configured. Set ABUSEIPDB_API_KEY on the API server."
        )

    now = time.monotonic()
    async with _cache_lock:
        cached = _cache.get(ip_address)
        if cached and cached[0] > now:
            return IPReputation.model_validate({**cached[1], "cached": True})
        if cached:
            _cache.pop(ip_address, None)

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0), transport=transport) as client:
            response = await client.get(
                ABUSEIPDB_CHECK_URL,
                params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": key, "Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise ThreatIntelUnavailable("AbuseIPDB could not be reached; try again later") from exc

    if response.status_code == 429:
        raise ThreatIntelRateLimited("AbuseIPDB rate limit reached; retry later")
    if response.status_code in (401, 403):
        raise ThreatIntelConfigurationError("AbuseIPDB rejected the configured API key")
    if response.status_code >= 500:
        raise ThreatIntelUnavailable("AbuseIPDB is temporarily unavailable")
    if response.status_code != 200:
        raise ThreatIntelUnavailable(f"AbuseIPDB returned an unexpected status ({response.status_code})")

    try:
        data = response.json()["data"]
        result = IPReputation(
            ip_address=ip_address,
            ip_version=data["ipVersion"],
            abuse_confidence_score=data["abuseConfidenceScore"],
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            total_reports=data.get("totalReports", 0),
            num_distinct_users=data.get("numDistinctUsers", 0),
            last_reported_at=data.get("lastReportedAt"),
            is_whitelisted=data.get("isWhitelisted"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ThreatIntelUnavailable("AbuseIPDB returned an invalid response") from exc

    cache_payload = result.model_dump()
    cache_payload["cached"] = False
    async with _cache_lock:
        if len(_cache) >= CACHE_MAX_ENTRIES:
            oldest_key = min(_cache, key=lambda item: _cache[item][0])
            _cache.pop(oldest_key, None)
        _cache[ip_address] = (time.monotonic() + CACHE_TTL_SECONDS, cache_payload)
    return result
