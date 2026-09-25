#!/usr/bin/env python3
"""
© NAuliajati - TangerangKota-CSIRT
HTTP client pool, unified API call helper, error handling, IP validation.
"""
from __future__ import annotations
import asyncio, ipaddress, json, logging, random, socket, time
from typing import Any, Dict, Optional, Annotated
import httpx
from pydantic import AfterValidator
from mcp_server import WAZUH_INDEXER_VERIFY_SSL
from mcp_server import HTTP_TIMEOUT, WAZUH_API_VERIFY_SSL, WAZUH_INDEXER_VERIFY_SSL, ARGUS_VERIFY_SSL
from mcp_server.core.exceptions import ThreatIntelError

logger = logging.getLogger("blue_team_mcp.http")

# How much of an upstream error body is preserved in a diagnostic message.
_MAX_ERROR_BODY = 500

# http2 requires the optional 'h2' package (httpx[http2] extra). Degrade to
# http/1.1 gracefully when it's absent (e.g. minimal test/CI environments), so
# the server never fails to boot just because the optional dependency is missing.
try:
    import h2  # noqa: F401
    _HTTP2 = True
except ImportError:
    _HTTP2 = False

# Private / reserved IP ranges threat intel tools are for public IP only
_PRIVATE_NETWORKS: list = []

# Shared HTTP clients by name, pooled per SSL trust domain.
_clients: dict[str, httpx.AsyncClient] = {}

_MSEARCH_FALLBACK_ERROR: dict = {"error": "_msearch_failed"}

# Client pool
async def _get_client(
    name: str,
    verify: bool = True,
    max_keepalive: int = 20,
    max_connections: int = 100,
) -> httpx.AsyncClient:
    """Return a pooled httpx.AsyncClient by name and TLS trust setting.
    ``verify`` is part of the cache key: an unverified pool must never be handed to
    a caller that asked for certificate verification (or vice versa), no matter which
    caller created the pool first.
    """
    key = f"{name}|verify={verify}"
    if key not in _clients or _clients[key].is_closed:
        _clients[key] = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=max_keepalive, max_connections=max_connections),
            verify=verify,
            http2=_HTTP2,
        )
    return _clients[key]

# Circuit breaker (per pool fail fast)
class CircuitOpenError(httpx.ConnectError):
    """Raised by ``_api_call`` when the per-pool circuit breaker is open.
    Subclasses ``httpx.ConnectError`` so existing ``except httpx.ConnectError``
    handlers (Wazuh auth/indexer) already catch it as "upstream unreachable".
    """


class CircuitBreaker:
    """Fail-fast breaker keyed per HTTP client pool.
    Counts consecutive upstream failures (5xx / transport errors). After
    ``failure_threshold`` it opens and refuses new requests for ``recovery_timeout`` seconds, then allows a single half-open trial.
    A 429 (throttle) and any 4xx (client error) are no failures, prove the dependency responded, so they never count against the breaker. 
    A 4xx during a half-open trial closes the breaker.
    All state transitions are synchronous (no ``await``), so they are atomic
    within a single-threaded event loop, no lock required.
    """
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0, name: str = "http") -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._failures = 0
        self._opened_at = 0.0
        self._half_open = False

    @property
    def open(self) -> bool:
        return self._failures >= self.failure_threshold

    @property
    def failures(self) -> int:
        return self._failures

    def before_call(self) -> bool:
        """Return True if a request may proceed; False to fail fast."""
        if not self.open:
            return True
        if time.monotonic() - self._opened_at < self.recovery_timeout:
            return False
        if self._half_open:
            return False  # a trial is already.
        self._half_open = True  # allow exactly one trial
        return True

    def on_success(self) -> None:
        was_open = self.open
        self._failures = 0
        self._opened_at = 0.0
        self._half_open = False
        if was_open:
            logger.info("circuit breaker '%s' CLOSED", self.name)

    def on_failure(self) -> None:
        was_open = self.open
        self._failures += 1
        self._opened_at = time.monotonic()
        self._half_open = False
        if self.open and not was_open:
            logger.warning(
                "circuit breaker '%s' OPEN after %d consecutive failures",
                self.name, self._failures,
            )

    def on_throttled(self) -> None:
        """429 - upstream throttling, not an outage. Don't count; re-arm the trial."""
        self._half_open = False
        self._opened_at = time.monotonic()

    def on_liveness(self) -> None:
        """4xx - a completed HTTP response proves the dependency is reachable."""
        if self._half_open:
            self._failures = 0
            self._opened_at = 0.0
            self._half_open = False
            logger.info("circuit breaker '%s' CLOSED (liveness proven by 4xx)", self.name)


# Per-upstream breakers, keyed by the resolved client_name (the URL host by default).
# The TLS trust setting is deliberately not part of this key: same upstream, same health.
_breakers: dict[str, CircuitBreaker] = {}


def _get_breaker(name: str) -> CircuitBreaker:
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(name=name)
    return _breakers[name]


# Longest Retry-After we will sit through. Anything longer is reported back to the
# caller instead of silently blocking the tool for minutes.
_RETRY_AFTER_MAX = 30.0


def _retry_after_seconds(header: str | None) -> float | None:
    """Parse a numeric ``Retry-After`` header into a delay worth waiting for.
    Returns None when the header is absent, non-numeric (the HTTP-date form is not
    parsed), negative, or longer than ``_RETRY_AFTER_MAX``. In all of those cases the
    caller fails fast rather than waiting and being throttled again. The raw header
    value still reaches the operator through the error message.
    """
    if not header:
        return None
    try:
        delay = float(header)
    except (TypeError, ValueError):
        return None
    if delay < 0 or delay > _RETRY_AFTER_MAX:
        return None
    return delay


# API call
async def _api_call(method: str, url: str, *, client_name: str | None = None, verify: bool = True,
                    max_retries: int = 1, backoff: float = 0.2, **kw) -> httpx.Response:
    """Unified async HTTP helper. Returns raw response caller calls .json() or .text.
    Retries (default once, configurable via max_retries) on 5xx server errors and
    network failures (jittered backoff). A 429 is retried only when the response
    carries a usable numeric Retry-After blind retries just burn more quota.
    A per-upstream circuit breaker fails fast (CircuitOpenError) when that upstream is
    repeatedly down, so outages don't pile up retries/timeouts across all tools.
    ``client_name`` selects the connection pool and the breaker. When omitted it is
    derived from the URL host, so unrelated upstreams never share one breaker: a
    flaky NVD must not fail-fast every Netra or GreyNoise call, and the error has to
    name the upstream that actually failed rather than a catch-all pool.
    """
    client_name = client_name or (httpx.URL(url).host or "http")
    client = await _get_client(client_name, verify=verify)
    breaker = _get_breaker(client_name)
    last_exc: Exception | None = None
    for attempt in range(1 + max_retries):
        if not breaker.before_call():
            raise CircuitOpenError(
                f"circuit breaker open for '{client_name}' "
                f"({breaker.failures} consecutive failures) try again shortly"
            )
        try:
            resp = await getattr(client, method.lower())(url, **kw)
            resp.raise_for_status()
            breaker.on_success()
            return resp
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 429:
                breaker.on_throttled()
                # Only retry when the server told us when to come back. A blind
                # fixed backoff retry of a 429 spends more of the same exhausted
                # quota and turns one throttle into two.
                delay = _retry_after_seconds(e.response.headers.get("Retry-After"))
                if delay is not None and attempt < max_retries:
                    await asyncio.sleep(delay)
                    last_exc = e
                    continue
                raise
            if 400 <= status < 500:
                breaker.on_liveness()
                raise
            breaker.on_failure()
            if attempt < max_retries:
                await asyncio.sleep(backoff + random.uniform(0, 0.2))
                last_exc = e
                continue
            raise
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
            breaker.on_failure()
            if attempt < max_retries:
                await asyncio.sleep(backoff + random.uniform(0, 0.2))
                last_exc = e
                continue
            raise
    raise last_exc  # type: ignore[misc]


# Error handling
# Statuses worth explaining in the error text itself rather than as a bare code.
_STATUS_HINTS: dict[int, str] = {
    400: "Bad request (400) - the API rejected the parameters. Try a smaller limit.",
    401: "Invalid or missing API key (401). Check your environment variables.",
    403: "Access forbidden (403). The API refused this credential. On RapidAPI this "
         "means the key is not subscribed to this API.",
    404: "No data found for this target (404).",
}


def _upstream_diagnostics(e: httpx.HTTPStatusError) -> dict[str, str]:
    """Preserve the identifying details of a failed upstream call.
    Provider gateways explain a rejection in the response body ("You are not
    subscribed to this API.") and in ``x-ratelimit-*`` / ``Retry-After`` headers.
    Discarding them, as this module used to, makes a 403 (wrong RapidAPI product)
    and a quota-exhausted 429 indistinguishable in the MCP output.
    """
    resp = e.response
    diag: dict[str, str] = {}
    try:
        diag["url"] = str(resp.url)
    except Exception:  # synthesised response without an attached request
        pass
    try:
        for name, value in resp.headers.items():
            low = name.lower()
            if low.startswith("x-ratelimit") or low in (
                "retry-after", "x-rapidapi-request-id", "x-request-id",
            ):
                diag[name] = value
    except Exception:  # headers unavailable - not fatal for error reporting
        pass
    try:
        body = (resp.text or "").strip()
    except Exception:  # streamed or already-consumed body
        body = ""
    if body:
        diag["body"] = body[:_MAX_ERROR_BODY]
    return diag


def _with_diagnostics(msg: str, e: httpx.HTTPStatusError) -> str:
    """Append upstream diagnostics to an error message, through the redaction boundary.
    The body can echo a queried victim email, so it passes through
    ``_redact_alert_data`` before it reaches the LLM. Attacker IPs stay visible.
    """
    diag = _upstream_diagnostics(e)
    if not diag:
        return msg
    from mcp_server.core.redact import _redact_alert_data  # lazy: keeps boot import order flat
    detail = " | ".join(f"{k}: {v}" for k, v in diag.items())
    try:
        return _redact_alert_data(f"{msg} | {detail}")
    except Exception:  # never let redaction turn a diagnosable failure into a crash
        logger.exception("redaction of upstream diagnostics failed")
        safe = " | ".join(f"{k}: {v}" for k, v in diag.items() if k != "body")
        return f"{msg} | {safe}" if safe else msg


def _failed_request(e: Exception) -> httpx.Request | None:
    """The request behind a failed call, when httpx recorded one on the exception.
    A hand-built ``httpx.TimeoutException`` (synthetic errors, tests) has none, and
    ``.request`` raises RuntimeError instead of returning None.
    """
    try:
        return e.request
    except (AttributeError, RuntimeError):
        return None


def _applied_timeout(request: httpx.Request | None) -> float | None:
    """The timeout httpx actually applied to this request, or None when unknown.
    httpx resolves the budget (per-call override, else the client default) onto
    ``request.extensions["timeout"]``. Reading it back keeps the message honest when a
    caller overrides the global default, as Netra slow fan-out query does.
    """
    budget = (getattr(request, "extensions", None) or {}).get("timeout")
    if isinstance(budget, dict):
        for key in ("read", "connect", "write", "pool"):
            value = budget.get(key)
            if isinstance(value, (int, float)):
                return float(value)
        return None
    return float(budget) if isinstance(budget, (int, float)) else None


def _rate_limit_text(resp: httpx.Response) -> str:
    """Separate a spent monthly pool from a transient burst limit.
    RapidAPI answers 429 to both, and the operator action differs: one means stop
    until next month, the other means wait a minute. The distinction is only in the
    headers, so it is read here rather than left to the LLM to infer.
    """
    retry_after = resp.headers.get("Retry-After")
    hint = f" Retry after {retry_after} seconds." if retry_after else ""
    remaining = resp.headers.get("x-ratelimit-requests-remaining")
    if remaining is None:
        return f"Rate limit reached (429).{hint}"
    try:
        left = int(remaining)
    except ValueError:
        return f"Rate limit reached (429).{hint}"
    if left <= 0:
        return (
            "Request quota exhausted (429) the provider reports no requests left in "
            f"this billing period, so a retry is unlikely to help.{hint}"
        )
    return f"Rate limit reached (429), {left} request(s) left in the quota.{hint}"


def _api_error_text(e: Exception, context: str = "") -> str:
    """Human-readable, actionable text for a failed upstream API call.
    Bulk tools call this to capture a per-item error string and keep going.
    Single-item tools call ``_handle_api_error``, which raises.
    """
    prefix = f"[{context}] " if context else ""
    if isinstance(e, CircuitOpenError):
        return f"{prefix}Error: {e}"
    if isinstance(e, httpx.HTTPStatusError):
        status = e.response.status_code
        if status == 429:
            msg = f"{prefix}Error: {_rate_limit_text(e.response)}"
        elif status in _STATUS_HINTS:
            msg = f"{prefix}Error: {_STATUS_HINTS[status]}"
        else:
            msg = f"{prefix}Error: API request failed with status {status}."
        return _with_diagnostics(msg, e)
    if isinstance(e, httpx.TimeoutException):
        request = _failed_request(e)
        host = getattr(getattr(request, "url", None), "host", None)
        budget = _applied_timeout(request)
        where = f" for {host}" if host else ""
        return (f"{prefix}Error: Request timed out after "
                f"{budget if budget is not None else HTTP_TIMEOUT}s{where}. Try again.")
    if isinstance(e, (RuntimeError, ValueError)):
        return f"{prefix}Error: {e}"
    return f"{prefix}Error: Unexpected error ({type(e).__name__})."


def _handle_api_error(e: Exception, context: str = "") -> None:
    """Format a failed upstream API call, log it, and raise ``ThreatIntelError``.
    Raising is the point. A tool that *returns* "Error: ..." as text is reported to
    the MCP client as ``isError: false``, so an LLM can read a hard failure as a
    finding. Letting the exception escape makes FastMCP return ``isError: true``
    carrying the same message. Bulk tools that need a per-item string must call
    ``_api_error_text`` instead.
    Raises:
        ThreatIntelError: always, chained to the original exception.
    """
    text = _api_error_text(e, context)
    if isinstance(e, httpx.HTTPStatusError):
        logger.warning("%s upstream %s %s - %s", context or "http",
                       e.response.status_code, e.response.url, text)
    elif isinstance(e, (httpx.TimeoutException, RuntimeError, CircuitOpenError)):
        logger.warning("%s upstream failure - %s", context or "http", text)
    else:
        logger.exception("Unexpected error in %s", context)
    raise ThreatIntelError(text) from e


# IP validation
def _is_private_or_reserved(ip: str) -> bool:
    """True if the IP is not globally routable: private, loopback, link-local,
    reserved, CGNAT (100.64.0.0/10), multicast, unspecified, or otherwise non-public.
    Gated on ``is_global`` because neither ``is_private`` nor ``is_reserved`` covers
    CGNAT 100.64/10 (RFC 6598). IPv4-mapped IPv6 (::ffff:a.b.c.d) is unmasked to its
    IPv4 form first, because ``::ffff:100.64.0.1`` is misreported as global otherwise."""
    try:
        ip = ipaddress.ip_address(ip)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return not ip.is_global


def _validate_public_ip(v: str) -> str:
    """Reject private/reserved IP for public threat intel tools (SSRF guard/prevention)."""
    if _is_private_or_reserved(v):
        raise ValueError(
            f"'{v}' is a private/reserved IP address."
            "This tool only accepts public IPs for threat intelligence lookup."
        )
    return v


ValidPublicIp = Annotated[str, AfterValidator(_validate_public_ip)]


def _resolve_host_ips(host: str) -> tuple[list[str], str | None]:
    """Resolve host to all A/AAAA records (both families). Returns (ips, error).
    Literal IPs are returned as-is (no DNS). IPv4 mapped IPv6 is normalized to IPv4."""
    try:
        ipaddress.ip_address(host)
        return [host], None
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return [], f"DNS resolution failed for {host}: {e}"
    ips: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
            mapped = getattr(ip, "ipv4_mapped", None)
            if mapped is not None:
                addr = str(mapped)
        except ValueError:
            continue
        if addr not in ips:
            ips.append(addr)
    return ips, None


def _domain_allowed(host: str, allowed_domains: list[str]) -> bool:
    """True if host equals or is a subdomain of any allowlisted domain."""
    host = host.lower().rstrip(".")
    for d in allowed_domains:
        d = d.strip().lower().rstrip(".")
        if not d:
            continue
        if host == d or host.endswith("." + d):
            return True
    return False


def _allowed_internal_domains() -> list[str]:
    """Read the ALLOWED_INTERNAL_DOMAINS allowlist from the Config singleton."""
    from mcp_server.core.config import config
    if config and getattr(config, "ssrf", None):
        return config.ssrf.allowed_internal_domains
    return []


def _host_pins(host: str, allowed_domains: list[str]) -> tuple[list[str], str | None]:
    """Resolve host once and return validated IPs for curl --resolve pinning.
    Allowlisted domains may resolve to internal IPs; any other host must resolve
    only to public IPs. Returns (pinned_ips, error)."""
    ips, err = _resolve_host_ips(host)
    if err:
        return [], err
    if not ips:
        return [], f"Host {host} did not resolve to any address."
    if _domain_allowed(host, allowed_domains):
        return ips, None
    bad = [ip for ip in ips if _is_private_or_reserved(ip)]
    if bad:
        return [], f"Host {host} resolves to non-public address {bad[0]} rejected (not in allowlist)."
    return ips, None


def _host_resolves_public(host: str) -> bool:
    """True if the host is a public IP or resolves ONLY to public IPs (both families)."""
    ips, err = _resolve_host_ips(host)
    if err or not ips:
        return False
    return all(not _is_private_or_reserved(ip) for ip in ips)
