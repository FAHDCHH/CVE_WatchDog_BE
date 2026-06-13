"""
dashboard_api/security.py
Auth, security headers, and a lightweight rate limiter.

Notes:
- API-key check uses hmac.compare_digest (constant-time) to avoid timing oracles.
- The rate limiter is in-memory (per-process). It is correct for a single
  worker / demo. For multi-worker production, swap the store for Redis.
"""
from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque

from fastapi import Request, Security
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware

from dashboard_api.config import api_settings
from dashboard_api.errors import APIError

API_KEY_HEADER = "X-API-Key"
_api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)


def require_api_key(key: str | None = Security(_api_key_scheme)) -> None:
    """Reject any request without a valid data API key. Fails closed."""
    expected = api_settings.DASHBOARD_API_KEY
    if not expected:
        raise APIError(
            status_code=503,
            code="auth_not_configured",
            message="API key authentication is not configured on the server.",
        )
    if not key or not hmac.compare_digest(key, expected):
        raise APIError(
            status_code=401,
            code="unauthorized",
            message="A valid API key must be supplied in the X-API-Key header.",
        )


def require_admin_key(key: str | None = Security(_api_key_scheme)) -> None:
    """Stronger gate for future /admin/* routes."""
    expected = api_settings.ADMIN_API_KEY
    if not expected:
        raise APIError(
            status_code=503,
            code="admin_not_configured",
            message="Admin authentication is not configured on the server.",
        )
    if not key or not hmac.compare_digest(key, expected):
        raise APIError(
            status_code=401,
            code="unauthorized",
            message="A valid admin key must be supplied in the X-API-Key header.",
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach conservative security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response


class _SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, identity: str) -> bool:
        now = time.monotonic()
        bucket = self._hits[identity]
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


_limiter = _SlidingWindowLimiter(api_settings.RATE_LIMIT_PER_MINUTE)


def rate_limit(request: Request) -> None:
    identity = request.client.host if request.client else "anonymous"
    if not _limiter.allow(identity):
        raise APIError(
            status_code=429,
            code="rate_limited",
            message="Rate limit exceeded. Slow down and retry shortly.",
        )
