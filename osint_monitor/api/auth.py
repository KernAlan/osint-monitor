"""Simple API key authentication middleware for OSINT Monitor."""

from __future__ import annotations

import os

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader, APIKeyQuery

# Read key from environment; if unset, auth is disabled (dev mode).
_API_KEY = os.environ.get("OSINT_API_KEY", "")

_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)
_query_scheme = APIKeyQuery(name="api_key", auto_error=False)

# Paths that never require authentication.
_EXEMPT_PREFIXES = ("/docs", "/openapi.json", "/redoc", "/static/")
_EXEMPT_EXACT = {"/", "/docs", "/openapi.json"}


def _is_exempt(path: str) -> bool:
    """Return True if *path* should skip API-key checks."""
    if path in _EXEMPT_EXACT:
        return True
    for prefix in _EXEMPT_PREFIXES:
        if path.startswith(prefix):
            return True
    # All non-API paths (HTML pages) are exempt.
    if not path.startswith("/api/"):
        return True
    return False


async def require_api_key(
    request: Request,
    header_key: str | None = Security(_header_scheme),
    query_key: str | None = Security(_query_scheme),
) -> str | None:
    """FastAPI dependency that enforces API-key auth when OSINT_API_KEY is set.

    Usage::

        from osint_monitor.api.auth import require_api_key
        router = APIRouter(dependencies=[Depends(require_api_key)])

    Or attach globally via ``app.dependency_overrides`` / router dependencies.
    """
    # If no key configured, everything is allowed (development mode).
    if not _API_KEY:
        return None

    # Exempt certain paths from auth.
    if _is_exempt(request.url.path):
        return None

    provided = header_key or query_key
    if not provided or provided != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    return provided
