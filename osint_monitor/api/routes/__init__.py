"""API route helpers."""

from datetime import datetime


def utc_iso(dt: datetime | None) -> str | None:
    """Format a naive UTC datetime as an ISO 8601 string with Z suffix.

    The database stores UTC times as naive datetimes. Without the Z suffix,
    browsers interpret ISO strings as local time, causing a timezone offset
    error. This function appends Z so the browser correctly converts to the
    user's local timezone.
    """
    if dt is None:
        return None
    return dt.isoformat() + "Z"
