from __future__ import annotations

import base64
import re


def safe_b64decode(s: str) -> bytes:
    """Lenient base64 decode: handles missing padding, URL-safe chars, whitespace."""
    s = s.strip()
    # Try standard decode first
    for decode_fn in [_try_standard, _try_urlsafe, _try_add_padding, _try_urlsafe_add_padding]:
        result = decode_fn(s)
        if result is not None:
            return result
    raise ValueError(f"Failed to decode base64 string (len={len(s)})")


def _try_standard(s: str) -> bytes | None:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        return None


def _try_urlsafe(s: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(s)
    except Exception:
        return None


def _try_add_padding(s: str) -> bytes | None:
    try:
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _try_urlsafe_add_padding(s: str) -> bytes | None:
    try:
        padded = s + "=" * (4 - len(s) % 4) if len(s) % 4 else s
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def safe_b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_valid_uuid(s: str) -> bool:
    return bool(UUID_PATTERN.match(s))
