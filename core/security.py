"""
core/security.py
All security policy enforcement.
"""
from urllib.parse import urlparse
from core.config import Settings


def is_allowed_url(url: str) -> bool:
    """Check URL netloc against the allowlist. SSRF prevention."""
    netloc = urlparse(url).netloc
    return netloc in Settings.ALLOWED_HOSTS


def sanitize_headers(headers: dict) -> dict:
    """Redact sensitive header values before logging."""
    return {
        k: "[REDACTED]" if k.lower() in Settings.SENSITIVE_KEYS else v
        for k, v in headers.items()
    }
