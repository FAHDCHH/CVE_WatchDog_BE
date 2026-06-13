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
def sanitize_metadata(self, value: dict) -> dict:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if self._is_sensitive_key(str(key)) else self.sanitize_metadata(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.sanitize_metadata(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.sanitize_metadata(item) for item in value)
        return value