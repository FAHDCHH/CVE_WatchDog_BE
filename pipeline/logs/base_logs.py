"""
Shared logger base classes and security helpers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from core.config import Settings
from core.exceptions.exceptions import InvalidLogEventError


class BaseLogger(ABC):
    allowed_levels: tuple[str, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    allowed_event_types: tuple[str, ...] = ()
    sensitive_keys: set[str] = Settings.SENSITIVE_KEYS

    def __init__(self, db: Session, commit_immediately: bool = True):
        self.db = db
        self.commit_immediately = commit_immediately

    @abstractmethod
    def log(self, **fields: Any):
        pass

    @abstractmethod
    def _write_to_database(self, **fields: Any):
        pass

    def _validate_event(
        self,
        *,
        level: str,
        source: str,
        event_type: str,
        message: str,
    ) -> None:
        if level not in self.allowed_levels:
            raise InvalidLogEventError(f"Invalid log level: {level}")
        if source not in self.allowed_sources:
            raise InvalidLogEventError(f"Invalid log source: {source}")
        if event_type not in self.allowed_event_types:
            raise InvalidLogEventError(f"Invalid log event_type: {event_type}")
        if not message:
            raise InvalidLogEventError("Log message cannot be empty")

    def _sanitize_url(self, url: str | None) -> str | None:
        if url is None:
            return None
        try:
            parts = urlsplit(url)
            clean_params = [
                (k, v)
                for k, v in parse_qsl(parts.query)
                if k.lower() not in self.sensitive_keys
            ]
            sanitized = parts._replace(query=urlencode(clean_params))
            return urlunsplit(sanitized)
        except Exception:
            return None
