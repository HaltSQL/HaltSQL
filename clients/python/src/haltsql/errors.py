"""Exceptions raised by the HaltSQL client.

Every failure mode is an exception; no code path in this package turns an error
into an "allowed" verdict. Callers that catch :class:`HaltSQLError` and carry on
must treat the query as denied.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .models import Verdict

__all__ = [
    "HaltSQLError",
    "HaltSQLUnavailable",
    "HaltSQLRequestError",
    "QueryDenied",
    "GuardError",
]


class HaltSQLError(Exception):
    """Base class for every error raised by this package."""


class HaltSQLUnavailable(HaltSQLError):
    """No trustworthy verdict could be obtained.

    Raised for connection errors, timeouts, 5xx responses (after retries), and
    malformed or inconsistent responses. The query must not run.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id


class HaltSQLRequestError(HaltSQLError):
    """The sidecar rejected the request itself (HTTP 4xx), e.g. a bad token.

    Not retried: repeating the same request cannot succeed. ``code`` is the
    server's ``error.code`` (``UNAUTHORIZED``, ``FORBIDDEN``,
    ``POLICY_NOT_FOUND``, ``BAD_REQUEST``, ``PAYLOAD_TOO_LARGE``, ...).
    """

    def __init__(
        self,
        message: str,
        *,
        status: int,
        code: str,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.request_id = request_id


class QueryDenied(HaltSQLError):
    """The policy denied the query. ``verdict`` carries the reasons and hints."""

    def __init__(self, verdict: "Verdict") -> None:
        self.verdict = verdict
        parts = [f"{r.code}: {r.hint or r.message}" for r in verdict.reasons]
        if not parts:
            # A shadow-mode verdict: allowed by the server, refused by the guard.
            parts = [
                f"{r.code}: {r.hint or r.message}"
                for r in getattr(verdict, "shadow_reasons", ())
            ]
            if parts:
                parts.insert(0, "the policy is in shadow mode and would deny this query")
        super().__init__("; ".join(parts or ["query denied"]))

    @property
    def reasons(self):  # type: ignore[no-untyped-def]
        """The reasons for the denial: ``verdict.reasons``, or for a shadow-mode
        verdict the guard refused to run, ``verdict.shadow_reasons``."""
        return self.verdict.reasons or getattr(self.verdict, "shadow_reasons", ())


class GuardError(HaltSQLError):
    """The guarded executor refused to run (unsupported connection, bad state)."""
