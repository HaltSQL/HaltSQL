"""HaltSQL Python client: verify LLM-generated PostgreSQL against a policy.

Quick start::

    from haltsql import HaltSQLClient, guard

    hs = HaltSQLClient.from_env()          # HALTSQL_URL, HALTSQL_TOKEN
    result = guard.execute(conn, sql, {"tenant_id": session.tenant_id}, verifier=hs)

Every failure raises; nothing is ever treated as allowed. See
``docs/sdk-python.md``.
"""

from . import agent_core, guard
from ._version import __version__
from .client import AsyncHaltSQLClient, HaltSQLClient, RetryPolicy
from .errors import (
    GuardError,
    HaltSQLError,
    HaltSQLRequestError,
    HaltSQLUnavailable,
    QueryDenied,
)
from .guard import Guard, GuardedResult
from .local import AsyncLocalVerifier, LocalVerifier
from .models import BindParam, PolicyInfo, PolicyRef, Reason, Verdict, sql_sha256, validate_context

__all__ = [
    "__version__",
    "HaltSQLClient",
    "AsyncHaltSQLClient",
    "RetryPolicy",
    "LocalVerifier",
    "AsyncLocalVerifier",
    "Verdict",
    "Reason",
    "BindParam",
    "PolicyRef",
    "PolicyInfo",
    "sql_sha256",
    "validate_context",
    "agent_core",
    "guard",
    "Guard",
    "GuardedResult",
    "HaltSQLError",
    "HaltSQLUnavailable",
    "HaltSQLRequestError",
    "QueryDenied",
    "GuardError",
]
