"""Re-export of the framework-free agent core from :mod:`haltsql.agent_core`."""

from __future__ import annotations

from haltsql.agent_core import (
    DEFAULT_CONTEXT_KEY,
    DEFAULT_DESCRIPTION,
    QUERY_ARG,
    TOOL_NAME,
    ContextUnavailable,
    HaltSQLToolRunner,
    SettingsSource,
    check_only,
    context_from_app,
    result_to_text,
)

__all__ = [
    "TOOL_NAME",
    "QUERY_ARG",
    "DEFAULT_CONTEXT_KEY",
    "DEFAULT_DESCRIPTION",
    "ContextUnavailable",
    "HaltSQLToolRunner",
    "SettingsSource",
    "check_only",
    "context_from_app",
    "result_to_text",
]
