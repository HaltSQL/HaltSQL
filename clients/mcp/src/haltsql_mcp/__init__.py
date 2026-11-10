"""haltsql-mcp: an MCP server that runs SQL only after HaltSQL allows it."""

from .config import ConfigError, Settings, TokenEntry, hash_token, load_tokens_file
from .core import HaltSQLTools, ToolFailure, jsonable, summarize_policy
from .server import StaticTokenVerifier, build_server, build_tools, main

__version__ = "0.0.1"

__all__ = [
    "__version__",
    "Settings",
    "ConfigError",
    "TokenEntry",
    "hash_token",
    "load_tokens_file",
    "HaltSQLTools",
    "ToolFailure",
    "jsonable",
    "summarize_policy",
    "StaticTokenVerifier",
    "build_server",
    "build_tools",
    "main",
]
