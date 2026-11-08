"""Configuration for haltsql-mcp: environment variables, overridable by flags.

Tenant context is configuration, never a tool argument:

* stdio: one static context for the whole process (``HALTSQL_MCP_CONTEXT`` or
  ``--context-file``), set by whoever launches the server for one user.
* streamable HTTP: each bearer token in the tokens file maps to its own
  context; the authenticated MCP session decides the tenant.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from haltsql import validate_context

__all__ = ["ConfigError", "TokenEntry", "Settings", "load_tokens_file", "hash_token"]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SETTING_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_.]*$")
MAX_ROW_CAP = 10_000


class ConfigError(ValueError):
    """Invalid configuration; the server refuses to start."""


def hash_token(token: str) -> str:
    """Lower-case hex SHA-256 of a bearer token (what the tokens file stores)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TokenEntry:
    """One accepted bearer token, stored only as its SHA-256."""

    name: str
    token_sha256: str
    context: Mapping[str, Any]

    def matches(self, token_hash: str) -> bool:
        return hmac.compare_digest(self.token_sha256.encode(), token_hash.encode())


def load_tokens_file(path: str) -> List[TokenEntry]:
    """Load ``{"tokens": [{"name", "token_sha256", "context"}]}`` (JSON)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read tokens file {path}: {e.strerror}") from None
    except ValueError as e:
        raise ConfigError(f"tokens file {path} is not valid JSON: {e}") from None
    if not isinstance(data, dict) or set(data) != {"tokens"} or not isinstance(data["tokens"], list):
        raise ConfigError('tokens file must be {"tokens": [...]} with no other keys')
    entries: List[TokenEntry] = []
    names = set()
    hashes = set()
    for i, t in enumerate(data["tokens"]):
        where = f"tokens[{i}]"
        if not isinstance(t, dict) or set(t) - {"name", "token_sha256", "context"}:
            raise ConfigError(f"{where}: expected keys name, token_sha256, context")
        name = t.get("name")
        h = t.get("token_sha256")
        if not isinstance(name, str) or not name:
            raise ConfigError(f"{where}.name must be a non-empty string")
        if not isinstance(h, str) or not _HEX64.match(h):
            raise ConfigError(f"{where}.token_sha256 must be 64 lower-case hex characters")
        if name in names or h in hashes:
            raise ConfigError(f"{where}: duplicate name or token")
        try:
            ctx = validate_context(t.get("context") or {})
        except ValueError as e:
            raise ConfigError(f"{where}.context: {e}") from None
        names.add(name)
        hashes.add(h)
        entries.append(TokenEntry(name=name, token_sha256=h, context=ctx))
    if not entries:
        raise ConfigError("tokens file has no tokens")
    return entries


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None


def _json_obj(raw: str, what: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise ConfigError(f"{what} is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{what} must be a JSON object")
    return data


@dataclass
class Settings:
    """Everything haltsql-mcp needs. See ``docs/mcp.md`` for each variable."""

    # Verification: sidecar (default) or local CLI.
    haltsql_url: str = "http://127.0.0.1:8080"
    haltsql_token: Optional[str] = field(default=None, repr=False)
    haltsql_policy: Optional[str] = None
    haltsql_timeout: float = 2.0
    local_policy_file: Optional[str] = None
    haltsql_bin: Optional[str] = None
    # Execution.
    database_url: Optional[str] = field(default=None, repr=False)
    row_cap: int = 200
    statement_timeout_ms: int = 5000
    set_config: Dict[str, str] = field(default_factory=dict)
    """Postgres setting -> context key, applied with set_config(..., true) (for RLS)."""
    # Policy description.
    policy_file: Optional[str] = None
    # Tenant context.
    context: Dict[str, Any] = field(default_factory=dict)
    tokens_file: Optional[str] = None
    insecure_static_context: bool = False
    # Transport.
    transport: str = "stdio"
    host: str = "127.0.0.1"
    port: int = 8765
    public_url: Optional[str] = None

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        e = os.environ if env is None else env
        s = cls()
        s.haltsql_url = e.get("HALTSQL_URL") or s.haltsql_url
        s.haltsql_token = e.get("HALTSQL_TOKEN") or None
        s.haltsql_policy = e.get("HALTSQL_POLICY") or None
        if e.get("HALTSQL_TIMEOUT"):
            try:
                s.haltsql_timeout = float(e["HALTSQL_TIMEOUT"])
            except ValueError:
                raise ConfigError("HALTSQL_TIMEOUT must be a number") from None
        s.local_policy_file = e.get("HALTSQL_MCP_LOCAL_POLICY") or None
        s.haltsql_bin = e.get("HALTSQL_BIN") or None
        s.database_url = e.get("HALTSQL_MCP_DATABASE_URL") or e.get("DATABASE_URL") or None
        s.row_cap = _env_int(e, "HALTSQL_MCP_ROW_CAP", s.row_cap)
        s.statement_timeout_ms = _env_int(e, "HALTSQL_MCP_STATEMENT_TIMEOUT_MS", s.statement_timeout_ms)
        if e.get("HALTSQL_MCP_SET_CONFIG"):
            s.set_config = {str(k): v for k, v in _json_obj(e["HALTSQL_MCP_SET_CONFIG"], "HALTSQL_MCP_SET_CONFIG").items()}
        s.policy_file = e.get("HALTSQL_MCP_POLICY_FILE") or None
        if e.get("HALTSQL_MCP_CONTEXT"):
            s.context = _json_obj(e["HALTSQL_MCP_CONTEXT"], "HALTSQL_MCP_CONTEXT")
        s.tokens_file = e.get("HALTSQL_MCP_TOKENS_FILE") or None
        s.transport = e.get("HALTSQL_MCP_TRANSPORT") or s.transport
        s.host = e.get("HALTSQL_MCP_HOST") or s.host
        s.port = _env_int(e, "HALTSQL_MCP_PORT", s.port)
        s.public_url = e.get("HALTSQL_MCP_PUBLIC_URL") or None
        return s

    def load_context_file(self, path: str) -> None:
        try:
            with open(path, encoding="utf-8") as f:
                self.context = _json_obj(f.read(), f"context file {path}")
        except OSError as e:
            raise ConfigError(f"cannot read context file {path}: {e.strerror}") from None

    def validate(self) -> None:
        """Check every setting; raise :class:`ConfigError` on the first problem."""
        if self.transport not in ("stdio", "http"):
            raise ConfigError("transport must be 'stdio' or 'http'")
        if not (1 <= self.row_cap <= MAX_ROW_CAP):
            raise ConfigError(f"row cap must be between 1 and {MAX_ROW_CAP}")
        if not (1 <= self.statement_timeout_ms <= 600_000):
            raise ConfigError("statement timeout must be between 1 and 600000 ms")
        if self.haltsql_timeout <= 0:
            raise ConfigError("HALTSQL_TIMEOUT must be > 0")
        for setting, key in self.set_config.items():
            if not _SETTING_RE.match(setting):
                raise ConfigError(
                    f"set_config setting {setting!r} must be a custom setting like app.tenant_id"
                )
            if not isinstance(key, str) or not key:
                raise ConfigError(f"set_config[{setting!r}] must name a context key")
        try:
            self.context = validate_context(self.context)
        except ValueError as e:
            raise ConfigError(f"context: {e}") from None
        for f in (self.local_policy_file, self.policy_file, self.tokens_file):
            if f is not None and not os.path.isfile(f):
                raise ConfigError(f"file not found: {f}")
        if self.transport == "http":
            if self.tokens_file is None and not self.insecure_static_context:
                raise ConfigError(
                    "HTTP transport needs a tokens file (HALTSQL_MCP_TOKENS_FILE / --tokens-file) so "
                    "each client is authenticated and mapped to its tenant context; "
                    "--insecure-static-context exists for local development only"
                )
            if self.insecure_static_context and self.tokens_file is None:
                try:
                    loopback = ipaddress.ip_address(self.host).is_loopback
                except ValueError:
                    loopback = self.host == "localhost"
                if not loopback:
                    raise ConfigError("--insecure-static-context is only allowed on a loopback host")
            if not (1 <= self.port <= 65535):
                raise ConfigError("port must be between 1 and 65535")
        if self.tokens_file is not None and self.transport == "stdio":
            raise ConfigError("a tokens file only applies to the HTTP transport")

    @property
    def describe_file(self) -> Optional[str]:
        """The policy document used for describe_policy / list_tables."""
        return self.policy_file or self.local_policy_file
