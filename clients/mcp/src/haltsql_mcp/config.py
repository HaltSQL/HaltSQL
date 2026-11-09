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

__all__ = ["ConfigError", "TokenEntry", "Settings", "load_config_file", "load_tokens_file", "hash_token"]

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


# Config file keys -> (Settings attribute, kind). Paths are resolved relative
# to the config file's directory, so one file works natively and in Docker.
_FILE_KEYS: Dict[str, Any] = {
    "database_url": ("database_url", "str"),
    "policy": ("local_policy_file", "path"),
    "policy_file": ("policy_file", "path"),
    "context": ("context", "obj"),
    "tokens_file": ("tokens_file", "path"),
    "row_cap": ("row_cap", "int"),
    "statement_timeout_ms": ("statement_timeout_ms", "int"),
    "set_config": ("set_config", "obj"),
    "transport": ("transport", "str"),
    "host": ("host", "str"),
    "port": ("port", "int"),
    "public_url": ("public_url", "str"),
    "haltsql_bin": ("haltsql_bin", "path"),
}
_SERVER_KEYS: Dict[str, Any] = {
    "url": ("haltsql_url", "str"),
    "token_file": ("haltsql_token", "secret_file"),
    "policy": ("haltsql_policy", "str"),
    "timeout": ("haltsql_timeout", "num"),
    "ca_file": ("haltsql_ca_file", "path"),
    "client_cert": ("haltsql_client_cert", "path"),
    "client_key": ("haltsql_client_key", "path"),
}


def _parse_config_text(path: str, raw: str) -> Any:
    if path.endswith(".json"):
        try:
            return json.loads(raw)
        except ValueError as e:
            raise ConfigError(f"config file {path} is not valid JSON: {e}") from None
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        try:
            return json.loads(raw)  # JSON is valid YAML
        except ValueError:
            raise ConfigError(
                f"config file {path} is YAML; install PyYAML (pip install 'haltsql-mcp[yaml]') "
                "or write it as JSON"
            ) from None
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ConfigError(f"config file {path} is not valid YAML: {e}") from None


def _convert(value: Any, kind: str, where: str, base: str) -> Any:
    if kind in ("str", "path", "secret_file"):
        if not isinstance(value, str) or not value:
            raise ConfigError(f"{where} must be a non-empty string")
        if kind == "str":
            return value
        p = os.path.join(base, os.path.expanduser(value))
        if kind == "path":
            return p
        try:
            with open(p, encoding="utf-8") as f:
                secret = f.read().strip()
        except OSError as e:
            raise ConfigError(f"cannot read {where} {p}: {e.strerror}") from None
        if not secret:
            raise ConfigError(f"{where} {p} is empty")
        return secret
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be an integer")
        return value
    if kind == "num":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where} must be a number")
        return float(value)
    if not isinstance(value, dict):  # obj
        raise ConfigError(f"{where} must be a mapping")
    return dict(value)


def load_config_file(path: str) -> Dict[str, Any]:
    """Read a haltsql-mcp config file and return ``{Settings attribute: value}``.

    Unknown keys are errors (a typo must not silently drop a guardrail).
    ``policy`` (local verification with the haltsql CLI) and ``server``
    (a central haltsql-server) are mutually exclusive. The sidecar token is
    read from ``server.token_file`` or ``HALTSQL_TOKEN``, never inline.
    """
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        raise ConfigError(f"cannot read config file {path}: {e.strerror}") from None
    data = _parse_config_text(path, raw)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must be a mapping")
    base = os.path.dirname(os.path.abspath(path))
    out: Dict[str, Any] = {}
    for key, value in data.items():
        if key == "server":
            if not isinstance(value, dict):
                raise ConfigError("server must be a mapping")
            for skey, svalue in value.items():
                if skey == "token":
                    raise ConfigError(
                        "server.token is not allowed in the config file; use server.token_file "
                        "or the HALTSQL_TOKEN environment variable"
                    )
                if skey not in _SERVER_KEYS:
                    raise ConfigError(
                        f"unknown key server.{skey} in {path} (expected one of {', '.join(sorted(_SERVER_KEYS))})"
                    )
                attr, kind = _SERVER_KEYS[skey]
                out[attr] = _convert(svalue, kind, f"server.{skey}", base)
            continue
        if key not in _FILE_KEYS:
            raise ConfigError(
                f"unknown key {key!r} in {path} (expected one of {', '.join(sorted([*_FILE_KEYS, 'server']))})"
            )
        attr, kind = _FILE_KEYS[key]
        out[attr] = _convert(value, kind, key, base)
    if "local_policy_file" in out and "server" in data:
        raise ConfigError("set either policy (verify locally) or server (central haltsql-server), not both")
    if "set_config" in out:
        out["set_config"] = {str(k): v for k, v in out["set_config"].items()}
    return out


@dataclass
class Settings:
    """Everything haltsql-mcp needs. See ``docs/mcp.md`` for each variable."""

    # Verification: sidecar (default) or local CLI.
    haltsql_url: str = "http://127.0.0.1:8080"
    haltsql_token: Optional[str] = field(default=None, repr=False)
    haltsql_policy: Optional[str] = None
    haltsql_timeout: float = 2.0
    haltsql_ca_file: Optional[str] = None
    """CA bundle for an https sidecar with a private CA (default: system CAs)."""
    haltsql_client_cert: Optional[str] = None
    """Client certificate (PEM) for mutual TLS to the sidecar."""
    haltsql_client_key: Optional[str] = field(default=None, repr=False)
    """Private key for ``haltsql_client_cert`` when it is a separate file."""
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
        """Defaults overridden by environment variables."""
        s = cls()
        s.apply_env(os.environ if env is None else env)
        return s

    @classmethod
    def from_sources(
        cls, env: Optional[Mapping[str, str]] = None, config_file: Optional[str] = None
    ) -> "Settings":
        """Defaults, then the config file (if any), then environment variables."""
        e = os.environ if env is None else env
        s = cls()
        path = config_file or e.get("HALTSQL_MCP_CONFIG") or None
        if path:
            s.apply_file(path)
        s.apply_env(e)
        return s

    def apply_env(self, e: Mapping[str, str]) -> None:
        """Override settings with every environment variable that is set (non-empty)."""
        def get(name: str) -> Optional[str]:
            v = e.get(name)
            return v if v else None

        self.haltsql_url = get("HALTSQL_URL") or self.haltsql_url
        self.haltsql_token = get("HALTSQL_TOKEN") or self.haltsql_token
        self.haltsql_policy = get("HALTSQL_POLICY") or self.haltsql_policy
        if get("HALTSQL_TIMEOUT"):
            try:
                self.haltsql_timeout = float(e["HALTSQL_TIMEOUT"])
            except ValueError:
                raise ConfigError("HALTSQL_TIMEOUT must be a number") from None
        self.haltsql_ca_file = get("HALTSQL_CA_FILE") or self.haltsql_ca_file
        self.haltsql_client_cert = get("HALTSQL_CLIENT_CERT") or self.haltsql_client_cert
        self.haltsql_client_key = get("HALTSQL_CLIENT_KEY") or self.haltsql_client_key
        self.local_policy_file = get("HALTSQL_MCP_LOCAL_POLICY") or self.local_policy_file
        self.haltsql_bin = get("HALTSQL_BIN") or self.haltsql_bin
        self.database_url = get("HALTSQL_MCP_DATABASE_URL") or get("DATABASE_URL") or self.database_url
        self.row_cap = _env_int(e, "HALTSQL_MCP_ROW_CAP", self.row_cap)
        self.statement_timeout_ms = _env_int(e, "HALTSQL_MCP_STATEMENT_TIMEOUT_MS", self.statement_timeout_ms)
        if get("HALTSQL_MCP_SET_CONFIG"):
            self.set_config = {
                str(k): v for k, v in _json_obj(e["HALTSQL_MCP_SET_CONFIG"], "HALTSQL_MCP_SET_CONFIG").items()
            }
        self.policy_file = get("HALTSQL_MCP_POLICY_FILE") or self.policy_file
        if get("HALTSQL_MCP_CONTEXT"):
            self.context = _json_obj(e["HALTSQL_MCP_CONTEXT"], "HALTSQL_MCP_CONTEXT")
        self.tokens_file = get("HALTSQL_MCP_TOKENS_FILE") or self.tokens_file
        self.transport = get("HALTSQL_MCP_TRANSPORT") or self.transport
        self.host = get("HALTSQL_MCP_HOST") or self.host
        self.port = _env_int(e, "HALTSQL_MCP_PORT", self.port)
        self.public_url = get("HALTSQL_MCP_PUBLIC_URL") or self.public_url

    def apply_file(self, path: str) -> None:
        """Load a config file (YAML or JSON). See ``load_config_file``."""
        for attr, value in load_config_file(path).items():
            setattr(self, attr, value)

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
        if self.haltsql_client_key and not self.haltsql_client_cert:
            raise ConfigError("HALTSQL_CLIENT_KEY needs HALTSQL_CLIENT_CERT")
        for f in (
            self.local_policy_file,
            self.policy_file,
            self.tokens_file,
            self.haltsql_ca_file,
            self.haltsql_client_cert,
            self.haltsql_client_key,
        ):
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
