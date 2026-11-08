"""The haltsql-mcp server: MCP tools over stdio or streamable HTTP.

Works with the official ``mcp`` SDK 2.x (``MCPServer``) and 1.x (``FastMCP``).
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from haltsql import AsyncHaltSQLClient, AsyncLocalVerifier, RetryPolicy

from .config import ConfigError, Settings, TokenEntry, hash_token, load_tokens_file
from .core import HaltSQLTools, ToolFailure

__all__ = ["StaticTokenVerifier", "build_tools", "build_server", "main", "INSTRUCTIONS"]

log = logging.getLogger("haltsql_mcp")

INSTRUCTIONS = (
    "SQL access to a PostgreSQL database guarded by HaltSQL. Call describe_policy or "
    "list_tables first, write one SELECT with a LIMIT, and run it with query. If the query "
    "is denied, read the reason codes and hints (or call explain_denial), fix the SQL, and "
    "retry. The tenant is fixed by the server; never try to choose or change it."
)


def _sdk() -> Tuple[Any, Any, int]:
    """(ServerClass, ToolError, major_version) for the installed mcp SDK."""
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError

        return MCPServer, ToolError, 2
    except ImportError:  # pragma: no cover - mcp 1.x
        from mcp.server.fastmcp import FastMCP  # type: ignore[attr-defined, import-not-found, no-redef]
        from mcp.server.fastmcp.exceptions import ToolError  # type: ignore[import-not-found, no-redef]

        return FastMCP, ToolError, 1


def _get_access_token() -> Any:
    from mcp.server.auth.middleware.auth_context import get_access_token

    return get_access_token()


class StaticTokenVerifier:
    """MCP ``TokenVerifier`` for pre-shared bearer tokens stored as SHA-256.

    Every entry is compared in constant time; the raw token is never stored
    or logged. The returned ``AccessToken`` carries the entry name as
    ``client_id``, which the context provider maps to that client's context.
    """

    def __init__(self, entries: List[TokenEntry]) -> None:
        self._entries = list(entries)
        self.by_name: Dict[str, TokenEntry] = {e.name: e for e in entries}

    async def verify_token(self, token: str) -> Any:
        from mcp.server.auth.provider import AccessToken

        if not isinstance(token, str) or not token:
            return None
        h = hash_token(token)
        match: Optional[TokenEntry] = None
        for e in self._entries:  # no early exit: constant work per entry
            if e.matches(h):
                match = e
        if match is None:
            return None
        # Store the hash, not the token, in the request context.
        return AccessToken(token=f"sha256:{h}", client_id=match.name, scopes=[])


def session_context_provider(verifier: StaticTokenVerifier) -> Callable[[], Mapping[str, Any]]:
    """Context from the authenticated MCP session (HTTP transport)."""

    def provider() -> Mapping[str, Any]:
        tok = _get_access_token()
        if tok is None:
            raise PermissionError("not authenticated")
        entry = verifier.by_name.get(getattr(tok, "client_id", None) or "")
        if entry is None:
            raise PermissionError("unknown client")
        return dict(entry.context)

    return provider


def static_context_provider(context: Mapping[str, Any]) -> Callable[[], Mapping[str, Any]]:
    """One fixed context from server configuration (stdio transport)."""
    frozen = dict(context)
    return lambda: dict(frozen)


def build_tools(
    settings: Settings,
    context_provider: Callable[[], Mapping[str, Any]],
    *,
    connect: Optional[Callable[[], Any]] = None,
) -> HaltSQLTools:
    """Wire verifier, database, and limits from ``settings``."""
    lister = None
    if settings.local_policy_file:
        verifier: Any = AsyncLocalVerifier(settings.local_policy_file, binary=settings.haltsql_bin)
    else:
        client = AsyncHaltSQLClient(
            settings.haltsql_url,
            settings.haltsql_token,
            timeout=settings.haltsql_timeout,
            policy=settings.haltsql_policy,
            retry=RetryPolicy(),
            verify=settings.haltsql_ca_file or True,
            cert=(
                (settings.haltsql_client_cert, settings.haltsql_client_key)
                if settings.haltsql_client_cert and settings.haltsql_client_key
                else settings.haltsql_client_cert
            ),
        )
        verifier = client
        lister = client.policies
    if connect is None and settings.database_url:
        dsn = settings.database_url

        async def connect() -> Any:  # type: ignore[no-redef]
            import psycopg

            return await psycopg.AsyncConnection.connect(dsn, autocommit=True)

    return HaltSQLTools(
        verifier,
        context_provider,
        connect=connect,
        row_cap=settings.row_cap,
        statement_timeout_ms=settings.statement_timeout_ms,
        set_config=settings.set_config,
        policy_file=settings.describe_file,
        policies_lister=lister,
        haltsql_bin=settings.haltsql_bin,
    )


def build_server(
    tools: HaltSQLTools,
    *,
    token_verifier: Optional[StaticTokenVerifier] = None,
    public_url: str = "http://127.0.0.1:8765",
    name: str = "haltsql-mcp",
) -> Any:
    """Create the MCP server object and register the four tools."""
    Server, ToolError, major = _sdk()
    kwargs: Dict[str, Any] = {"instructions": INSTRUCTIONS}
    if token_verifier is not None:
        from mcp.server.auth.settings import AuthSettings

        kwargs["token_verifier"] = token_verifier
        kwargs["auth"] = AuthSettings.model_validate({
            "issuer_url": public_url,
            "resource_server_url": public_url.rstrip("/") + "/mcp",
            "validate_token_resource": False,
        })
    server = Server(name, **kwargs)

    try:
        from mcp.types import ToolAnnotations

        ro = ToolAnnotations.model_validate({"readOnlyHint": True, "openWorldHint": False})
    except Exception:  # noqa: BLE001  # pragma: no cover
        ro = None

    def tool(fn_name: str, description: str) -> Callable[[Any], Any]:
        if ro is not None:
            return server.tool(name=fn_name, description=description, annotations=ro)
        return server.tool(name=fn_name, description=description)  # pragma: no cover

    async def _call(coro: Any) -> Dict[str, Any]:
        try:
            return await coro
        except ToolFailure as e:
            raise ToolError(str(e)) from None

    @tool(
        "query",
        "Run one read-only SQL query on PostgreSQL. HaltSQL verifies it against the policy for "
        "your tenant first; if allowed, the exact SQL runs with server-bound $n parameters and "
        "rows are returned (capped). If denied, the result has allowed=false and reasons with "
        "hints; fix the SQL and retry.",
    )
    async def query(sql: str) -> Dict[str, Any]:
        return await _call(tools.query(sql))

    @tool(
        "explain_denial",
        "Check SQL against the HaltSQL policy without running it and return every reason code, "
        "message, and hint, plus the tables and columns it touches.",
    )
    async def explain_denial(sql: str) -> Dict[str, Any]:
        return await _call(tools.explain_denial(sql))

    @tool("list_tables", "List the tables and columns the policy lets you read, and which are tenant-scoped.")
    async def list_tables() -> Dict[str, Any]:
        return await _call(tools.list_tables())

    @tool(
        "describe_policy",
        "Describe the active HaltSQL policy: name, version, mode, allowed statements, LIMIT "
        "rule, tenancy mode, tables, and functions.",
    )
    async def describe_policy() -> Dict[str, Any]:
        return await _call(tools.describe_policy())

    server._haltsql_sdk_major = major  # noqa: SLF001 - informational
    return server


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="haltsql-mcp",
        description="MCP server that runs SQL on PostgreSQL only after HaltSQL allows it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
EXAMPLES
  # stdio (one user per process); tenant fixed by the launcher:
  HALTSQL_URL=http://127.0.0.1:8080 HALTSQL_TOKEN=... \\
  HALTSQL_MCP_DATABASE_URL=postgresql://agent_ro@db/app \\
  HALTSQL_MCP_CONTEXT='{"tenant_id":"acme"}' haltsql-mcp

  # streamable HTTP; each bearer token maps to a tenant context:
  haltsql-mcp --transport http --port 8765 --tokens-file tokens.json \\
    --database-url postgresql://agent_ro@db/app --policy-file policy.yaml

  # without a sidecar, verifying with the local haltsql CLI:
  haltsql-mcp --local-policy policy.yaml --context-file ctx.json --database-url ...

  # everything in one file (YAML or JSON); env and flags override it:
  haltsql-mcp --config haltsql-mcp.yaml

  # drop-in for @modelcontextprotocol/server-postgres (DSN as the last argument):
  haltsql-mcp --local-policy policy.yaml postgresql://agent_ro@localhost/app

Exit status: 0 on shutdown, 2 on a configuration error.
See docs/mcp.md for every environment variable.""",
    )
    p.add_argument("--config", help="Config file (YAML or JSON); environment variables and flags override it. "
                                    "Also HALTSQL_MCP_CONFIG.")
    p.add_argument("--transport", choices=["stdio", "http"])
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--public-url", help="External URL of this server (OAuth resource metadata).")
    p.add_argument("--haltsql-url")
    p.add_argument("--policy", dest="haltsql_policy", help="Policy name to request from the sidecar.")
    p.add_argument("--local-policy", help="Verify with the local haltsql CLI and this policy file.")
    p.add_argument("--policy-file", help="Policy document for describe_policy/list_tables.")
    p.add_argument("--database-url")
    p.add_argument("dsn", nargs="?", metavar="DATABASE_URL",
                   help="libpq DSN, as a positional argument like @modelcontextprotocol/server-postgres "
                        "takes it (same as --database-url).")
    p.add_argument("--row-cap", type=int)
    p.add_argument("--statement-timeout-ms", type=int)
    p.add_argument("--context-file", help="JSON context for stdio (overrides HALTSQL_MCP_CONTEXT).")
    p.add_argument("--tokens-file", help="JSON tokens file for the HTTP transport.")
    p.add_argument("--insecure-static-context", action="store_true",
                   help="HTTP without authentication, using the static context (loopback only; dev).")
    return p


def settings_from_args(argv: Optional[List[str]] = None, env: Optional[Mapping[str, str]] = None) -> Settings:
    args = _parser().parse_args(argv)
    s = Settings.from_sources(env, config_file=args.config)
    for attr in ("transport", "host", "port", "public_url", "haltsql_url", "haltsql_policy",
                 "local_policy", "policy_file", "database_url", "row_cap",
                 "statement_timeout_ms", "tokens_file"):
        val = getattr(args, attr)
        if val is not None:
            setattr(s, "local_policy_file" if attr == "local_policy" else attr, val)
    if args.dsn is not None:
        if args.database_url is not None and args.database_url != args.dsn:
            raise ConfigError("give the database URL once: positionally or with --database-url, not both")
        s.database_url = args.dsn
    if args.context_file:
        s.load_context_file(args.context_file)
    s.insecure_static_context = bool(args.insecure_static_context)
    s.validate()
    return s


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    try:
        settings = settings_from_args(argv)
        token_verifier: Optional[StaticTokenVerifier] = None
        if settings.transport == "http" and settings.tokens_file:
            token_verifier = StaticTokenVerifier(load_tokens_file(settings.tokens_file))
            provider = session_context_provider(token_verifier)
        else:
            provider = static_context_provider(settings.context)
        tools = build_tools(settings, provider)
    except ConfigError as e:
        print(f"haltsql-mcp: {e}", file=sys.stderr)
        return 2
    public_url = settings.public_url or f"http://{settings.host}:{settings.port}"
    server = build_server(tools, token_verifier=token_verifier, public_url=public_url)
    if settings.transport == "stdio":
        server.run("stdio")
    elif getattr(server, "_haltsql_sdk_major", 2) >= 2:
        server.run("streamable-http", host=settings.host, port=settings.port)
    else:  # pragma: no cover - mcp 1.x
        server.settings.host = settings.host
        server.settings.port = settings.port
        server.run("streamable-http")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
