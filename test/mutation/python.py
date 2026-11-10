"""Mutants of the Python guard, verdict model, HTTP client and MCP tool core.

Run from the repository root with the built binaries present (dune build) and the lab
Postgres on 127.0.0.1:5417; PYTHON selects the interpreter (default: python3).
"""

import os

G = "clients/python/src/haltsql/guard.py"
M = "clients/python/src/haltsql/models.py"
C = "clients/python/src/haltsql/client.py"
K = "clients/mcp/src/haltsql_mcp/core.py"
PY = os.environ.get("PYTHON", "python3")
BUILD = "true"
TEST = (
    "PYTHONPATH=clients/python/src:clients/mcp/src " + PY + " -m pytest -q -x -p no:cacheprovider clients/python/tests && "
    "PYTHONPATH=clients/python/src:clients/mcp/src " + PY + " -m pytest -q -x -p no:cacheprovider clients/mcp/tests"
)

EQUIVALENT = {}

MUTANTS = [
    ('guard: verdict for another SQL string accepted', 'clients/python/src/haltsql/guard.py', '    if not verdict.matches_sql(sql):\n        raise HaltSQLUnavailable("verdict is for a different', '    if False:\n        raise HaltSQLUnavailable("verdict is for a different'),
    ('guard: denied verdict not raised', 'clients/python/src/haltsql/guard.py', '    verdict.raise_for_denied()\n    if verdict.shadow_reasons', '    if verdict.shadow_reasons'),
    ('guard: shadow would-deny runs without opt-in', 'clients/python/src/haltsql/guard.py', '    if verdict.shadow_reasons and not shadow_allowed():', '    if False:'),
    ('guard: explicit set_allow_shadow(False) loses to the environment', 'clients/python/src/haltsql/guard.py', '    if _allow_shadow is not None:\n        return _allow_shadow\n', '    if _allow_shadow:\n        return _allow_shadow\n'),
    ('guard: non-Verdict object accepted', 'clients/python/src/haltsql/guard.py', '    if not isinstance(verdict, Verdict):\n        raise HaltSQLUnavailable("verifier did not return a Verdict")\n', ''),
    ('guard: read_only default off for SELECT', 'clients/python/src/haltsql/guard.py', '        return verdict.statement_kind == "select"', '        return False'),
    ('guard: psycopg sync never sets READ ONLY', 'clients/python/src/haltsql/guard.py', '            if read_only:\n                cur.execute("SET TRANSACTION READ ONLY")', '            if False:\n                cur.execute("SET TRANSACTION READ ONLY")'),
    ('guard: psycopg async never sets READ ONLY', 'clients/python/src/haltsql/guard.py', '            if read_only:\n                await cur.execute("SET TRANSACTION READ ONLY")', '            if False:\n                await cur.execute("SET TRANSACTION READ ONLY")'),
    ('guard: asyncpg transaction not read-only', 'clients/python/src/haltsql/guard.py', '    async with conn.transaction(readonly=read_only):', '    async with conn.transaction(readonly=False):'),
    ('guard: settings (statement_timeout, pin) not applied on psycopg sync', 'clients/python/src/haltsql/guard.py', '            for name, value in [*settings, *pin]:\n                cur.execute(', '            for name, value in []:\n                cur.execute('),
    ('guard: search_path pin dropped (sync)', 'clients/python/src/haltsql/guard.py', '        conn, sql, params, _read_only(read_only, verdict), setts, max_rows,\n        pin=_pin_search_path(verdict),', '        conn, sql, params, _read_only(read_only, verdict), setts, max_rows,\n        pin=[],'),
    ('guard: search_path pin dropped (asyncpg)', 'clients/python/src/haltsql/guard.py', '            conn, sql, params, ro, setts, max_rows, verdict.statement_kind,\n            pin=_pin_search_path(verdict),', '            conn, sql, params, ro, setts, max_rows, verdict.statement_kind,\n            pin=[],'),
    ('guard: search_path identifiers not quoted', 'clients/python/src/haltsql/guard.py', '", ".join(\'"\' + x.replace(\'"\', \'""\') + \'"\' for x in sp)', '", ".join(x for x in sp)'),
    ('guard: caller search_path setting wins over the pin', 'clients/python/src/haltsql/guard.py', '            for name, value in [*settings, *pin]:\n                await cur.execute(', '            for name, value in [*pin, *settings]:\n                await cur.execute('),
    ('guard: row cap not enforced (sync)', 'clients/python/src/haltsql/guard.py', '    return rows[:max_rows], columns, len(rows) > max_rows', '    return rows, columns, False'),
    ('guard: SQL altered before execution (sync)', 'clients/python/src/haltsql/guard.py', '            cur.execute(sql, list(params))\n            rows, cols, truncated = _fetch_psycopg', "            cur.execute(sql.strip() + ' ', list(params))\n            rows, cols, truncated = _fetch_psycopg"),
    ('guard: runs inside an open transaction', 'clients/python/src/haltsql/guard.py', '    idle = conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE\n    if (read_only or settings) and not idle:\n        raise GuardError(\n            "connection is already in a transaction; guarded execution with read_only, "\n            "statement_timeout, or settings needs an idle connection"\n        )\n    with conn.transaction():', '    idle = True\n    with conn.transaction():'),
    ('guard: invalid setting names accepted', 'clients/python/src/haltsql/guard.py', '        if not isinstance(k, str) or not _SETTING_RE.match(k):', '        if not isinstance(k, str):'),
    ('guard: execute_on_engine skips re-check of a supplied verdict', 'clients/python/src/haltsql/guard.py', '    else:\n        _authorize(kwargs["verdict"], sql)\n    raw = engine.raw_connection()', '    raw = engine.raw_connection()'),
    ('models: allowed accepts truthy non-booleans', 'clients/python/src/haltsql/models.py', '        if self.allowed is not True:\n            raise QueryDenied(self)', '        if not self.allowed:\n            raise QueryDenied(self)'),
    ('models: matches_sql always true', 'clients/python/src/haltsql/models.py', '        return self.sql_sha256 == sql_sha256(sql)', '        return True'),
    ('models: bind_args does not sort by placeholder', 'clients/python/src/haltsql/models.py', '        ordered = sorted(self.bind_params, key=lambda b: b.param)', '        ordered = list(self.bind_params)'),
    ('models: bind_args accepts gaps', 'clients/python/src/haltsql/models.py', '            if b.param != i:\n                raise ValueError(', '            if False:\n                raise ValueError('),
    ('models: bind_args works on denied verdicts', 'clients/python/src/haltsql/models.py', '        self.raise_for_denied()\n        ordered = sorted', '        ordered = sorted'),
    ('client: sql hash of the response not checked', 'clients/python/src/haltsql/client.py', '        if self.verify_sql_hash and not verdict.matches_sql(sql):', '        if False:'),
    ('mcp: denied verdict goes to execution path', 'clients/mcp/src/haltsql_mcp/core.py', '        if not verdict.allowed:\n            return {\n                "allowed": False,\n                "executed": False,\n                "reasons": _reasons(verdict),\n                "message": "HaltSQL denied the query. Fix it using the reasons and hints, then retry.",\n            }\n        if verdict.shadow_reasons and not guard.shadow_allowed():', '        if verdict.shadow_reasons and not guard.shadow_allowed():'),
    ('mcp: shadow would-deny goes to execution path', 'clients/mcp/src/haltsql_mcp/core.py', '        if verdict.shadow_reasons and not guard.shadow_allowed():\n            # A shadow-mode', '        if False:\n            # A shadow-mode'),
    ('mcp: executes read-write', 'clients/mcp/src/haltsql_mcp/core.py', '                read_only=True,', '                read_only=False,'),
    ('mcp: no row cap', 'clients/mcp/src/haltsql_mcp/core.py', '                max_rows=self.row_cap,', '                max_rows=None,'),
    ('mcp: no statement timeout', 'clients/mcp/src/haltsql_mcp/core.py', '                statement_timeout_ms=self.statement_timeout_ms,', '                statement_timeout_ms=None,'),
    ('mcp: verifier exception treated as success', 'clients/mcp/src/haltsql_mcp/core.py', '        if not isinstance(result, Verdict) or not result.matches_sql(sql):', '        if not isinstance(result, Verdict):'),
    ('mcp: unauthenticated session gets an empty context', 'clients/mcp/src/haltsql_mcp/core.py', '        except PermissionError as e:\n            raise ToolFailure(str(e) or "not authenticated") from None', '        except PermissionError as e:\n            ctx = {}'),
    ('mcp: oversized SQL accepted', 'clients/mcp/src/haltsql_mcp/core.py', '        if len(sql) > MAX_SQL_CHARS:', '        if False:'),
    ('client: non-200 treated as a verdict', 'clients/python/src/haltsql/client.py', '    def _parse_verdict(self, resp: httpx.Response, sql: str) -> Verdict:\n        if resp.status_code != 200:', '    def _parse_verdict(self, resp: httpx.Response, sql: str) -> Verdict:\n        if False:'),
    ('guard: SQL altered before execution (asyncpg)', 'clients/python/src/haltsql/guard.py', '        stmt = await conn.prepare(sql)', '        stmt = await conn.prepare(sql.strip())'),
    ('guard: SQL altered before execution (psycopg async)', 'clients/python/src/haltsql/guard.py', '            await cur.execute(sql, list(params))', '            await cur.execute(sql.strip(), list(params))'),
]
