"""Local mode: verify by running the ``haltsql`` CLI instead of calling the sidecar.

Useful in CI, notebooks, and batch jobs where no ``haltsql-server`` runs. Each
call spawns ``haltsql verify --policy FILE --batch`` and exchanges JSONL over
stdin/stdout, so the SQL never appears on a command line. Same fail-closed
rules as the HTTP clients: a missing binary, a timeout, a non-zero exit, or a
malformed line raises; nothing is ever treated as allowed.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .errors import HaltSQLRequestError, HaltSQLUnavailable
from .models import Context, Verdict, validate_context

__all__ = ["LocalVerifier", "AsyncLocalVerifier"]

_MAX_STDERR = 500


def _resolve_binary(binary: Optional[str]) -> str:
    candidate = binary or os.environ.get("HALTSQL_BIN") or "haltsql"
    if os.sep in candidate:
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            raise HaltSQLUnavailable(f"haltsql binary not found or not executable: {candidate}")
        return candidate
    found = shutil.which(candidate)
    if found is None:
        raise HaltSQLUnavailable(
            f"haltsql binary {candidate!r} not found on PATH (set HALTSQL_BIN)"
        )
    return found


class _LocalBase:
    def __init__(
        self,
        policy_file: "os.PathLike[str] | str",
        *,
        binary: Optional[str] = None,
        timeout: float = 30.0,
        verify_sql_hash: bool = True,
    ) -> None:
        path = os.fspath(policy_file)
        if not os.path.isfile(path):
            raise ValueError(f"policy file not found: {path}")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        self.policy_file = path
        self.binary = _resolve_binary(binary)
        self.timeout = timeout
        self.verify_sql_hash = verify_sql_hash

    def __repr__(self) -> str:
        return f"{type(self).__name__}(policy_file={self.policy_file!r}, binary={self.binary!r})"

    def _argv(self) -> List[str]:
        return [self.binary, "verify", "--policy", self.policy_file, "--batch"]

    @staticmethod
    def _input(items: Sequence[Tuple[str, Optional[Context]]]) -> bytes:
        lines = []
        for i, (sql, ctx) in enumerate(items):
            if not isinstance(sql, str):
                raise TypeError("sql must be a str")
            lines.append(
                json.dumps(
                    {"id": i, "sql": sql, "context": validate_context(ctx)},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _parse(
        self,
        items: Sequence[Tuple[str, Optional[Context]]],
        returncode: Optional[int],
        stdout: bytes,
        stderr: bytes,
    ) -> List[Verdict]:
        if returncode != 0:
            err = stderr.decode("utf-8", "replace").strip()[:_MAX_STDERR]
            raise HaltSQLUnavailable(
                f"haltsql CLI exited with status {returncode}" + (f": {err}" if err else "")
            )
        out_lines = [ln for ln in stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
        if len(out_lines) != len(items):
            raise HaltSQLUnavailable(
                f"haltsql CLI returned {len(out_lines)} result(s) for {len(items)} request(s)"
            )
        verdicts: List[Verdict] = []
        for i, (line, (sql, _ctx)) in enumerate(zip(out_lines, items)):
            try:
                data: Any = json.loads(line)
            except ValueError:
                raise HaltSQLUnavailable("haltsql CLI returned a non-JSON line") from None
            if not isinstance(data, dict) or data.get("id") != i:
                raise HaltSQLUnavailable("haltsql CLI returned results out of order")
            if "error" in data:
                msg = data["error"] if isinstance(data["error"], str) else "invalid request"
                raise HaltSQLRequestError(
                    f"haltsql rejected the request: {msg}", status=400, code="BAD_REQUEST"
                )
            body: Dict[str, Any] = {k: v for k, v in data.items() if k != "id"}
            try:
                verdict = Verdict.from_dict(body)
            except ValueError as e:
                raise HaltSQLUnavailable(f"haltsql CLI returned a malformed verdict: {e}") from None
            if self.verify_sql_hash and not verdict.matches_sql(sql):
                raise HaltSQLUnavailable("haltsql CLI verdict is for a different SQL string")
            verdicts.append(verdict)
        return verdicts


class LocalVerifier(_LocalBase):
    """Verify SQL with the local ``haltsql`` CLI.

    Args:
        policy_file: Policy document (YAML or JSON).
        binary: Path or name of the ``haltsql`` executable; defaults to
            ``$HALTSQL_BIN`` or ``haltsql`` on ``PATH``.
        timeout: Seconds before the CLI is killed and
            :class:`HaltSQLUnavailable` is raised.
    """

    def verify_many(self, items: Sequence[Tuple[str, Optional[Context]]]) -> List[Verdict]:
        """Verify several ``(sql, context)`` pairs with one CLI process."""
        if not items:
            return []
        data = self._input(items)
        try:
            proc = subprocess.run(
                self._argv(),
                input=data,
                capture_output=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise HaltSQLUnavailable(f"haltsql CLI timed out after {self.timeout}s") from None
        except OSError as e:
            raise HaltSQLUnavailable(f"could not run haltsql CLI: {type(e).__name__}") from None
        return self._parse(items, proc.returncode, proc.stdout, proc.stderr)

    def verify(self, sql: str, context: Optional[Context] = None) -> Verdict:
        """Verify one SQL string; returns the verdict (allowed or denied)."""
        return self.verify_many([(sql, context)])[0]

    def check(self, sql: str, context: Optional[Context] = None) -> Verdict:
        """Like :meth:`verify`, but raises :class:`~haltsql.QueryDenied` on a denial."""
        return self.verify(sql, context).raise_for_denied()


class AsyncLocalVerifier(_LocalBase):
    """``asyncio`` twin of :class:`LocalVerifier`."""

    async def verify_many(
        self, items: Sequence[Tuple[str, Optional[Context]]]
    ) -> List[Verdict]:
        if not items:
            return []
        data = self._input(items)
        try:
            proc = await asyncio.create_subprocess_exec(
                *self._argv(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            raise HaltSQLUnavailable(f"could not run haltsql CLI: {type(e).__name__}") from None
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(data), self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise HaltSQLUnavailable(f"haltsql CLI timed out after {self.timeout}s") from None
        return self._parse(items, proc.returncode, stdout, stderr)

    async def verify(self, sql: str, context: Optional[Context] = None) -> Verdict:
        return (await self.verify_many([(sql, context)]))[0]

    async def check(self, sql: str, context: Optional[Context] = None) -> Verdict:
        return (await self.verify(sql, context)).raise_for_denied()
