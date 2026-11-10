"""Typed mirrors of the HaltSQL verdict JSON (``docs/verdict.md``).

Parsing is strict about the fields that decide whether a query may run
(``allowed``, ``reasons``, ``bind_params``): a response with the wrong shape
raises :class:`ValueError`, which the clients turn into
:class:`~haltsql.errors.HaltSQLUnavailable`. Unknown extra fields are ignored,
as the verdict contract requires.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import QueryDenied

__all__ = [
    "BindValue",
    "ContextValue",
    "Context",
    "Reason",
    "BindParam",
    "PolicyRef",
    "Verdict",
    "PolicyInfo",
    "validate_context",
    "sql_sha256",
]

#: A bound value: a string, or a list of strings for tenant sets.
BindValue = Union[str, List[str]]
#: A context value: string, integer, or a list of those.
ContextValue = Union[str, int, Sequence[Union[str, int]]]
#: The caller's context, taken from its authenticated session.
Context = Mapping[str, ContextValue]


def sql_sha256(sql: str) -> str:
    """Lower-case hex SHA-256 of the UTF-8 bytes of ``sql`` (as in ``sql_sha256``)."""
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_context(context: Optional[Context]) -> Dict[str, Any]:
    """Check and copy a context into a JSON-ready dict.

    Keys must be non-empty strings; values strings, integers (not booleans), or
    lists/tuples of those. Raises :class:`ValueError` otherwise.
    """
    if context is None:
        return {}
    if not isinstance(context, Mapping):
        raise ValueError("context must be a mapping")
    out: Dict[str, Any] = {}
    for k, v in context.items():
        if not isinstance(k, str) or not k:
            raise ValueError("context keys must be non-empty strings")
        if isinstance(v, str) or _is_int(v):
            out[k] = v
        elif isinstance(v, (list, tuple)):
            items = list(v)
            for item in items:
                if not (isinstance(item, str) or _is_int(item)):
                    raise ValueError(
                        f"context[{k!r}] list items must be strings or integers"
                    )
            out[k] = items
        else:
            raise ValueError(
                f"context[{k!r}] must be a string, an integer, or a list of those"
            )
    return out


def _req(d: Mapping[str, Any], key: str, typ: Any, what: str) -> Any:
    if key not in d:
        raise ValueError(f"{what}: missing field {key!r}")
    v = d[key]
    if typ is int:
        ok = _is_int(v)
    else:
        ok = isinstance(v, typ)
    if not ok:
        raise ValueError(f"{what}: field {key!r} has the wrong type")
    return v


def _opt(d: Mapping[str, Any], key: str, typ: Any, what: str) -> Any:
    v = d.get(key)
    if v is None:
        return None
    if typ is int:
        ok = _is_int(v)
    else:
        ok = isinstance(v, typ)
    if not ok:
        raise ValueError(f"{what}: field {key!r} has the wrong type")
    return v


def _str_list(d: Mapping[str, Any], key: str, what: str) -> Tuple[str, ...]:
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{what}: field {key!r} must be a list of strings")
    return tuple(v)


@dataclass(frozen=True)
class Reason:
    """Why a query was (or would have been) denied."""

    code: str
    """Stable reason code, e.g. ``E_TENANT_MISSING``. Match on this."""
    message: str
    """Human-readable explanation; may change between releases."""
    rule: str = ""
    """Identifier of the rule that produced the reason."""
    loc: Optional[int] = None
    """0-based byte offset into the SQL string, when known."""
    hint: Optional[str] = None
    """A short instruction an LLM agent can follow to fix its query."""

    @classmethod
    def from_dict(cls, d: Any) -> "Reason":
        if not isinstance(d, Mapping):
            raise ValueError("reason must be an object")
        return cls(
            code=_req(d, "code", str, "reason"),
            message=_req(d, "message", str, "reason"),
            rule=_opt(d, "rule", str, "reason") or "",
            loc=_opt(d, "loc", int, "reason"),
            hint=_opt(d, "hint", str, "reason"),
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"code": self.code, "message": self.message, "rule": self.rule}
        if self.loc is not None:
            out["loc"] = self.loc
        if self.hint is not None:
            out["hint"] = self.hint
        return out


@dataclass(frozen=True)
class BindParam:
    """A value the caller must bind to placeholder ``$param``."""

    param: int
    value: BindValue

    @classmethod
    def from_dict(cls, d: Any) -> "BindParam":
        if not isinstance(d, Mapping):
            raise ValueError("bind_param must be an object")
        param = _req(d, "param", int, "bind_param")
        if param < 1:
            raise ValueError("bind_param: param must be >= 1")
        value = d.get("value")
        if isinstance(value, str):
            v: BindValue = value
        elif isinstance(value, list) and all(isinstance(x, str) for x in value):
            v = list(value)
        else:
            raise ValueError("bind_param: value must be a string or a list of strings")
        return cls(param=param, value=v)

    def to_dict(self) -> Dict[str, Any]:
        return {"param": self.param, "value": self.value}


@dataclass(frozen=True)
class PolicyRef:
    """The policy that produced a verdict."""

    name: str
    version: str
    """``sha256:<hex>`` of the normalized policy."""
    search_path: Optional[Tuple[str, ...]] = None
    """The schemas the verifier resolved unqualified names against, or ``None``
    from an engine that does not report it. The verdict holds only if the
    session that runs the SQL uses this search path; the guard pins it."""

    @classmethod
    def from_dict(cls, d: Any) -> "PolicyRef":
        if not isinstance(d, Mapping):
            raise ValueError("policy must be an object")
        sp = d.get("search_path")
        if sp is not None and (
            not isinstance(sp, (list, tuple)) or not all(isinstance(s, str) for s in sp)
        ):
            raise ValueError("policy.search_path must be a list of strings")
        return cls(
            name=_req(d, "name", str, "policy"),
            version=_req(d, "version", str, "policy"),
            search_path=None if sp is None else tuple(sp),
        )


@dataclass(frozen=True)
class Verdict:
    """The answer to "may this caller run this exact SQL string?"."""

    allowed: bool
    reasons: Tuple[Reason, ...]
    shadow_reasons: Tuple[Reason, ...]
    policy: PolicyRef
    statement_kind: Optional[str]
    tables: Tuple[str, ...]
    columns: Tuple[str, ...]
    bind_params: Tuple[BindParam, ...]
    fingerprint: Optional[str]
    sql_sha256: str
    elapsed_us: int = 0
    request_id: Optional[str] = field(default=None, compare=False)
    """``X-Request-Id`` of the HTTP exchange (not part of the verdict JSON)."""
    raw: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)
    """The verdict JSON as received, including fields this version ignores."""

    @classmethod
    def from_dict(cls, d: Any, *, request_id: Optional[str] = None) -> "Verdict":
        """Parse a verdict JSON object. Raises :class:`ValueError` on a bad shape."""
        if not isinstance(d, Mapping):
            raise ValueError("verdict must be a JSON object")
        allowed = d.get("allowed")
        if allowed is not True and allowed is not False:
            raise ValueError("verdict: 'allowed' must be a boolean")
        reasons_raw = d.get("reasons", [])
        shadow_raw = d.get("shadow_reasons", [])
        binds_raw = d.get("bind_params", [])
        for name, val in (
            ("reasons", reasons_raw),
            ("shadow_reasons", shadow_raw),
            ("bind_params", binds_raw),
        ):
            if not isinstance(val, list):
                raise ValueError(f"verdict: {name!r} must be a list")
        reasons = tuple(Reason.from_dict(r) for r in reasons_raw)
        if not allowed and not reasons:
            # A denial with no reason is never produced by HaltSQL; keep it a
            # denial but make it explainable.
            reasons = (
                Reason(code="E_INTERNAL", message="denied without a reason", rule="client"),
            )
        if allowed and reasons:
            raise ValueError("verdict: allowed is true but reasons is not empty")
        binds = tuple(BindParam.from_dict(b) for b in binds_raw)
        if len({b.param for b in binds}) != len(binds):
            raise ValueError("verdict: duplicate bind_params entries")
        kind = d.get("statement_kind")
        if kind is not None and not isinstance(kind, str):
            raise ValueError("verdict: 'statement_kind' must be a string or null")
        fp = d.get("fingerprint")
        if fp is not None and not isinstance(fp, str):
            raise ValueError("verdict: 'fingerprint' must be a string or null")
        elapsed = d.get("elapsed_us", 0)
        if not _is_int(elapsed):
            raise ValueError("verdict: 'elapsed_us' must be an integer")
        return cls(
            allowed=bool(allowed),
            reasons=reasons,
            shadow_reasons=tuple(Reason.from_dict(r) for r in shadow_raw),
            policy=PolicyRef.from_dict(d.get("policy")),
            statement_kind=kind,
            tables=_str_list(d, "tables", "verdict"),
            columns=_str_list(d, "columns", "verdict"),
            bind_params=binds,
            fingerprint=fp,
            sql_sha256=_req(d, "sql_sha256", str, "verdict"),
            elapsed_us=elapsed,
            request_id=request_id,
            raw=dict(d),
        )

    @property
    def codes(self) -> List[str]:
        """The reason codes, in order."""
        return [r.code for r in self.reasons]

    def matches_sql(self, sql: str) -> bool:
        """True if this verdict was computed for exactly ``sql`` (by SHA-256)."""
        return self.sql_sha256 == sql_sha256(sql)

    def raise_for_denied(self) -> "Verdict":
        """Raise :class:`QueryDenied` unless allowed; return ``self`` otherwise."""
        if self.allowed is not True:
            raise QueryDenied(self)
        return self

    def bind_args(self) -> List[BindValue]:
        """Positional parameters for psycopg (``RawCursor``) and asyncpg.

        Returns ``[value_of_$1, value_of_$2, ...]``; tenant sets stay Python
        lists (bound as Postgres arrays). Raises :class:`QueryDenied` if the
        verdict is a denial and :class:`ValueError` if the placeholders are not
        exactly ``$1..$n`` (positional binding would be ambiguous).
        """
        self.raise_for_denied()
        ordered = sorted(self.bind_params, key=lambda b: b.param)
        for i, b in enumerate(ordered, start=1):
            if b.param != i:
                raise ValueError(
                    f"bind_params are not contiguous: expected ${i}, got ${b.param}"
                )
        return [list(b.value) if isinstance(b.value, list) else b.value for b in ordered]

    def to_dict(self) -> Dict[str, Any]:
        """The verdict as JSON-ready data (the received JSON when available)."""
        if self.raw:
            return dict(self.raw)
        return {
            "allowed": self.allowed,
            "reasons": [r.to_dict() for r in self.reasons],
            "shadow_reasons": [r.to_dict() for r in self.shadow_reasons],
            "policy": {
                "name": self.policy.name,
                "version": self.policy.version,
                **(
                    {}
                    if self.policy.search_path is None
                    else {"search_path": list(self.policy.search_path)}
                ),
            },
            "statement_kind": self.statement_kind,
            "tables": list(self.tables),
            "columns": list(self.columns),
            "bind_params": [b.to_dict() for b in self.bind_params],
            "fingerprint": self.fingerprint,
            "sql_sha256": self.sql_sha256,
            "elapsed_us": self.elapsed_us,
        }


@dataclass(frozen=True)
class PolicyInfo:
    """An entry of ``GET /v1/policies``."""

    name: str
    version: str
    mode: str

    @classmethod
    def from_dict(cls, d: Any) -> "PolicyInfo":
        if not isinstance(d, Mapping):
            raise ValueError("policy entry must be an object")
        return cls(
            name=_req(d, "name", str, "policy entry"),
            version=_req(d, "version", str, "policy entry"),
            mode=_opt(d, "mode", str, "policy entry") or "enforce",
        )
