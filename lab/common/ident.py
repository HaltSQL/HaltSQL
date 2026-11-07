"""Postgres identifier helpers (quoting, parsing qualified names from policies).

Names are kept exactly as Postgres stores them: an unquoted policy name is
lower-cased, a double-quoted one is preserved (same rule as the HaltSQL policy
loader, see lib/core/policy.ml).
"""

from __future__ import annotations

import re

# Postgres reserved key words (SQL key words table, "reserved" in PostgreSQL
# column, plus a few "reserved (can be function or type)" that break as
# column names). Quoting extra words is always safe.
RESERVED: frozenset[str] = frozenset(
    """
    all analyse analyze and any array as asc asymmetric authorization binary both
    case cast check collate collation column concurrently constraint create cross
    current_catalog current_date current_role current_schema current_time
    current_timestamp current_user default deferrable desc distinct do else end
    except false fetch for foreign freeze from full grant group having ilike in
    initially inner intersect into is isnull join lateral leading left like limit
    localtime localtimestamp natural not notnull null offset on only or order outer
    overlaps placing primary references returning right select session_user similar
    some symmetric system_user table tablesample then to trailing true union unique
    user using variadic verbose when where window with
    """.split()
)

_SIMPLE = re.compile(r"^[a-z_][a-z0-9_$]*$")


def qi(name: str) -> str:
    """Quote an identifier only when Postgres needs it."""
    if _SIMPLE.match(name) and name not in RESERVED:
        return name
    return '"' + name.replace('"', '""') + '"'


def qname(schema: str, name: str) -> str:
    """Render a qualified relation name."""
    return f"{qi(schema)}.{qi(name)}"


def split_qualified(text: str) -> list[str]:
    """Split a policy-style name like ``app.orders`` or ``"Fin"."GL Acct"``.

    Unquoted parts are lower-cased; quoted parts are preserved with ``""``
    unescaped. Raises ValueError on malformed input.
    """
    parts: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == '"':
            j = i + 1
            buf: list[str] = []
            while True:
                if j >= n:
                    raise ValueError(f"unterminated quoted identifier in {text!r}")
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        buf.append('"')
                        j += 2
                        continue
                    break
                buf.append(text[j])
                j += 1
            parts.append("".join(buf))
            i = j + 1
        else:
            j = i
            while j < n and text[j] != ".":
                j += 1
            part = text[i:j].strip()
            if not part:
                raise ValueError(f"empty identifier part in {text!r}")
            parts.append(part.lower())
            i = j
        if i < n:
            if text[i] != ".":
                raise ValueError(f"expected '.' in {text!r} at {i}")
            i += 1
    return parts


def normalize_column(name: str) -> str:
    """A policy column entry: quoted keeps case, unquoted is lower-cased."""
    parts = split_qualified(name)
    if len(parts) != 1:
        raise ValueError(f"column name must not be qualified: {name!r}")
    return parts[0]


def slug(text: str) -> str:
    """Marker-safe slug: lower-case, [a-z0-9_] only (used in honeytokens)."""
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s or "x"
