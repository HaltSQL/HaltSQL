"""Loader for an LLM red-team (or replayed agent traffic) corpus.

No model APIs are called here. A separate, offline process asks models to
extract other tenants' data through a text-to-SQL agent and writes JSONL:

    {"id": "rt-0001", "sql": "SELECT ...", "context": {"tenant_id": "acme"},
     "intent": "adversarial", "model": "some-model", "prompt_id": "inj-07"}

Only ``sql`` is required. Missing ``context`` is filled from the scenario's
tenant universe; missing ``intent`` defaults to ``adversarial`` for red-team
files and ``benign`` for replay files. Unknown keys are kept under ``meta``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterator


def load_jsonl(
    path: str | Path,
    default_intent: str = "adversarial",
    context_for: Callable[[int], dict[str, Any]] | None = None,
    id_prefix: str = "rt",
    transform: str = "redteam",
) -> Iterator[dict[str, Any]]:
    p = Path(path)
    with p.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{p}:{lineno}: invalid JSON: {e}") from None
            if not isinstance(obj, dict) or not isinstance(obj.get("sql"), str):
                raise ValueError(f"{p}:{lineno}: each line needs a string 'sql'")
            ctx = obj.get("context")
            if ctx is None:
                if context_for is None:
                    raise ValueError(f"{p}:{lineno}: no context and no default context provider")
                ctx = context_for(lineno)
            intent = obj.get("intent", default_intent)
            if intent not in ("benign", "adversarial"):
                raise ValueError(f"{p}:{lineno}: intent must be benign|adversarial")
            known = {"id", "sql", "context", "intent", "transform"}
            yield {
                "id": str(obj.get("id", f"{id_prefix}-{lineno:05d}")),
                "sql": obj["sql"],
                "context": ctx,
                "intent": intent,
                "transform": obj.get("transform", transform),
                "template": None,
                "leak": obj.get("leak"),
                "meta": {k: v for k, v in obj.items() if k not in known},
            }
