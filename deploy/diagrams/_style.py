"""Shared drawing style for the cloud architecture diagrams.

Edges are routed orthogonally (horizontal and vertical segments only) instead
of as curves. Graphviz centres an edge label on its edge's midpoint and, in
orthogonal mode, routes the line straight through it, so `Edge` here pads every
label with blank lines underneath. That lifts the text above a horizontal line
and keeps it readable.

Set HALTSQL_DIAGRAM_SPLINES (for example to "polyline" or "spline") to compare
other routing modes without editing the scripts.
"""

import os

from diagrams import Edge as _Edge

__all__ = ["ORTHO", "Edge"]

ORTHO = {
    "splines": os.environ.get("HALTSQL_DIAGRAM_SPLINES", "ortho"),
    "nodesep": "1.1",
    "ranksep": "1.5",
}


class Edge(_Edge):
    """A diagrams Edge whose label sits above the line instead of on it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        label = self._attrs.get("label", "")
        if label:
            pad = "\n" * (label.count("\n") + 2)
            self._attrs["label"] = label + pad
