"""Cloud Run option B for HaltSQL: one internal haltsql service shared by agents.

docs/deploy-gcp.md, pattern 2B. Writes docs/assets/cloud/gcp-cloud-run-internal.png.
Run with `make diagrams`, or directly:

    deploy/diagrams/.venv/bin/python deploy/diagrams/gcp_cloud_run_internal.py

Paths are resolved from this file, so the working directory does not matter.

Layout: the request path reads left to right from the agent services to the
internal haltsql service, with the policy bucket on its right. The managed
services sit in one band underneath: Cloud SQL below the agents and the audit
bucket below haltsql-server (one vertical line each), Secret Manager below the
policy bucket so its edge crosses nothing.
"""

from pathlib import Path

from diagrams import Cluster, Diagram, Node
from diagrams.gcp.compute import Run
from diagrams.gcp.database import SQL
from diagrams.gcp.security import SecretManager
from diagrams.gcp.storage import GCS
from diagrams.onprem.client import Users

from _style import ORTHO, Edge  # shared orthogonal-edge style

OUT = Path(__file__).resolve().parent.parent.parent / "docs" / "assets" / "cloud"

GRAPH = {
    "fontsize": "20",
    "fontname": "Helvetica",
    "pad": "0.4",
    **ORTHO,  # right-angle edges
    "nodesep": "0.6",
    "ranksep": "1.1",
}
# imagepos=tc: icon at the top of the node box, so edges arriving from above
# meet the icon rather than empty space (see fit()).
NODE = {"fontsize": "12", "fontname": "Helvetica", "imagepos": "tc"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

# Edge styles: request path, cloud API calls, configuration.
REQ = {"color": "#1a73e8", "penwidth": "2"}
API = {"color": "#188038", "style": "dashed"}
CFG = {"color": "#5f6368", "style": "dashed"}
INVIS = {"style": "invis"}
BAND = {"bgcolor": "transparent", "pencolor": "transparent", "margin": "4"}


def fit(label):
    """Node height that fits a top-aligned icon plus `label` with no gap."""
    return {"height": f"{1.45 + 0.2 * (label.count(chr(10)) + 1):.2f}"}


def node(cls, label, **attrs):
    return cls(label, **fit(label), **attrs)


def _key(color, style, text):
    return (
        f'<tr><td width="44" height="8" border="2" sides="b" color="{color}" style="{style}"></td>'
        f'<td align="left">{text}</td></tr>'
    )


LEGEND = (
    '<<table border="0" cellborder="0" cellspacing="6" cellpadding="0">'
    + _key("#1a73e8", "solid", "request path, verified SQL")
    + _key("#188038", "dashed", "audit batches (GCS API)")
    + _key("#5f6368", "dashed", "configuration (at startup)")
    + "</table>>"
)


def cloud_run_internal():
    with Diagram(
        "HaltSQL on Cloud Run: internal service shared by several agents",
        filename=str(OUT / "gcp-cloud-run-internal"),
        show=False,
        outformat="png",
        direction="LR",
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    ):
        users = node(Users, "End users")

        with Cluster("Google Cloud project"):
            agents = node(Run, "agent services\n(VPC egress: all-traffic)")

            with Cluster("Cloud Run service: haltsql\ningress=internal, callers need run.invoker"):
                hs = node(Run, "haltsql-server :8080")

            policies = node(GCS, "GCS policy bucket\nsigned bundles,\nread-only volume")

            # Borderless, untitled group: keeps the managed services together
            # in one band under the request path.
            with Cluster("", graph_attr=BAND):
                cloudsql = node(SQL, "Cloud SQL, private IP")
                audit = node(GCS, "GCS audit bucket\nretention locked")
                sm = node(SecretManager, "Secret Manager\nconfig.yaml")

        # Legend in the users' column, level with the band (bottom left).
        legend = Node(LEGEND, shape="plaintext", fixedsize="false", fontsize="11")
        legend >> Edge(**INVIS) >> cloudsql

        # Rank scaffolding (LR: rank = column). Cloud SQL shares the agents'
        # column and the audit bucket the haltsql column, so their edges are
        # single vertical lines; Secret Manager shares the policy bucket's.
        cloudsql >> Edge(**INVIS) >> audit
        audit >> Edge(**INVIS) >> sm
        hs >> Edge(**INVIS) >> policies

        # Main path
        users >> Edge(weight="10", **REQ) >> agents
        agents >> Edge(label="POST /v1/verify\nID tokens: IAM invoker + haltsql", weight="10", **REQ) >> hs

        # Side edges
        agents >> Edge(constraint="false", **REQ) >> cloudsql
        hs >> Edge(constraint="false", **API) >> audit
        policies >> Edge(constraint="false", **CFG) >> hs
        sm >> Edge(constraint="false", **CFG) >> hs


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    cloud_run_internal()
    print((OUT / "gcp-cloud-run-internal.png").relative_to(OUT.parent.parent.parent))
