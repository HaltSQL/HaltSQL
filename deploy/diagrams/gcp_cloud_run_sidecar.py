"""Cloud Run option A for HaltSQL: sidecar in the agent's service.

docs/deploy-gcp.md, pattern 2A. Writes docs/assets/cloud/gcp-cloud-run-sidecar.png.
Run with `make diagrams`, or directly:

    deploy/diagrams/.venv/bin/python deploy/diagrams/gcp_cloud_run_sidecar.py

Paths are resolved from this file, so the working directory does not matter.

Layout: the request path reads left to right through the one Cloud Run
service. The managed services sit in one band under it: Cloud SQL below the
agent and the audit bucket below haltsql-server (one vertical line each),
Secret Manager below the collector so its edge crosses nothing. Flow types are told apart by colour and line style (see the legend).
"""

from pathlib import Path

from diagrams import Cluster, Diagram, Node
from diagrams.gcp.compute import Run
from diagrams.gcp.database import SQL
from diagrams.gcp.operations import Logging, Monitoring
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

# Edge styles: request path, cloud API calls, telemetry, configuration.
REQ = {"color": "#1a73e8", "penwidth": "2"}
API = {"color": "#188038", "style": "dashed"}
TEL = {"color": "#9334e6", "style": "dotted", "penwidth": "1.5"}
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
    + _key("#9334e6", "dotted", "telemetry (OTLP, /metrics)")
    + _key("#5f6368", "dashed", "configuration (at startup)")
    + "</table>>"
)


def cloud_run_sidecar():
    with Diagram(
        "HaltSQL on Cloud Run: sidecar in the agent's service",
        filename=str(OUT / "gcp-cloud-run-sidecar"),
        show=False,
        outformat="png",
        direction="LR",
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    ):
        users = node(Users, "End users")

        with Cluster("Google Cloud project"):
            with Cluster("Cloud Run service: agent (three containers; only :8080 is exposed)"):
                agent = node(Run, "agent :8080\n(ingress container)")
                hs = node(Run, "haltsql-server :8081")
                otel = node(Run, "otel collector")

            # Borderless, untitled group: keeps the managed services together
            # in one band under the service.
            with Cluster("", graph_attr=BAND):
                cloudsql = node(SQL, "Cloud SQL, private IP\n(Direct VPC egress)")
                audit = node(GCS, "GCS audit bucket\nretention locked")
                sm = node(SecretManager, "Secret Manager\nconfig, policy, token hash")

            trace = node(Logging, "Cloud Trace")
            mon = node(Monitoring, "Cloud Monitoring\n(Managed Prometheus)")
            legend = Node(LEGEND, shape="plaintext", fixedsize="false", fontsize="11")

        # Rank scaffolding (LR: rank = column). Cloud SQL shares the agent's
        # column and the audit bucket the haltsql column, so their edges are
        # single vertical lines. Secret Manager sits in the collector's column;
        # under haltsql its edge would cross the audit edge.
        users >> Edge(weight="0", **INVIS) >> cloudsql
        cloudsql >> Edge(**INVIS) >> audit
        audit >> Edge(**INVIS) >> sm
        sm >> Edge(**INVIS) >> legend

        # Main path
        users >> Edge(weight="10", **REQ) >> agent
        agent >> Edge(label="POST /v1/verify", weight="10", **REQ) >> hs
        hs >> Edge(label="OTLP, /metrics", weight="10", **TEL) >> otel
        otel >> Edge(**TEL) >> trace
        otel >> Edge(**TEL) >> mon

        # Side edges
        agent >> Edge(constraint="false", **REQ) >> cloudsql
        hs >> Edge(constraint="false", **API) >> audit
        sm >> Edge(constraint="false", **CFG) >> hs


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    cloud_run_sidecar()
    print((OUT / "gcp-cloud-run-sidecar.png").relative_to(OUT.parent.parent.parent))
