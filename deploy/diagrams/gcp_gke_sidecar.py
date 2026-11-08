"""GKE sidecar reference architecture for HaltSQL (docs/deploy-gcp.md, Pattern 1).

Writes docs/assets/cloud/gcp-gke-sidecar.png. Run with `make diagrams`, or:

    deploy/diagrams/.venv/bin/python deploy/diagrams/gcp_gke_sidecar.py

Paths are resolved from this file, so the working directory does not matter.

Layout: the numbered request path runs left to right along the bottom row
(users -> agent -> haltsql-server, then cloud-sql-proxy -> Cloud SQL).
Secondary flows (Workload Identity, secrets, audit, telemetry) step up and
right into the managed-services column; their details live in node labels
because orthogonal routing places long-edge labels badly. Node and edge order
below is deliberate: graphviz stacks the managed services in reverse
declaration order, and the minlen/weight on the TLS edge keeps Cloud SQL out
of that column so the bottom row stays straight. Re-check the PNG after any
reordering.
"""

from pathlib import Path

from diagrams import Cluster, Diagram, Node
from diagrams.gcp.database import SQL
from diagrams.gcp.ml import VertexAI
from diagrams.gcp.operations import Logging, Monitoring
from diagrams.gcp.security import Iam, SecretManager
from diagrams.gcp.storage import GCS
from diagrams.k8s.compute import Pod
from diagrams.k8s.rbac import ServiceAccount
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
NODE = {"fontsize": "12", "fontname": "Helvetica"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

# Edge styles: request path, cloud API calls, telemetry, configuration.
REQ = {"color": "#1a73e8", "penwidth": "2"}
API = {"color": "#188038", "style": "dashed"}
TEL = {"color": "#9334e6", "style": "dotted", "penwidth": "1.5"}
CFG = {"color": "#5f6368", "style": "dashed"}


def legend_label():
    """An HTML table keyed to the edge styles above."""
    rows = [
        ("#1a73e8", "━" * 5, "request path"),
        ("#188038", "╍" * 5, "Google Cloud API call"),
        ("#9334e6", "• " * 5, "telemetry"),
        ("#5f6368", "╍" * 5, "identity binding"),
    ]
    cells = "".join(
        f'<tr><td><font color="{color}">{sample}</font></td><td align="left">{text}</td></tr>'
        for color, sample, text in rows
    )
    return f'<<table border="0" cellspacing="2" cellpadding="2">{cells}</table>>'


def gke_sidecar():
    with Diagram(
        "HaltSQL on GKE: sidecar with Workload Identity",
        filename=str(OUT / "gcp-gke-sidecar"),
        show=False,
        outformat="png",
        direction="LR",
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    ):
        users = Users("End users")
        llm = VertexAI("LLM API")

        with Cluster("Google Cloud project"):
            legend = Node(
                legend_label(), shape="box", style="rounded", color="#AEB6BE",
                fontsize="11", margin="0.15", fixedsize="false", width="0", height="0",
            )
            cloudsql = SQL("Cloud SQL Postgres\nprivate IP, IAM auth\nrestricted role, RLS")
            with Cluster("GKE cluster: private nodes, Workload Identity"):
                with Cluster("namespace: agents"):
                    with Cluster("Agent pod (NetworkPolicy: no ingress from other pods)"):
                        agent = Pod("agent")
                        sqlproxy = Pod("cloud-sql-proxy\n127.0.0.1:5432")
                        hs = Pod("haltsql-server\n127.0.0.1:8080\npolicy: ConfigMap")
                    ksa = ServiceAccount("KSA analytics-agent\nWorkload Identity")

            with Cluster("Managed services (IAM-scoped to the GSA)"):
                mon = Monitoring("Managed Prometheus\nscrapes /metrics")
                trace = Logging("Cloud Trace\nvia in-cluster OTel Collector")
                gcs = GCS("GCS audit bucket\nhash-chained, retention-locked")
                sm = SecretManager("Secret Manager\ntoken SHA-256")
                gsa = Iam("GSA haltsql-agent\nleast-privilege roles")

        # Primary request path.
        users >> Edge(label="request", weight="20", **REQ) >> agent
        agent >> Edge(label="prompt", **REQ) >> llm
        agent >> Edge(label="2. allowed SQL", weight="20", **REQ) >> sqlproxy
        agent >> Edge(headlabel="1. POST /v1/verify", labeldistance="9", labelangle="8", **REQ) >> hs
        # A blank centre label keeps the edge straight; the text sits at the head.
        tls = {"headlabel": "3. TLS", "labeldistance": "7", "labelangle": "-10"}
        sqlproxy >> Edge(label=" ", minlen="2", weight="20", **tls, **REQ) >> cloudsql

        # Secondary flows.
        legend >> Edge(style="invis") >> ksa  # park the legend above the GKE cluster
        agent >> Edge(style="invis") >> ksa  # KSA in the haltsql column, clear of cluster titles
        ksa >> Edge(**CFG) >> gsa
        hs >> Edge(weight="10", **TEL) >> trace
        hs >> Edge(**API) >> gcs
        hs >> Edge(**API) >> sm
        hs << Edge(**TEL) << mon  # Managed Prometheus scrapes /metrics (pull)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    gke_sidecar()
    print((OUT / "gcp-gke-sidecar.png").relative_to(OUT.parent.parent.parent))
