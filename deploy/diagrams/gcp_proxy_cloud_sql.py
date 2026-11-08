"""Pattern 3 of docs/deploy-gcp.md: haltsql-proxy in front of Cloud SQL.

Writes docs/assets/cloud/gcp-proxy-cloud-sql.png. Run with `make diagrams`,
or directly:

    deploy/diagrams/.venv/bin/python deploy/diagrams/gcp_proxy_cloud_sql.py

Paths are resolved from this file, so the working directory does not matter.
"""

from pathlib import Path

from diagrams import Cluster, Diagram
from diagrams.gcp.database import SQL
from diagrams.gcp.operations import Logging
from diagrams.gcp.security import Iam, SecretManager
from diagrams.k8s.compute import Pod
from diagrams.k8s.network import Service
from diagrams.k8s.rbac import ServiceAccount
from diagrams.onprem.client import Users

from _style import ORTHO, Edge  # shared orthogonal-edge style

OUT = Path(__file__).resolve().parent.parent.parent / "docs" / "assets" / "cloud"

GRAPH = {
    "fontsize": "20",
    "fontname": "Helvetica",
    "pad": "0.4",
    "nodesep": "0.7",
    "ranksep": "1.0",
    **ORTHO,  # right-angle edges; overrides the spacing above
}
NODE = {"fontsize": "12", "fontname": "Helvetica"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

# Edge styles: request path, telemetry, configuration (secrets, identity).
REQ = {"color": "#1a73e8", "penwidth": "2"}
TEL = {"color": "#9334e6", "style": "dotted"}
CFG = {"color": "#5f6368", "style": "dashed"}


def diagram(name, title, direction="LR"):
    return Diagram(
        title,
        filename=str(OUT / name),
        show=False,
        outformat="png",
        direction=direction,
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    )


# Nested clusters put their titles at the bottom: every secondary edge leaves
# its cluster through the top, so no line runs through a title.
BOTTOM = {"labelloc": "b"}


def same_rank(d, *nodes):
    """Put nodes in one rank (one column in LR). Needs newrank=true, since the
    nodes sit in different clusters. Takes diagrams nodes or raw node ids."""
    ids = (getattr(n, "_id", n) for n in nodes)
    d.dot.body.append("{rank=same; " + "; ".join(f'"{i}"' for i in ids) + "}")


def _swatch(color, dash, gap, height):
    """A line sample drawn with HTML table cells (font glyphs measure badly)."""
    n = 36 // (dash + gap) if gap else 1
    w = dash if gap else 36
    cells = "".join(
        f'<TD WIDTH="{w}" HEIGHT="{height}" FIXEDSIZE="TRUE" BGCOLOR="{color}"></TD>'
        for _ in range(n)
    )
    return f'<TABLE BORDER="0" CELLBORDER="0" CELLPADDING="0" CELLSPACING="{gap}"><TR>{cells}</TR></TABLE>'


def legend(d):
    """A small key for the three line styles; returns its node id."""
    rows = "".join(
        f'<TR><TD>{_swatch(*sample)}</TD><TD ALIGN="LEFT">{text}</TD></TR>'
        for sample, text in (
            ((REQ["color"], 36, 0, 2), "SQL request path"),
            ((CFG["color"], 6, 4, 1), "secrets / identity"),
            ((TEL["color"], 2, 4, 2), "audit logs"),
        )
    )
    d.dot.node(
        "legend",
        label=f'<<TABLE BORDER="1" COLOR="#AEB6BE" CELLBORDER="0" CELLPADDING="4" CELLSPACING="0">{rows}</TABLE>>',
        shape="plaintext",
        fontsize="12",
        fontname="Helvetica",
    )
    return "legend"


def proxy_cloud_sql():
    # Left to right, the request path is one straight row. Every secondary
    # node sits above the node it connects to, so its edge is a vertical (or
    # one L-shaped hop for the logs). Secondary edges carry no labels: their
    # meaning is in the node captions and the key, which keeps orthogonal label
    # placement out of the picture. Every node on the main row has a 3-line
    # caption: diagrams sizes a node by its caption, so equal captions keep
    # the icons (and the edges between them) aligned.
    with diagram("gcp-proxy-cloud-sql", "haltsql-proxy in front of Cloud SQL (GKE)") as d:
        d.dot.graph_attr["newrank"] = "true"
        clients = Users("Agents, BI tools,\nany Postgres driver\n(SCRAM or client cert)")

        with Cluster("Google Cloud project"):
            sm = SecretManager(
                "Secret Manager (GKE add-on)\nupstream password, TLS key/cert,\nSCRAM verifiers, mounted as files"
            )
            logs = Logging("Cloud Logging\naudit JSON, one line\nper statement (stdout)")

            with Cluster("VPC", graph_attr=BOTTOM):
                with Cluster("GKE cluster", graph_attr=BOTTOM):
                    with Cluster("namespace: haltsql", graph_attr=BOTTOM):
                        # Invisible box with an empty bottom title, mirroring the
                        # pod box next to it, so the Service lines up with the pods.
                        with Cluster(" ", graph_attr={**BOTTOM, "style": "invis"}):
                            ilb = Service("Service :6432\ninternal passthrough\nNetwork Load Balancer")
                        with Cluster("haltsql-proxy pod (x2+, PDB)", graph_attr=BOTTOM):
                            hp = Pod("haltsql-proxy\nSCRAM / client certs\nverifies every statement")
                            csp = Pod("cloud-sql-proxy\nCloud SQL Auth Proxy\n127.0.0.1:5432")
                        ksa = ServiceAccount("KSA haltsql-proxy")
                cloudsql = SQL("Cloud SQL for PostgreSQL\nprivate IP only,\nno authorized networks")

            gsa = Iam("GSA haltsql-proxy\nroles/cloudsql.client\n(Workload Identity from KSA)")

        # Primary flow.
        clients >> Edge(label="TLS", weight="100", **REQ) >> ilb
        ilb >> Edge(weight="100", **REQ) >> hp
        hp >> Edge(label="verified SQL only", weight="100", **REQ) >> csp
        csp >> Edge(label="mTLS + IAM", weight="100", **REQ) >> cloudsql

        # Secondary flows.
        sm >> Edge(**CFG) >> hp
        hp >> Edge(constraint="false", **TEL) >> logs
        ksa >> Edge(**CFG) >> gsa

        # Column placement (rank = column in LR). Each secondary node sits in
        # the column of the node it connects to, so its edge is (nearly) a
        # straight vertical: GSA above KSA above the Service, Secret Manager
        # above haltsql-proxy, Cloud Logging above cloud-sql-proxy's column.
        same_rank(d, gsa, ksa, ilb)
        same_rank(d, legend(d), clients)  # key sits above the clients
        same_rank(d, sm, hp)
        same_rank(d, logs, csp)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    proxy_cloud_sql()
    print((OUT / "gcp-proxy-cloud-sql.png").relative_to(OUT.parent.parent.parent))
