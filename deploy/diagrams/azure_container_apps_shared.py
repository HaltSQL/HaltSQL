"""Azure Container Apps, Option B (shared internal service), drawn with
mingrammer/diagrams.

Writes, relative to the repository root:

  docs/assets/cloud/azure-container-apps-shared.png

Run with `make diagrams`, or directly:

  deploy/diagrams/.venv/bin/python deploy/diagrams/azure_container_apps_shared.py

Agent apps call one `haltsql` app through internal ingress (TLS) with Entra ID
access tokens. HaltSQL cannot write to Azure Monitor or Blob Storage itself: an
OpenTelemetry Collector container forwards OTLP/HTTP to Application Insights,
and a Log Analytics data export rule copies the audit log to Blob. See
docs/deploy-azure.md, "Pattern 2: Azure Container Apps".

Layout: top-to-bottom ranks used as rows (rank=same), so the main path is one
row read left to right and every other edge is a short vertical drop.
"""

from pathlib import Path

from diagrams import Cluster, Diagram, Node
from diagrams.azure.compute import ContainerApps
from diagrams.azure.databases import AzureDatabasePostgresqlServer
from diagrams.azure.devops import ApplicationInsights
from diagrams.azure.identity import AppRegistrations
from diagrams.azure.monitor import LogAnalyticsWorkspaces
from diagrams.azure.storage import BlobStorage
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall

from _style import ORTHO, Edge  # shared orthogonal-edge style

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "cloud"
NAME = "azure-container-apps-shared"

GRAPH = {
    "fontsize": "22",
    "fontname": "Helvetica",
    "pad": "0.4",
    **ORTHO,  # right-angle edges
    "nodesep": "0.9",
    "ranksep": "0.9",
    "newrank": "true",  # lets rank=same rows span clusters
    "labelloc": "t",
}
NODE = {"fontsize": "12", "fontname": "Helvetica"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

# Cluster titles sit top-right so the Entra ID drops on the left miss them.
ENV = {"bgcolor": "#EEF5FC", "pencolor": "#0078D4", "fontsize": "13", "labeljust": "r"}
SUBNET = {"bgcolor": "#FFFFFF", "pencolor": "#7FB2E5", "style": "dashed", "fontsize": "13"}
APP = {"bgcolor": "#F7F7F7", "pencolor": "#999999", "fontsize": "13", "labeljust": "r"}

VERIFY = "#0078D4"   # verify call
SQL = "#107C10"      # SQL that reaches the database
AUDIT = "#8764B8"    # audit records
TELEMETRY = "#CA5010"
IDENTITY = "#5C5C5C"

INVIS = {"style": "invis"}


def row(d: Diagram, *nodes: Node) -> None:
    """Put nodes on one rank (a row, in top-to-bottom layout)."""
    ids = "; ".join(f'"{n._id}"' for n in nodes)
    d.dot.body.append(f"{{rank=same; {ids}}}")


def legend(items: list[tuple[str, str, str]]) -> Node:
    """A key for the line styles, drawn as one HTML-label node."""
    rows = "".join(
        f'<TR><TD><FONT COLOR="{color}">{"&middot; " * 4 if style == "dotted" else "&#9472;" * 3}'
        f"&#9654;</FONT></TD>"
        f'<TD ALIGN="LEFT">{text}</TD></TR>'
        for color, style, text in items
    )
    return Node(
        f'<<TABLE BORDER="0" CELLSPACING="3">{rows}</TABLE>>',
        shape="box",
        style="rounded",
        color="#BBBBBB",
        fontsize="11",
        fixedsize="false",
        width="0",
        height="0",
        labelloc="c",
        margin="0.12",
    )


def shared() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with Diagram(
        "HaltSQL on Azure Container Apps: shared service (Option B)",
        filename=str(OUT / NAME),
        outformat="png",
        show=False,
        direction="TB",
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    ) as d:
        # Label on top: the identity edges leave from the bottom of the node.
        entra = AppRegistrations("Entra ID (app 'haltsql')", labelloc="t")
        key = legend(
            [
                (VERIFY, "solid", "POST /v1/verify: HTTPS + Entra JWT"),
                (SQL, "solid", "exact SQL, only if allowed"),
                (TELEMETRY, "solid", "traces and metrics (OTLP/HTTP)"),
                (AUDIT, "solid", "audit records (stdout, then data export)"),
                (IDENTITY, "dotted", "access tokens; signing keys (JWKS)"),
            ]
        )

        with Cluster("Container Apps env (internal)", graph_attr=ENV):
            agents = ContainerApps("agent apps\n(managed identities)")
            with Cluster("haltsql app (internal ingress)", graph_attr=APP):
                haltsql = Firewall("haltsql\nmin 2 replicas")
                otel = Rack("otel-collector\n127.0.0.1:4318")
        appi = ApplicationInsights("Azure Monitor\nApplication Insights")

        with Cluster("delegated subnet", graph_attr=SUBNET):
            pg = AzureDatabasePostgresqlServer("PostgreSQL\nFlexible Server")
        law = LogAnalyticsWorkspaces("Azure Monitor\nLog Analytics")
        blob = BlobStorage("immutable Blob\ncontainer")

        # Rows: identity on top, the request path in the middle, sinks below,
        # each sink straight under the container that feeds it.
        row(d, entra, key)
        row(d, agents, haltsql, otel, appi)
        row(d, pg, law, blob)

        # Edges carry no text: in orthogonal mode Graphviz places labels before
        # it routes, so they drift. The legend and node labels carry the detail.
        # Main path, left to right.
        agents >> Edge(color=VERIFY) >> haltsql
        haltsql >> Edge(color=TELEMETRY) >> otel
        otel >> Edge(color=TELEMETRY) >> appi

        # Straight drops below the main path.
        agents >> Edge(color=SQL) >> pg
        haltsql >> Edge(color=AUDIT) >> law
        law >> Edge(color=AUDIT) >> blob

        # Entra ID issues the agents' tokens and publishes the keys haltsql
        # checks them with.
        entra >> Edge(color=IDENTITY, style="dotted") >> agents
        entra >> Edge(color=IDENTITY, style="dotted", weight="10") >> haltsql
        key >> Edge(**INVIS) >> otel


if __name__ == "__main__":
    shared()
    print(f"wrote {OUT / (NAME + '.png')}")
