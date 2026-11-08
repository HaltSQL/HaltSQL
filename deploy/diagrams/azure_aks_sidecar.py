"""Azure reference architecture for HaltSQL on AKS, drawn with mingrammer/diagrams.

Writes, relative to the repository root:

  docs/assets/cloud/azure-aks-sidecar.png       AKS: agent pod + haltsql sidecar

Run with `make diagrams`, or directly:

  deploy/diagrams/.venv/bin/python deploy/diagrams/azure_aks_sidecar.py

Only components HaltSQL supports today are drawn as HaltSQL integrations.
Azure services that HaltSQL cannot talk to natively (Key Vault, Blob Storage,
Azure Monitor) are reached through standard Azure plumbing: the Secrets Store
CSI driver, a log shipper sidecar, Container Insights and an OpenTelemetry
Collector. See docs/deploy-azure.md, "Pattern 1: AKS sidecar" and "Current
limitations on Azure".

Layout (left to right): Key Vault and Entra ID feed the pod; inside the pod
the agent sits directly under its haltsql sidecar; on the right are the things
the pod writes to. The primary flow (verify, verdict, exact SQL to Flexible
Server) is the thick blue and green path along the bottom; secrets, audit and
telemetry run as thinner rows above it.

Graphviz cannot place ordinary edge labels on bent orthogonal edges, so every
labelled edge is weighted to stay straight, the vertical verify hop uses an
xlabel, and bent edges are unlabelled (their meaning is in the node text).
"""

from pathlib import Path

from diagrams import Cluster, Diagram
from diagrams.azure.databases import AzureDatabasePostgresqlServer
from diagrams.azure.devops import ApplicationInsights
from diagrams.azure.identity import ManagedIdentities
from diagrams.azure.monitor import Monitor
from diagrams.azure.security import KeyVaults
from diagrams.azure.storage import BlobStorage
from diagrams.generic.compute import Rack
from diagrams.generic.network import Firewall
from diagrams.k8s.storage import Volume
from diagrams.onprem.aggregator import Vector
from diagrams.onprem.container import Docker

from _style import ORTHO, Edge  # shared orthogonal-edge style

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "cloud"

GRAPH = {
    "fontsize": "22",
    "fontname": "Helvetica",
    "pad": "0.4",
    **ORTHO,  # right-angle edges
    # Tighter than the ORTHO defaults: this diagram has more rows than most.
    "nodesep": "0.6",
    "ranksep": "1.6",
    "labelloc": "t",
}
NODE = {"fontsize": "12", "fontname": "Helvetica"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

SUBNET = {"bgcolor": "#FFFFFF", "pencolor": "#7FB2E5", "style": "dashed", "fontsize": "13"}
POD = {"bgcolor": "#F7F7F7", "pencolor": "#999999", "fontsize": "13"}
PLATFORM = {"bgcolor": "#FAFAFA", "pencolor": "#BBBBBB", "fontsize": "13"}

VERIFY = "#0078D4"   # verify call
SQL = "#107C10"      # SQL that reaches the database
AUDIT = "#8764B8"    # audit records
TELEMETRY = "#CA5010"
IDENTITY = "#5C5C5C"


def diagram(name: str, title: str, direction: str = "LR") -> Diagram:
    OUT.mkdir(parents=True, exist_ok=True)
    return Diagram(
        title,
        filename=str(OUT / name),
        outformat="png",
        show=False,
        direction=direction,
        graph_attr=GRAPH,
        node_attr=NODE,
        edge_attr=EDGE,
    )


def same_rank(cluster: Cluster, *nodes) -> None:
    """Pin nodes to one rank (one column in an LR diagram)."""
    ids = "; ".join(f'"{n._id}"' for n in nodes)
    cluster.dot.body.append(f"{{rank=same; {ids}}}")


def straight(label: str, **attrs) -> Edge:
    """A labelled edge that dot keeps horizontal.

    Graphviz reserves room for an ordinary edge label in the rank gap and
    then routes orthogonal edges without looking at it, so the text only sits
    on its line when the line is straight. Every labelled edge here is
    weighted to stay straight; bent edges carry no label and their meaning
    lives in the node text instead.
    """
    attrs.setdefault("weight", "10")
    return Edge(label=label, **attrs)


def aks_sidecar() -> None:
    with diagram("azure-aks-sidecar", "HaltSQL on AKS: sidecar with Workload Identity"):
        kv = KeyVaults("Key Vault\n(RBAC, purge protection,\nprivate endpoint)")
        uami = ManagedIdentities("Entra ID: user-assigned MI\nfederated with the pod's SA\n(agent, CSI driver, Vector)")

        with Cluster("VNet: AKS node subnet (private cluster, OIDC issuer, NSG)", graph_attr=SUBNET):
            # Padding spaces keep the first glyphs clear of the icon's edge.
            otel = Rack("  OTel Collector  \n(observability ns)\nOTLP/HTTP :4318")
            with Cluster("agent pod  (namespace: agents; policies from a ConfigMap, reload.watch)", graph_attr=POD) as pod:
                shipper = Vector("Vector sidecar")
                csi = Volume("CSI volume\n(token hash)")
                haltsql = Firewall("  haltsql-server  \n  no Azure identity  ")
                agent = Docker("agent container")
                # The agent sits directly under its sidecar: the verify call is
                # a short vertical hop and the SQL leaves the pod in a straight line.
                same_rank(pod, agent, haltsql)

        with Cluster("Azure Monitor", graph_attr=PLATFORM):
            insights = Monitor("Log Analytics,\nManaged\nPrometheus\n(stdout audit,\n/metrics)")
            appi = ApplicationInsights("Application Insights")

        blob = BlobStorage("Blob, immutable container\n(WORM, private endpoint)")

        with Cluster("VNet: delegated subnet", graph_attr=SUBNET):
            pg = AzureDatabasePostgresqlServer("Flexible Server\n(zone-redundant HA)")

        # Primary flow. Verify and verdict share one two-way edge; the pinned
        # rank makes it a vertical hop, so its text is an xlabel beside it.
        uami >> straight("Workload Identity", color=IDENTITY, style="dotted", minlen="2") >> agent
        agent >> straight("3. exact SQL, only if allowed\n(Entra token, TLS)", color=SQL, penwidth="2", minlen="3") >> pg
        agent >> Edge(xlabel="1. POST /v1/verify    \n2. verdict    ", color=VERIFY, reverse=True, penwidth="2") >> haltsql

        # Secrets and config.
        csi >> Edge(color=IDENTITY) >> haltsql
        kv >> straight("CSI driver", color=IDENTITY) >> csi

        # Audit.
        shipper >> straight("block blobs", color=AUDIT) >> blob
        haltsql >> straight("audit file", color=AUDIT, weight="20") >> shipper

        # Telemetry.
        haltsql >> Edge(color=TELEMETRY, style="dashed", minlen="3", weight="10") >> insights
        otel >> straight("azuremonitor exporter", color=TELEMETRY, minlen="2") >> appi
        haltsql >> Edge(color=TELEMETRY) >> otel


if __name__ == "__main__":
    aks_sidecar()
    print(f"wrote azure-aks-sidecar.png to {OUT}")
