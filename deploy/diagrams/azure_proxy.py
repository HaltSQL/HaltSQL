"""Azure reference architecture: haltsql-proxy in front of Flexible Server.

Drawn with mingrammer/diagrams. Writes, relative to the repository root:

  docs/assets/cloud/azure-proxy.png

Run with `make diagrams`, or directly:

  deploy/diagrams/.venv/bin/python deploy/diagrams/azure_proxy.py

Matches docs/deploy-azure.md, "Pattern 3". Edges carry no labels: Graphviz
places orthogonal-edge labels before routing, so they drift off their lines.
A legend explains the edge colours instead.
"""

from pathlib import Path

from diagrams import Cluster, Diagram
from diagrams.azure.databases import AzureDatabasePostgresqlServer
from diagrams.azure.monitor import LogAnalyticsWorkspaces
from diagrams.azure.networking import NetworkSecurityGroups
from diagrams.azure.security import KeyVaults
from diagrams.generic.network import Firewall
from diagrams.onprem.container import Docker

from _style import ORTHO, Edge  # shared orthogonal-edge style

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "cloud"

GRAPH = {
    "fontsize": "22",
    "fontname": "Helvetica",
    "pad": "0.4",
    "nodesep": "0.7",
    "ranksep": "1.0",
    **ORTHO,  # right-angle edges; overrides the spacing above
    "labelloc": "t",
}
NODE = {"fontsize": "12", "fontname": "Helvetica"}
EDGE = {"fontsize": "11", "fontname": "Helvetica"}

VNET = {"bgcolor": "#EEF5FC", "pencolor": "#0078D4", "fontsize": "14"}
SUBNET = {"bgcolor": "#FFFFFF", "pencolor": "#7FB2E5", "style": "dashed", "fontsize": "13"}
POD = {"bgcolor": "#F7F7F7", "pencolor": "#999999", "fontsize": "13"}

VERIFY = "#0078D4"   # client traffic into HaltSQL
SQL = "#107C10"      # SQL that reaches the database
AUDIT = "#8764B8"    # audit records
IDENTITY = "#5C5C5C" # secrets
BLOCKED = "#C50F1F"  # path the network denies


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


# (colour, line style, meaning); solid lines are drawn as thin colour bars.
LEGEND_ROWS = [
    (VERIFY, "solid", "Postgres wire, TLS (client to proxy)"),
    (SQL, "solid", "verified statements only, TLS verify-full"),
    (BLOCKED, "- - - -|", "direct :5432 denied (NSG; NetworkPolicy on AKS)"),
    (IDENTITY, "· · · · ·", "upstream password + TLS key (CSI volume)"),
    (AUDIT, "solid", "statement audit on stdout"),
]


def legend(diag: Diagram) -> None:
    """A small key for the edge colours, so the edges themselves need no labels."""

    def sample(colour: str, style: str) -> str:
        if style == "solid":
            bar = f'<TABLE BORDER="0" CELLPADDING="0" CELLSPACING="0"><TR><TD BGCOLOR="{colour}" WIDTH="34" HEIGHT="3" FIXEDSIZE="TRUE"></TD></TR></TABLE>'
            return f'<TD WIDTH="40">{bar}</TD>'
        return f'<TD WIDTH="40"><FONT COLOR="{colour}"><B>{style}</B></FONT></TD>'

    rows = "".join(
        f'<TR>{sample(c, st)}<TD ALIGN="LEFT">{text}</TD></TR>' for c, st, text in LEGEND_ROWS
    )
    diag.node(
        "legend",
        f'<<TABLE BORDER="1" COLOR="#BBBBBB" CELLBORDER="0" CELLSPACING="2" CELLPADDING="4" BGCOLOR="#FAFAFA">{rows}</TABLE>>',
        shape="plaintext",
        style="",
        fixedsize="false",
        width="0",
        height="0",
        labelloc="c",
        fontsize="12",
    )


def proxy() -> None:
    # Node labels end in "\n " where an edge meets the node's bottom or top, to
    # keep arrowheads off the text and the primary row's icons level.
    with diagram("azure-proxy", "haltsql-proxy in front of Azure Database for PostgreSQL") as d:
        law = LogAnalyticsWorkspaces("Log Analytics\n(Container Insights)")
        kv = KeyVaults("Key Vault")
        with Cluster("VNet", graph_attr=VNET):
            with Cluster("AKS or Container Apps subnet", graph_attr=SUBNET):
                agent = Docker("agent / BI tool\n(any Postgres driver)\nsslmode=verify-full\n ", group="main")
                with Cluster("haltsql-proxy  (2+ replicas across zones)", graph_attr={**POD, "labelloc": "b"}):
                    proxy_node = Firewall("haltsql-proxy :6432\nSCRAM or client cert\n-> policy + context\n ", group="main")
            with Cluster("delegated subnet", graph_attr={**SUBNET, "margin": "32"}) as db:
                pg = AzureDatabasePostgresqlServer("Flexible Server\nrequire_secure_transport=on\nread-only service role\n ", group="main")
                nsg = NetworkSecurityGroups("NSG: 5432 only\nfrom proxy subnet")
                same_rank(db, pg, nsg)
        legend(d)

        agent >> Edge(color=VERIFY, penwidth="2") >> proxy_node
        proxy_node >> Edge(color=SQL, penwidth="2") >> pg
        agent >> Edge(color=BLOCKED, style="dashed", arrowhead="tee") >> nsg
        kv >> Edge(color=IDENTITY, style="dotted") >> proxy_node
        proxy_node >> Edge(color=AUDIT) >> law
        # Layout only: the legend goes under the proxy column, and Key Vault
        # and Log Analytics share the row above the VNet, so neither secondary
        # edge crosses the blocked path along the bottom.
        d.dot.edge(agent._id, "legend", style="invis")
        d.dot.edge(kv._id, law._id, style="invis", minlen="2")


if __name__ == "__main__":
    proxy()
    print(f"wrote {OUT / 'azure-proxy.png'}")
