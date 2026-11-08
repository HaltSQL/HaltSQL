"""AWS pattern D: haltsql-proxy in front of RDS (docs/deploy-aws.md).

Drawn with mingrammer/diagrams. Run from the repo root:

    deploy/diagrams/.venv/bin/python deploy/diagrams/aws_proxy_rds.py   # or: make diagrams

Writes docs/assets/cloud/aws-proxy-rds.png. Paths are resolved from this
file's location.

Layout (columns are Graphviz ranks, left to right):

    clients | NLB | Secrets Manager / haltsql-proxy | CloudWatch Logs / RDS / refused

The request path is one row. The regional services sit in a row above the
VPC, so the secrets and audit edges are short and never cross the request
path. A direct client connection runs underneath and ends at a "direct
connection refused" box inside the database security group.
"""

import os

from diagrams import Cluster, Diagram, Node
from diagrams.aws.compute import ElasticContainerServiceContainer, Fargate
from diagrams.aws.database import RDSPostgresqlInstance
from diagrams.aws.management import CloudwatchLogs
from diagrams.aws.network import NLB
from diagrams.aws.security import SecretsManager

from _style import ORTHO, Edge  # shared orthogonal-edge style

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "assets", "cloud")
os.makedirs(OUT, exist_ok=True)

GRAPH = {
    "fontsize": "22",
    "fontname": "Helvetica",
    "pad": "0.4",
    **ORTHO,  # right-angle edges
    "nodesep": "0.9",
    "ranksep": "1.6",
}
NODE = {"fontname": "Helvetica", "fontsize": "12"}
EDGE = {"fontname": "Helvetica", "fontsize": "11"}

# Edge colours, one per flow type.
REQ = "#1f2937"  # client request path
SQL = "#047857"  # verified SQL to the database
AUDIT = "#b45309"  # audit / logs
CTRL = "#6b7280"  # control plane (secrets)
DENY = "#dc2626"  # path that does not exist


def fit(label, top=False):
    """Node attrs that make the node box hug its icon and label.

    By default diagrams centres the icon in a box that also holds the label,
    leaving empty space above the icon, so an edge entering from above stops
    short of it. Pinning the icon to one end and sizing the box to icon plus
    label makes edges meet the icon itself. With top=True the label goes
    above the icon (used for the services above the VPC, whose edges leave
    from the bottom).
    """
    lines = label.count("\n") + 1
    return {
        "height": str(round(1.4 + 0.1 + 0.2 * lines, 2)),
        "imagepos": "bc" if top else "tc",
        "labelloc": "t" if top else "b",
    }


with Diagram(
    "HaltSQL proxy in front of Amazon RDS for PostgreSQL",
    filename=os.path.join(OUT, "aws-proxy-rds"),
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=GRAPH,
    node_attr=NODE,
    edge_attr=EDGE,
):
    with Cluster("AWS region"):
        with Cluster("VPC  (private subnets in 2 AZs)"):
            # Only the database security group is drawn as a box: it is the
            # boundary that leaves clients no route around the proxy. The
            # other security groups are named in the node labels.
            t = "clients\nagents, BI tools, any driver\n(SG: clients)"
            clients = ElasticContainerServiceContainer(t, group="main", **fit(t))
            t = "internal NLB\nTCP :6432\n(TLS passthrough)"
            nlb = NLB(t, group="main", **fit(t))
            t = "haltsql-proxy\nFargate tasks, AZ a + AZ b\n(SG: haltsql-proxy)"
            proxy = Fargate(t, group="main", **fit(t))

            with Cluster(
                "SG: database  (5432 from SG haltsql-proxy only)",
                graph_attr={"labelloc": "b"},
            ):
                # Where a direct client connection ends.
                denied = Node(
                    "direct connection refused\n(no rule for SG clients)",
                    shape="box",
                    style="rounded,dashed",
                    color=DENY,
                    fontcolor=DENY,
                    width="2.6",
                    height="0.9",
                    labelloc="c",
                )
                t = "RDS for PostgreSQL\nMulti-AZ\n(SG: database)"
                rds = RDSPostgresqlInstance(t, group="main", **fit(t))

        # Regional services, outside the VPC.
        t = "Secrets Manager\nupstream password, TLS key\n(env vars at task start)"
        sm = SecretsManager(t, **fit(t, top=True))
        t = "CloudWatch Logs\nper-statement audit (stdout)"
        cwl = CloudwatchLogs(t, **fit(t, top=True))

    # Request path.
    clients >> Edge(label="Postgres wire, TLS\nSCRAM or client cert", color=REQ, penwidth="1.5") >> nlb
    nlb >> Edge(label="TCP", color=REQ, penwidth="1.5") >> proxy
    proxy >> Edge(label="verified SQL\nTLS verify-full :5432", color=SQL, penwidth="2.2") >> rds

    # The bypass that does not exist. It is unlabelled: the box it ends at
    # says what happens. minlen puts that box in the database column.
    clients >> Edge(color=DENY, style="dashed", minlen="3", weight="0") >> denied

    # Secondary flows: Secrets Manager straight above the proxy (same column),
    # CloudWatch Logs above RDS.
    sm >> Edge(color=CTRL, style="dashed", constraint="false") >> proxy
    proxy >> Edge(color=AUDIT) >> cwl
    nlb >> Edge(style="invis") >> sm
    # Mirrors the Secrets Manager -> proxy edge in the database column, so RDS
    # gets the same vertical offset as the proxy and the SQL edge stays level.
    cwl >> Edge(style="invis", constraint="false") >> rds
