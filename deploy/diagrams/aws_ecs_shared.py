"""AWS reference architecture C for HaltSQL (docs/deploy-aws.md): ECS Fargate
shared service behind an internal ALB.

Drawn with mingrammer/diagrams. Run from anywhere:

    deploy/diagrams/.venv/bin/python deploy/diagrams/aws_ecs_shared.py    # or: make diagrams

Writes docs/assets/cloud/aws-ecs-shared.png. Paths are resolved from this
file's location.
"""

import os

from diagrams import Cluster, Diagram, Node, getdiagram
from diagrams.aws.compute import ElasticContainerServiceContainer, Fargate
from diagrams.aws.database import Aurora
from diagrams.aws.devtools import XRay
from diagrams.aws.management import AmazonManagedPrometheus, CloudwatchLogs
from diagrams.aws.network import ALB
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
    # Local spacing: tighter than the shared default so the figure fits a
    # docs page, but with room between ranks for the edge labels.
    "nodesep": "0.8",
    "ranksep": "1.3",
    "newrank": "true",
    "compound": "true",
}
NODE = {"fontname": "Helvetica", "fontsize": "12"}
EDGE = {"fontname": "Helvetica", "fontsize": "11"}

# Edge styles: the request and SQL paths are thick; logs and telemetry are
# thin so the verify -> SQL path stands out. One colour per flow type.
REQ = "#1f2937"
SQL = "#047857"
AUDIT = "#b45309"
TEL = "#7c3aed"


def out(name):
    return os.path.join(OUT, name)


def box(label):
    """Node attributes that fit the box to the icon plus its label.

    diagrams makes every node box much taller than its icon, and orthogonal
    edges may attach anywhere on the box, so lines start or end in empty
    space above or below an icon. Pinning the icon to the top of a box that
    is only as tall as icon + label keeps edge ends on or next to the icon.
    """
    lines = label.count("\n") + 1
    return {"imagepos": "tc", "height": str(round(1.5 + 0.22 * lines, 2))}


def junction(color, **attrs):
    """A dot where parallel edges merge into one (or fan out from one)."""
    return Node("", shape="point", width="0.08", height="0.08",
                fixedsize="true", color=color, fillcolor=color, **attrs)


def same_rank(*nodes):
    """Pin nodes to one rank (one column in an LR layout)."""
    ids = "; ".join(f'"{n._id}"' for n in nodes)
    getdiagram().dot.body.append(f"{{rank=same; {ids}}}")


def node(cls, label, **attrs):
    """An icon node sized with box()."""
    return cls(label, **box(label), **attrs)


# Service and task titles sit on the right, clear of the awslogs edge that
# leaves the service box through the top, above haltsql-server.
TASK = {"labeljust": "r"}
SERVICE = "ECS service: haltsql (2+ tasks per AZ)"
SERVICE_CLUSTER = "cluster_" + SERVICE


with Diagram(
    "HaltSQL on Amazon ECS (Fargate): shared service",
    filename=out("aws-ecs-shared"),
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=GRAPH,
    node_attr=NODE,
    edge_attr=EDGE,
):
    with Cluster("AWS region"):
        with Cluster("VPC"):
            agents = node(ElasticContainerServiceContainer,
                          "LLM agents\nEKS, ECS, EC2,\nLambda (in VPC)\nBearer / OIDC token", group="req")
            alb = node(ALB, "internal ALB\nHTTPS :443 (ACM)", group="req")
            alb_j = junction(REQ)

            with Cluster("Private subnets: database (Multi-AZ)"):
                db = node(Aurora, "Aurora PostgreSQL")

            # One box for the service lets the awslogs edge start at the
            # service (ltail) instead of threading out of each task.
            with Cluster(SERVICE, graph_attr=TASK):
                with Cluster("AZ b, private subnet: Fargate task", graph_attr=TASK):
                    hs_b = node(Fargate, "haltsql-server\nHTTPS :8443 (TLS)")
                    otel_b = node(ElasticContainerServiceContainer, "ADOT sidecar\nOTLP :4318", group="tel_b")
                with Cluster("AZ a, private subnet: Fargate task", graph_attr=TASK):
                    hs_a = node(Fargate, "haltsql-server\nHTTPS :8443 (TLS)")
                    otel_a = node(ElasticContainerServiceContainer, "ADOT sidecar\nOTLP :4318", group="tel_a")
            # Telemetry bus: a dot level with each sidecar, joined by one
            # vertical line, so both sidecars visibly feed both backends.
            tel_b = junction(TEL, group="tel_b")
            tel_a = junction(TEL, group="tel_a")

        # Extra margin: the Secrets Manager label is wider than its icon box.
        with Cluster("Regional services", graph_attr={"margin": "20"}):
            xray = node(XRay, "X-Ray (traces)", group="tel_b")
            cwl = node(CloudwatchLogs, "CloudWatch Logs (awslogs)\naudit (stdout) + logs")
            amp = node(AmazonManagedPrometheus, "Amazon Managed\nPrometheus (metrics)", group="tel_a")
            sm = node(SecretsManager,
                      "Secrets Manager\ntoken hashes, TLS key\n(injected as env vars\nby the execution role)")

    same_rank(db, alb)
    same_rank(hs_a, hs_b)
    same_rank(otel_a, otel_b)
    same_rank(tel_a, tel_b)
    same_rank(xray, cwl, amp)

    # Primary flows. The agents -> database edge bends, and orthogonal
    # routing cannot place an ordinary label on a bent edge, so it uses an
    # xlabel (placed after routing) in the edge's colour.
    agents >> Edge(label="POST /v1/verify", color=REQ, fontcolor=REQ, penwidth="2") >> alb
    alb >> Edge(label="HTTPS :8443, health /readyz", color=REQ, fontcolor=REQ, penwidth="2",
                arrowhead="none") >> alb_j
    alb_j >> Edge(color=REQ, penwidth="2") >> hs_a
    alb_j >> Edge(color=REQ, penwidth="2") >> hs_b
    agents >> Edge(xlabel="verified SQL only, TLS :5432", color=SQL, fontcolor=SQL, penwidth="2") >> db

    # Logs and audit: awslogs (blocking) from every task's stdout/stderr,
    # drawn once from the service box rather than once per task.
    hs_a >> Edge(color=AUDIT, ltail=SERVICE_CLUSTER) >> cwl

    # Layout only: Secrets Manager has no edge (ECS, not HaltSQL, reads it),
    # so park it beside CloudWatch instead of lengthening the column.
    cwl >> Edge(style="invis") >> sm

    # Telemetry: OTLP from each server to its own sidecar; both sidecars
    # export traces to X-Ray and metrics to AMP.
    hs_b >> Edge(color=TEL) >> otel_b
    hs_a >> Edge(color=TEL) >> otel_a
    otel_b >> Edge(color=TEL, arrowhead="none") >> tel_b
    otel_a >> Edge(color=TEL, arrowhead="none") >> tel_a
    tel_b >> Edge(color=TEL, arrowhead="none") >> tel_a
    tel_b >> Edge(color=TEL) >> xray
    tel_a >> Edge(color=TEL) >> amp
