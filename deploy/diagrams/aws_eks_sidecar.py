"""AWS reference architecture for HaltSQL: EKS sidecar (docs/deploy-aws.md, pattern A).

Drawn with mingrammer/diagrams. Run from anywhere:

    deploy/diagrams/.venv/bin/python deploy/diagrams/aws_eks_sidecar.py    # or: make diagrams

Writes docs/assets/cloud/aws-eks-sidecar.png. Paths are resolved from this
file's location.

Layout. The pod row runs left to right through the middle: agent -> haltsql
sidecar (1, verify) -> ADOT collector -> X-Ray. Aurora sits above it, reached
only by the agent (2, verified SQL). The sidecar's AWS calls drop below the pod
row into the VPC endpoints, each lined up with the regional service it reaches.

Graphviz's orthogonal router places labels before it routes lines, so only
straight edges carry labels; the API call each endpoint carries is part of the
endpoint's own label. Weighted edges keep each endpoint -> service line, and
ADOT -> X-Ray, straight.
"""

import os

from diagrams import Cluster, Diagram
from diagrams import Edge as RawEdge
from diagrams.aws.compute import ElasticContainerServiceContainer
from diagrams.aws.database import Aurora
from diagrams.aws.devtools import XRay
from diagrams.aws.management import AmazonManagedPrometheus
from diagrams.aws.network import Endpoint
from diagrams.aws.security import IAMRole, SecretsManager
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.k8s.compute import Pod

from _style import ORTHO, Edge  # shared orthogonal-edge style

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "docs", "assets", "cloud")
os.makedirs(OUT, exist_ok=True)

GRAPH = {
    "fontsize": "22",
    "fontname": "Helvetica",
    "pad": "0.4",
    **ORTHO,  # right-angle edges
    "nodesep": "0.45",
    "ranksep": "1.7",
    "newrank": "true",
}
NODE = {"fontname": "Helvetica", "fontsize": "12"}
EDGE = {"fontname": "Helvetica", "fontsize": "11"}

# Edge styles: the request path is solid and dark; control-plane and
# telemetry traffic is lighter so the verify -> SQL path stands out.
REQ = "#1f2937"
SQL = "#047857"
AUDIT = "#b45309"
CTRL = "#6b7280"
TEL = "#7c3aed"

# Lines leave the pod upwards (to Aurora) and drop into the VPC endpoints from
# above, so every group carries its title bottom-left, clear of the lines.
TITLE_BOTTOM = {"labelloc": "b"}


with Diagram(
    "HaltSQL on Amazon EKS: sidecar pattern",
    filename=os.path.join(OUT, "aws-eks-sidecar"),
    outformat="png",
    show=False,
    direction="LR",
    graph_attr=GRAPH,
    node_attr=NODE,
    edge_attr=EDGE,
):
    # Declaration order steers the row order Graphviz picks: this order puts
    # the pod row above the VPC endpoints and sts above s3.
    with Cluster("AWS region", graph_attr=TITLE_BOTTOM):
        with Cluster("VPC", graph_attr=TITLE_BOTTOM):
            with Cluster("VPC endpoints", graph_attr=TITLE_BOTTOM):
                ep_s3 = Endpoint("s3 (gateway)\nPutObject: audit batches")
                ep_sm = Endpoint("secretsmanager (interface)\nGetSecretValue")
                ep_sts = Endpoint("sts (interface)\nAssumeRoleWithWebIdentity")

            with Cluster("Private subnets: database", graph_attr=TITLE_BOTTOM):
                db = Aurora("Aurora PostgreSQL\n(restricted role + RLS)")

            with Cluster("Private subnets: EKS worker nodes", graph_attr=TITLE_BOTTOM):
                with Cluster("Agent pod (IRSA ServiceAccount)", graph_attr=TITLE_BOTTOM):
                    agent = ElasticContainerServiceContainer("agent container")
                    hs = ElasticContainerServiceContainer("haltsql-server\nsidecar")
                adot = Pod("ADOT collector")

        with Cluster("Observability", graph_attr=TITLE_BOTTOM):
            amp = AmazonManagedPrometheus("Managed Prometheus")
            xray = XRay("AWS X-Ray")

        with Cluster("Regional services", graph_attr=TITLE_BOTTOM):
            audit = SimpleStorageServiceS3Bucket("S3 audit bucket\nObject Lock, SSE-KMS")
            sm = SecretsManager("Secrets Manager\ntoken hashes (KMS CMK)")
            role = IAMRole("IRSA role\nhaltsql-audit")

    # Primary path: verify in the pod, then only verified SQL reaches Aurora.
    # The agent -> Aurora line bends, and Graphviz parks its label just below
    # the final horizontal run, so this one label is padded on top (plain
    # diagrams Edge) to sit under the line instead of across it.
    agent >> RawEdge(label="\n\n2  verified SQL only\nTLS :5432", color=SQL,
                     penwidth="2.5") >> db
    agent >> Edge(label="1  POST /v1/verify\n127.0.0.1:8080", color=REQ,
                  penwidth="2") >> hs

    # Telemetry: sidecar -> ADOT collector -> X-Ray / Amazon Managed Prometheus.
    # Observability is its own column so X-Ray can line up with ADOT.
    hs >> Edge(label="OTLP/HTTP :4318", color=TEL) >> adot
    adot >> Edge(color=TEL, minlen="2", weight="40") >> xray
    adot >> Edge(color=TEL, minlen="2") >> amp

    # Sidecar -> AWS APIs through the VPC endpoints, with IRSA credentials.
    hs >> Edge(color=CTRL, style="dashed") >> ep_sts
    hs >> Edge(color=CTRL, style="dashed") >> ep_sm
    hs >> Edge(color=AUDIT) >> ep_s3
    ep_sts >> Edge(color=CTRL, style="dashed", weight="40") >> role
    ep_sm >> Edge(color=CTRL, style="dashed", weight="40") >> sm
    ep_s3 >> Edge(color=AUDIT, weight="40") >> audit
