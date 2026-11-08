"""Shared fixtures of the HaltSQL end-to-end suite (docs/testing.md#end-to-end-suite).

Every scenario runs the real haltsql CLI / haltsql-server / haltsql-proxy
binaries against the real services of test/e2e/compose.yaml. Nothing is mocked.

Conventions for scenario files (test_*.py):

* Each test file owns a sub-range of host ports in 17050-17099 for the
  haltsql-server/proxy processes it starts (stack services use 17000-17049).
* Names on shared services are unique per test: use ``unique_name("...")`` for
  Kafka topics, OpenSearch indexes, MinIO buckets, registry repositories and
  Postgres databases.
* Keys are generated at test time in a temporary directory; never commit one.

Skipping: ``HALTSQL_SKIP_DOCKER=1`` skips every test. A service that is not
reachable skips the tests that need it with the reason, unless
``HALTSQL_E2E_REQUIRE=1`` (set by ``make e2e`` and CI), which turns that into a
failure.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import signal
import string
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

import pytest
import requests

E2E_DIR = Path(__file__).resolve().parent
REPO = E2E_DIR.parent.parent
FIXTURES = E2E_DIR / "fixtures"
PROJECT = "haltsql-e2e"

# Stack endpoints (host side). Keep in sync with compose.yaml.
PG_PORT = 17000
KEYCLOAK_URL = "http://127.0.0.1:17001"
KEYCLOAK_REALM = "haltsql-e2e"
KEYCLOAK_ISSUER = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
KEYCLOAK_CLIENT_ID = "haltsql-agent"
KAFKA_BOOTSTRAP = "localhost:17002"
OPENSEARCH_URL = "http://127.0.0.1:17003"
OPA_URL = "http://127.0.0.1:17004"
REGISTRY = "localhost:17005"
REGISTRY_URL = "http://127.0.0.1:17005"
MINIO_URL = "http://127.0.0.1:17006"
MINIO_USER = "haltsql-e2e"


def _truthy(name: str) -> bool:
    return os.environ.get(name, "") == "1"


SKIP_DOCKER = _truthy("HALTSQL_SKIP_DOCKER")
REQUIRE = _truthy("HALTSQL_E2E_REQUIRE")


def unavailable(what: str) -> None:
    """Skip (or fail under HALTSQL_E2E_REQUIRE=1) because a service is missing."""
    msg = f"{what} (start the stack with `test/e2e/stack.sh up` or `make e2e`)"
    if REQUIRE:
        pytest.fail(f"HALTSQL_E2E_REQUIRE=1 but {msg}", pytrace=False)
    pytest.skip(msg)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if SKIP_DOCKER:
        marker = pytest.mark.skip(reason="HALTSQL_SKIP_DOCKER=1: the e2e suite needs Docker")
        for item in items:
            item.add_marker(marker)


# --------------------------------------------------------------------------
# Environment, binaries, names


def _read_env_file() -> dict[str, str]:
    path = Path(os.environ.get("HALTSQL_E2E_ENV_FILE", E2E_DIR / ".env"))
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


@pytest.fixture(scope="session")
def stack_env() -> dict[str, str]:
    """The generated secrets of the running stack (test/e2e/.env)."""
    env = _read_env_file()
    if "E2E_PG_PASSWORD" not in env:
        unavailable("test/e2e/.env is missing")
    return env


def _bin(var: str, rel: str) -> Path:
    override = os.environ.get(var)
    path = Path(override) if override else REPO / "_build" / "default" / rel
    if not path.is_file() or not os.access(path, os.X_OK):
        pytest.fail(
            f"{path} is not an executable; run `dune build` or set {var}", pytrace=False
        )
    return path


@pytest.fixture(scope="session")
def haltsql_bin() -> Path:
    return _bin("HALTSQL_BIN", "bin/haltsql/main.exe")


@pytest.fixture(scope="session")
def server_bin() -> Path:
    return _bin("HALTSQL_SERVER_BIN", "bin/server/main.exe")


@pytest.fixture(scope="session")
def proxy_bin() -> Path:
    return _bin("HALTSQL_PROXY_BIN", "bin/proxy/main.exe")


def unique_name(prefix: str) -> str:
    """A lower-case name that is unique per call: valid as a Kafka topic,
    OpenSearch index, S3 bucket, registry repository and Postgres database."""
    return f"{prefix}-{uuid.uuid4().hex[:10]}".lower()


def sha256_hex(s: str | bytes) -> str:
    return hashlib.sha256(s.encode() if isinstance(s, str) else s).hexdigest()


def new_token() -> str:
    return secrets.token_hex(24)


def render_policy(name: str, columns: list[str]) -> str:
    """The shop policy template (fixtures/policies/shop.yaml.tmpl)."""
    tmpl = string.Template((FIXTURES / "policies" / "shop.yaml.tmpl").read_text())
    return tmpl.substitute(NAME=name, COLUMNS=", ".join(columns))


def wait_until(what: str, pred: Callable[[], Any], timeout: float = 30.0, interval: float = 0.5) -> Any:
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while True:
        try:
            v = pred()
            if v:
                return v
        except Exception as e:  # noqa: BLE001 - reported on timeout
            last_exc = e
        if time.monotonic() > deadline:
            extra = f" (last error: {last_exc!r})" if last_exc else ""
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}{extra}")
        time.sleep(interval)


def _http_ok(url: str, timeout: float = 2.0) -> bool:
    try:
        return requests.get(url, timeout=timeout).status_code == 200
    except requests.RequestException:
        return False


def _service(name: str, url: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while not _http_ok(url):
        if time.monotonic() > deadline:
            unavailable(f"{name} is not reachable at {url}")
        time.sleep(1.0)


def docker(*args: str, check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
    )


def container(service: str) -> str:
    """Container name of a stack service (Compose v2 naming)."""
    return f"{PROJECT}-{service}-1"


# --------------------------------------------------------------------------
# Stack health


@pytest.fixture(scope="session")
def docker_available() -> None:
    try:
        docker("info", "--format", "{{.ServerVersion}}", timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        unavailable(f"Docker is not available: {e}")


@pytest.fixture(scope="session")
def registry(docker_available: None) -> str:
    """registry:2, plain HTTP on loopback. Returns the host:port for references."""
    _service("registry:2", f"{REGISTRY_URL}/v2/")
    return REGISTRY


@pytest.fixture(scope="session")
def opa(docker_available: None) -> str:
    _service("OPA", f"{OPA_URL}/health")
    return OPA_URL


@pytest.fixture(scope="session")
def opensearch(docker_available: None) -> str:
    _service("OpenSearch", f"{OPENSEARCH_URL}/_cluster/health?wait_for_status=yellow&timeout=5s", 120)
    return OPENSEARCH_URL


@pytest.fixture(scope="session")
def keycloak(docker_available: None, stack_env: dict[str, str]) -> "Keycloak":
    _service("Keycloak", f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration", 180)
    return Keycloak(stack_env["E2E_KC_CLIENT_SECRET"], stack_env["E2E_KC_USER_PASSWORD"])


@pytest.fixture(scope="session")
def minio(docker_available: None, stack_env: dict[str, str]) -> "Minio":
    _service("MinIO", f"{MINIO_URL}/minio/health/ready")
    return Minio(stack_env["E2E_MINIO_ROOT_PASSWORD"])


@pytest.fixture(scope="session")
def kafka(docker_available: None) -> "Kafka":
    k = Kafka()
    deadline = time.monotonic() + 90
    while True:
        try:
            k.admin().close()
            return k
        except Exception as e:  # noqa: BLE001
            if time.monotonic() > deadline:
                unavailable(f"Kafka is not reachable at {KAFKA_BOOTSTRAP}: {e}")
            time.sleep(1.0)


@pytest.fixture(scope="session")
def postgres(docker_available: None, stack_env: dict[str, str]) -> "Postgres":
    pg = Postgres(stack_env["E2E_PG_PASSWORD"])
    deadline = time.monotonic() + 60
    while True:
        try:
            pg.connect("postgres").close()
            return pg
        except Exception as e:  # noqa: BLE001
            if time.monotonic() > deadline:
                unavailable(f"Postgres is not reachable on 127.0.0.1:{PG_PORT}: {e}")
            time.sleep(1.0)


# --------------------------------------------------------------------------
# haltsql CLI


@dataclass
class Cli:
    path: Path

    def run(self, *args: str | Path, check: bool = True, env: dict[str, str] | None = None,
            timeout: float = 120) -> subprocess.CompletedProcess[str]:
        """Run `haltsql ARGS`. With check=True a non-zero exit fails the test
        with the output."""
        full_env = {**os.environ, **(env or {})}
        p = subprocess.run(
            [str(self.path), *map(str, args)],
            capture_output=True, text=True, env=full_env, timeout=timeout,
        )
        if check and p.returncode != 0:
            pytest.fail(
                f"haltsql {' '.join(map(str, args))} exited {p.returncode}\n"
                f"stdout:\n{p.stdout}\nstderr:\n{p.stderr}",
                pytrace=False,
            )
        return p

    def json(self, *args: str | Path, check: bool = True) -> tuple[int, Any]:
        p = self.run(*args, "--json", check=check)
        try:
            return p.returncode, json.loads(p.stdout)
        except json.JSONDecodeError:
            pytest.fail(f"haltsql {' '.join(map(str, args))} --json printed no JSON:\n"
                        f"{p.stdout}\n{p.stderr}", pytrace=False)

    # ---- bundles ----

    def keygen(self, path: Path) -> str:
        """Generate an Ed25519 key pair (path, path.pub); returns the key id."""
        _, j = self.json("bundle", "keygen", "-o", path)
        return j["keyid"]

    def build_bundle(self, policies: list[Path], out: Path, *, name: str, version: str) -> Path:
        self.run("bundle", "build", *policies, "--name", name, "--bundle-version", version,
                 "-o", out)
        return out

    def sign(self, bundle: Path, key: Path) -> Path:
        self.run("bundle", "sign", bundle, "--key", key)
        return Path(f"{bundle}.sig")

    def push_oci(self, ref: str, bundle: Path, *, plain_http: bool = True,
                 public_keys: list[Path] = (), check: bool = True) -> tuple[int, dict[str, Any]]:
        """`haltsql bundle push --oci`; returns (exit code, JSON report). On
        success the report has `digest`, `pinned`, `bundle`, `bundle_digest`."""
        args: list[str | Path] = ["bundle", "push", "--oci", ref, bundle]
        if plain_http:
            args.append("--plain-http")
        for k in public_keys:
            args += ["--public-key", k]
        return self.json(*args, check=check)


@pytest.fixture(scope="session")
def cli(haltsql_bin: Path) -> Cli:
    return Cli(haltsql_bin)


# --------------------------------------------------------------------------
# haltsql-server / haltsql-proxy processes


@dataclass
class Process:
    name: str
    port: int
    proc: subprocess.Popen[bytes]
    log_path: Path
    workdir: Path

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def log(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except OSError:
            return ""

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)

    # ---- HTTP helpers (haltsql-server) ----

    def get(self, path: str, token: str | None = None, **kw: Any) -> requests.Response:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return requests.get(self.base + path, headers=headers, timeout=10, **kw)

    def verify(self, sql: str, token: str | None = None, context: dict[str, Any] | None = None,
               policy: str | None = None) -> dict[str, Any]:
        """POST /v1/verify; returns the verdict (fails the test on a non-200)."""
        body: dict[str, Any] = {"sql": sql, "context": context or {}}
        if policy is not None:
            body["policy"] = policy
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.post(self.base + "/v1/verify", json=body, headers=headers, timeout=10)
        assert r.status_code == 200, f"/v1/verify -> {r.status_code}: {r.text}"
        return r.json()

    def admin_status(self, token: str) -> dict[str, Any]:
        r = self.get("/v1/admin/status", token)
        assert r.status_code == 200, f"/v1/admin/status -> {r.status_code}: {r.text}"
        return r.json()


def reason_codes(verdict: dict[str, Any]) -> list[str]:
    return [r["code"] for r in verdict.get("reasons", [])]


class Processes:
    """Starts haltsql-server / haltsql-proxy processes for one test and stops
    them all at teardown."""

    def __init__(self, server_bin: Path, proxy_bin_lazy: Callable[[], Path], tmp: Path):
        self._server_bin = server_bin
        self._proxy_bin = proxy_bin_lazy
        self._tmp = tmp
        self._procs: list[Process] = []

    def _spawn(self, name: str, argv: list[str], port: int, workdir: Path,
               env: dict[str, str] | None) -> Process:
        log_path = workdir / f"{name}.log"
        logf = open(log_path, "wb")  # noqa: SIM115 - closed with the process
        proc = subprocess.Popen(
            argv, stdout=logf, stderr=subprocess.STDOUT, cwd=workdir,
            env={**os.environ, **(env or {})},
        )
        logf.close()
        p = Process(name, port, proc, log_path, workdir)
        self._procs.append(p)
        return p

    def server(self, config: str, port: int, *, name: str = "haltsql-server",
               env: dict[str, str] | None = None, wait_ready: bool = True,
               ready_timeout: float = 60.0) -> Process:
        """Write CONFIG (YAML text; must listen on 127.0.0.1:PORT) and start
        haltsql-server with it. Waits until /readyz is 200 unless wait_ready=False."""
        workdir = self._tmp / f"{name}-{port}"
        workdir.mkdir(parents=True, exist_ok=True)
        cfg = workdir / "config.yaml"
        cfg.write_text(config)
        p = self._spawn(name, [str(self._server_bin), "--config", str(cfg)], port, workdir, env)
        if wait_ready:
            self.wait_ready(p, ready_timeout)
        return p

    def proxy(self, args: list[str], port: int, *, name: str = "haltsql-proxy",
              env: dict[str, str] | None = None) -> Process:
        """Start haltsql-proxy with ARGS (the caller waits for its listener)."""
        workdir = self._tmp / f"{name}-{port}"
        workdir.mkdir(parents=True, exist_ok=True)
        return self._spawn(name, [str(self._proxy_bin()), *args], port, workdir, env)

    @staticmethod
    def wait_ready(p: Process, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if not p.alive():
                pytest.fail(f"{p.name} exited with {p.proc.returncode} before it was ready:\n"
                            f"{p.log()}", pytrace=False)
            if _http_ok(p.base + "/readyz", timeout=1.0):
                return
            if time.monotonic() > deadline:
                pytest.fail(f"{p.name} not ready on {p.base}/readyz after {timeout:.0f}s:\n"
                            f"{p.log()}", pytrace=False)
            time.sleep(0.25)

    @staticmethod
    def wait_exit(p: Process, timeout: float = 60.0) -> int:
        try:
            return p.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pytest.fail(f"{p.name} still running after {timeout:.0f}s:\n{p.log()}", pytrace=False)

    def stop_all(self) -> None:
        for p in reversed(self._procs):
            p.stop()


@pytest.fixture
def processes(server_bin: Path, request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Processes]:
    procs = Processes(server_bin, lambda: request.getfixturevalue("proxy_bin"), tmp_path)
    try:
        yield procs
    finally:
        procs.stop_all()


# --------------------------------------------------------------------------
# registry:2


def registry_manifest(ref: str) -> tuple[str, dict[str, Any]]:
    """GET the OCI manifest REF (`localhost:17005/repo:tag`) straight from
    registry:2. Returns (digest, manifest)."""
    m = re.fullmatch(re.escape(REGISTRY) + r"/([^:@]+)[:@](.+)", ref)
    assert m, f"not a reference on the e2e registry: {ref}"
    r = requests.get(
        f"{REGISTRY_URL}/v2/{m.group(1)}/manifests/{m.group(2)}",
        headers={"Accept": "application/vnd.oci.image.manifest.v1+json"}, timeout=10,
    )
    assert r.status_code == 200, f"registry manifest {ref} -> {r.status_code}: {r.text}"
    return r.headers["Docker-Content-Digest"], r.json()


# --------------------------------------------------------------------------
# Keycloak


@dataclass
class Keycloak:
    client_secret: str
    user_password: str
    issuer: str = KEYCLOAK_ISSUER
    client_id: str = KEYCLOAK_CLIENT_ID

    def _token(self, form: dict[str, str]) -> str:
        r = requests.post(f"{self.issuer}/protocol/openid-connect/token",
                          data={"client_id": self.client_id,
                                "client_secret": self.client_secret, **form}, timeout=15)
        assert r.status_code == 200, f"Keycloak token -> {r.status_code}: {r.text}"
        return r.json()["access_token"]

    def client_token(self) -> str:
        """Client-credentials token of the haltsql-agent service account (group support)."""
        return self._token({"grant_type": "client_credentials"})

    def user_token(self, username: str) -> str:
        """Password-grant token for a realm user (alice: support, bob: finance)."""
        return self._token({"grant_type": "password", "username": username,
                            "password": self.user_password, "scope": "openid"})

    @staticmethod
    def claims(token: str) -> dict[str, Any]:
        """Decode (without verifying) the JWT payload, for assertions only."""
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


# --------------------------------------------------------------------------
# Kafka


class Kafka:
    bootstrap = KAFKA_BOOTSTRAP

    def admin(self) -> Any:
        from kafka import KafkaAdminClient

        return KafkaAdminClient(bootstrap_servers=self.bootstrap, request_timeout_ms=10000)

    def create_topic(self, name: str, partitions: int = 1) -> str:
        from kafka.admin import NewTopic

        a = self.admin()
        try:
            a.create_topics([NewTopic(name, num_partitions=partitions, replication_factor=1)])
        finally:
            a.close()
        return name

    def delete_topic(self, name: str) -> None:
        a = self.admin()
        try:
            a.delete_topics([name])
        finally:
            a.close()

    def consume(self, topic: str, *, min_messages: int = 1, timeout: float = 30.0) -> list[Any]:
        """Read TOPIC from the beginning until at least MIN_MESSAGES records
        arrived (or TIMEOUT). Returns the kafka-python ConsumerRecords."""
        from kafka import KafkaConsumer

        c = KafkaConsumer(topic, bootstrap_servers=self.bootstrap, auto_offset_reset="earliest",
                          enable_auto_commit=False, group_id=None, consumer_timeout_ms=1000)
        out: list[Any] = []
        deadline = time.monotonic() + timeout
        try:
            while len(out) < min_messages and time.monotonic() < deadline:
                for rec in c:
                    out.append(rec)
                    if len(out) >= min_messages:
                        break
        finally:
            c.close()
        return out


# --------------------------------------------------------------------------
# OpenSearch


class OpenSearch:
    url = OPENSEARCH_URL

    def search(self, index: str, query: dict[str, Any] | None = None, size: int = 1000) -> list[dict[str, Any]]:
        """Refresh INDEX and return the _source of matching documents."""
        requests.post(f"{self.url}/{index}/_refresh", timeout=10)
        r = requests.post(f"{self.url}/{index}/_search",
                          json={"query": query or {"match_all": {}}, "size": size}, timeout=10)
        if r.status_code == 404:
            return []
        assert r.status_code == 200, f"OpenSearch search {index} -> {r.status_code}: {r.text}"
        return [h["_source"] for h in r.json()["hits"]["hits"]]

    def wait_for(self, index: str, count: int, timeout: float = 30.0,
                 query: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return wait_until(f"{count} documents in OpenSearch index {index}",
                          lambda: (d := self.search(index, query)) and len(d) >= count and d,
                          timeout=timeout)

    def delete_index(self, index: str) -> None:
        requests.delete(f"{self.url}/{index}", timeout=10)


@pytest.fixture(scope="session")
def opensearch_client(opensearch: str) -> OpenSearch:
    return OpenSearch()


# --------------------------------------------------------------------------
# MinIO (driven with the server's own `mc`, inside the MinIO container)


@dataclass
class Minio:
    password: str
    user: str = MINIO_USER
    endpoint: str = MINIO_URL

    def mc(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run `mc ARGS` in the MinIO container against the alias `e2e`. The
        credentials reach the container through the environment of the docker
        CLI (`-e NAME` without a value), never through argv."""
        env = {**os.environ,
               "MC_HOST_e2e": f"http://{self.user}:{self.password}@127.0.0.1:9000"}
        return subprocess.run(
            ["docker", "exec", "-e", "MC_HOST_e2e", container("minio"), "mc", *args],
            capture_output=True, text=True, check=check, timeout=60, env=env,
        )

    def make_bucket(self, name: str) -> str:
        self.mc("mb", f"e2e/{name}")
        return name

    def remove_bucket(self, name: str) -> None:
        self.mc("rb", "--force", f"e2e/{name}", check=False)

    def credentials_env(self) -> dict[str, str]:
        """AWS_* variables for a haltsql process using `credentials: {source: env}`."""
        return {"AWS_ACCESS_KEY_ID": self.user, "AWS_SECRET_ACCESS_KEY": self.password,
                "AWS_REGION": "us-east-1"}


# --------------------------------------------------------------------------
# OPA


def opa_put_policy(policy_id: str, rego: str) -> None:
    r = requests.put(f"{OPA_URL}/v1/policies/{policy_id}", data=rego.encode(),
                     headers={"Content-Type": "text/plain"}, timeout=10)
    assert r.status_code == 200, f"OPA PUT policy {policy_id} -> {r.status_code}: {r.text}"


def opa_delete_policy(policy_id: str) -> None:
    requests.delete(f"{OPA_URL}/v1/policies/{policy_id}", timeout=10)


def opa_decision_logs(since: str | None = None) -> list[dict[str, Any]]:
    """The decision log entries OPA printed (docker logs of the OPA service):
    exactly the input HaltSQL sent and the result OPA returned."""
    args = ["logs"] + (["--since", since] if since else []) + [container("opa")]
    p = docker(*args)
    out = []
    for line in (p.stdout + p.stderr).splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if j.get("msg") == "Decision Log":
            out.append(j)
    return out


# --------------------------------------------------------------------------
# Postgres


@dataclass
class Postgres:
    password: str
    host: str = "127.0.0.1"
    port: int = PG_PORT
    user: str = "postgres"

    def dsn(self, dbname: str) -> str:
        return (f"host={self.host} port={self.port} user={self.user} "
                f"password={self.password} dbname={dbname} connect_timeout=5")

    def connect(self, dbname: str) -> Any:
        import psycopg

        return psycopg.connect(self.dsn(dbname), autocommit=True)


@pytest.fixture
def pg_database(postgres: Postgres) -> Iterator[str]:
    """A fresh, uniquely named database, dropped after the test."""
    from psycopg import sql

    name = unique_name("haltsql_e2e").replace("-", "_")
    with postgres.connect("postgres") as c:
        c.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield name
    finally:
        with postgres.connect("postgres") as c:
            c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))


# --------------------------------------------------------------------------
# Keycloak admin API (per-test realms)


class KeycloakAdmin:
    """Keycloak's admin REST API, for tests that need their own realm (users
    with attributes, extra groups) instead of the shared haltsql-e2e realm.
    The admin password comes from test/e2e/.env and is never logged."""

    def __init__(self, admin_password: str, base: str = KEYCLOAK_URL):
        self.base = base
        self._password = admin_password

    def _token(self) -> str:
        r = requests.post(f"{self.base}/realms/master/protocol/openid-connect/token",
                          data={"grant_type": "password", "client_id": "admin-cli",
                                "username": "admin", "password": self._password}, timeout=15)
        assert r.status_code == 200, f"Keycloak admin token -> {r.status_code}"
        return r.json()["access_token"]

    def call(self, method: str, path: str, *, json_body: Any = None,
             expect: tuple[int, ...] = (200, 201, 204)) -> requests.Response:
        r = requests.request(method, f"{self.base}/admin/realms{path}", json=json_body,
                             headers={"Authorization": f"Bearer {self._token()}"}, timeout=30)
        assert r.status_code in expect, f"Keycloak admin {method} {path} -> {r.status_code}: {r.text[:300]}"
        return r

    def create_realm(self, realm: str, *, unmanaged_attributes: bool = True) -> str:
        """Create REALM; with UNMANAGED_ATTRIBUTES the declarative user
        profile keeps arbitrary user attributes (Keycloak 26 drops them by
        default), so attribute mappers can put them into tokens."""
        self.call("POST", "", json_body={"realm": realm, "enabled": True, "sslRequired": "none",
                                          "accessTokenLifespan": 600})
        if unmanaged_attributes:
            profile = self.call("GET", f"/{realm}/users/profile").json()
            profile["unmanagedAttributePolicy"] = "ENABLED"
            self.call("PUT", f"/{realm}/users/profile", json_body=profile)
        return realm

    def delete_realm(self, realm: str) -> None:
        self.call("DELETE", f"/{realm}", expect=(204, 404))

    def create_group(self, realm: str, name: str) -> None:
        self.call("POST", f"/{realm}/groups", json_body={"name": name})

    def create_client(self, realm: str, client_id: str, secret: str,
                      mappers: list[dict[str, Any]]) -> None:
        self.call("POST", f"/{realm}/clients", json_body={
            "clientId": client_id, "enabled": True, "protocol": "openid-connect",
            "publicClient": False, "clientAuthenticatorType": "client-secret",
            "secret": secret, "standardFlowEnabled": False,
            "directAccessGrantsEnabled": True, "serviceAccountsEnabled": False,
            "fullScopeAllowed": True, "protocolMappers": mappers})

    def create_user(self, realm: str, username: str, password: str, *,
                    groups: list[str] = (), attributes: dict[str, list[str]] | None = None) -> None:
        self.call("POST", f"/{realm}/users", json_body={
            "username": username, "enabled": True, "emailVerified": True,
            "email": f"{username}@e2e.haltsql.invalid", "firstName": username.title(),
            "lastName": "E2e", "groups": [f"/{g}" for g in groups],
            "attributes": attributes or {}, "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}]})

    def password_token(self, realm: str, client_id: str, secret: str, username: str,
                       password: str) -> str:
        r = requests.post(f"{self.base}/realms/{realm}/protocol/openid-connect/token",
                          data={"grant_type": "password", "client_id": client_id,
                                "client_secret": secret, "username": username,
                                "password": password, "scope": "openid"}, timeout=15)
        assert r.status_code == 200, f"Keycloak token for {username} -> {r.status_code}: {r.text[:300]}"
        return r.json()["access_token"]


@pytest.fixture(scope="session")
def keycloak_admin(keycloak: Keycloak, stack_env: dict[str, str]) -> KeycloakAdmin:
    if "E2E_KC_ADMIN_PASSWORD" not in stack_env:
        unavailable("test/e2e/.env has no E2E_KC_ADMIN_PASSWORD")
    return KeycloakAdmin(stack_env["E2E_KC_ADMIN_PASSWORD"])


def pg_exec_exact(conn: Any, sql_text: str, bind_params: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """Run exactly SQL_TEXT (no client-side rewriting) on the psycopg
    connection CONN with the verdict's bind_params as server-side parameters
    ($n, all text). Returns the rows as tuples of str/None."""
    from psycopg import pq

    by_param = {b["param"]: b["value"] for b in bind_params}
    values: list[bytes | None] = []
    for n in range(1, len(by_param) + 1):
        v = by_param[n]
        if isinstance(v, list):
            v = "{" + ",".join('"' + x.replace("\\", "\\\\").replace('"', '\\"') + '"' for x in v) + "}"
        values.append(str(v).encode())
    res = conn.pgconn.exec_params(sql_text.encode(), values)
    if res.status not in (pq.ExecStatus.TUPLES_OK, pq.ExecStatus.COMMAND_OK):
        raise AssertionError(f"Postgres error: {res.error_message.decode(errors='replace')}")
    rows = []
    for i in range(res.ntuples):
        rows.append(tuple(None if res.get_value(i, j) is None else res.get_value(i, j).decode()
                          for j in range(res.nfields)))
    return rows


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
