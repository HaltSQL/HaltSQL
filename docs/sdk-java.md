# Java SDK

`com.haltsql:haltsql-client` is a client for the [HTTP sidecar](http-api.md)
for Java 17+. It uses `java.net.http` and Jackson (`jackson-databind`), and
its JDBC helper needs only `java.sql` at compile time, with PgJDBC at runtime.

Source: [`clients/java`](../clients/java).

## Install

The Java SDK is not on Maven Central yet. Build it from the repository and
install it into your local Maven repository, then depend on it as usual:

```sh
git clone --branch v0.0.3 https://github.com/HaltSQL/HaltSQL
mvn -f HaltSQL/clients/java/pom.xml install -DskipTests
```

```xml
<dependency>
  <groupId>com.haltsql</groupId>
  <artifactId>haltsql-client</artifactId>
  <version>0.0.3</version>
</dependency>
```

## Verify a query

```java
HaltSQLClient haltsql = HaltSQLClient.builder("http://127.0.0.1:8080")
    .token(System.getenv("HALTSQL_TOKEN"))   // pinned to one policy on the server
    .timeout(Duration.ofSeconds(2))
    .build();

Verdict v = haltsql.verify(
    "SELECT id, status FROM orders WHERE tenant_id = $1 LIMIT 50",
    Map.of("tenant_id", session.tenantId())); // from the session, never the prompt

if (!v.allowed()) {
  return deny(v.reasons()); // code(), message(), hint() for the agent
}
```

`verify` returns only for a strictly validated HTTP 200 body and otherwise
throws the checked `HaltSQLException`, so a failure can never be read as an
allow.

## Run it with JDBC (PgJDBC)

HaltSQL verifies SQL with PostgreSQL's own `$1, $2, ...` placeholders, but
JDBC uses `?`. PgJDBC does **not** understand `$n` in a `PreparedStatement`:
it would send the statement with zero parameters and the server rejects it.
And `preferQueryMode` does not change placeholder parsing.

`JdbcGuard` solves this without changing what runs:

1. It replaces each `$n` that is real code (not inside a string, quoted
   identifier, dollar-quoted string, or comment) with `?`.
2. PgJDBC rewrites each `?` back to `$1, $2, ...` in order before sending the
   query. So when the verified SQL uses its placeholders in textual order
   (`$1` then `$2`, each once), **the server receives the verified string byte
   for byte**. The test suite proves this against Postgres with
   `current_query()`.
3. If placeholders repeat or appear out of order (for example
   `JOIN c ON c.tenant_id = $2 WHERE o.tenant_id = $1`), each occurrence gets
   its own `?` bound to the right value. The server receives the verified
   statement with renumbered placeholders and identical values in identical
   positions. Call `requireByteIdenticalSql()` to refuse these instead.
4. Values are bound with `setObject(i, value, Types.OTHER)`: PgJDBC sends them
   with an unspecified type and the server infers it from the column, so a
   tenant id binds into `text`, `bigint` or `uuid` columns. A set (hierarchical
   tenants, `org_id = ANY($1)`) is bound as a Postgres array literal.

The translation fails closed (`HaltSQLException`, kind `USAGE`) on SQL it
cannot handle with certainty: any `?`, `{` or `}` character (PgJDBC treats
them as placeholders or JDBC escapes, even the `?` jsonb operators),
unterminated quotes or comments, and placeholders glued to identifier
characters. It also refuses any driver other than PgJDBC, and checks that the
SQL uses exactly the placeholders the verdict binds.

```java
JdbcGuard guard = new JdbcGuard(haltsql)
    .onVerdict(v -> audit.log(v.policy().version(), v.fingerprint(), v.allowed()));

try (Connection conn = dataSource.getConnection()) {
  List<Long> ids = guard.queryInTransaction(conn, sqlFromModel,
      Map.of("tenant_id", session.tenantId()),
      rs -> {                             // called inside the transaction
        List<Long> out = new ArrayList<>();
        while (rs.next()) out.add(rs.getLong(1));
        return out;
      });
} catch (HaltSQLDeniedException e) {
  return deny(e.verdict().reasons());   // nothing reached the database
}
```

`queryInTransaction` (and `updateInTransaction` for writes allowed by a write
policy) runs the verified SQL in a transaction on the connection you pass,
pinned to the policy's search path:

1. autocommit is turned off if it was on (PgJDBC then sends `BEGIN`);
2. `SET TRANSACTION READ ONLY` when the verdict's statement kind is `select`;
3. `SELECT set_config(name, value, true)` for each entry of
   `guard.transactionSettings(Map.of("app.tenant_id", tenantId))` (row-level
   security, `statement_timeout`, ...);
4. `SELECT set_config('search_path', ..., true)` with
   `verdict.policy().searchPath()`, each schema quoted as an identifier. This
   is the pin: the verified `orders` is the policy's `orders` whatever the
   role's or the database's default search path is. It is applied last, so a
   `search_path` in the settings does not override it, and it is
   transaction-local, so the session's own search path is back afterwards;
5. the verified statement; your handler reads the `ResultSet`;
6. `commit()`, or `rollback()` on any error, including one your handler
   throws;
7. autocommit is turned back on if it was on.

A denial, a shadow would-deny or a HaltSQL error is thrown before any of this.
A verdict without a search path (an engine older than the field) still runs,
without step 4. The connection must have no transaction in progress: with
autocommit off, the guard's transaction is the connection's next one, it is
committed or rolled back as above, and autocommit stays off. A connection
that PgJDBC reports as inside a transaction is refused (`USAGE`), because the
guard's commit would also commit your earlier statements.

### `prepare`, `query`, `update`: one statement, no pin

`guard.prepare(conn, sql, context)` returns the verified, bound
`PreparedStatement` (you execute and close it); `guard.query(conn, sql,
context, handler)` and `guard.update(conn, sql, context, opts)` execute it as
one statement on the connection as it is. **These low-level forms do not pin
the search path** and do not touch the transaction. Use them only when one of
these holds:

- the session already uses the policy's search path: you set it on the
  connection (`currentSchema=app` in the JDBC URL), the role or the database;
  or
- the SQL names every table with its schema (`app.orders`).

Otherwise a default such as `ALTER ROLE ... SET search_path = public, app` can
make a verified `orders` read `public.orders`. They are also the forms to use
inside a transaction you manage yourself; pin the search path there with
`SELECT set_config('search_path', ?, true)` and
`JdbcGuard.searchPathSetting(verdict)`.

Keep PgJDBC's default extended query protocol. With
`preferQueryMode=simple`, PgJDBC substitutes parameters into the SQL text on
the client (correctly escaped, but no longer server-side binding).

To bind manually with another API, `BindParams.positional(verdict)` returns
the values in `$1..$n` order (a `String`, or a `List<String>` for a set) and
throws unless the verdict is an allow with contiguous, unique placeholders.
`BindParams.pgArrayLiteral(list)` encodes a set as `{"a","b"}`.

## Fail-closed semantics

Every failure is a `HaltSQLException` whose `kind()` is one of:

| Kind | When |
|---|---|
| `HTTP` (`HaltSQLHttpException`) | Non-200 status: `status()` and `code()` (`UNAUTHORIZED`, `FORBIDDEN`, `AUDIT_UNAVAILABLE`, ... or `HTTP_<status>`). Redirects are never followed. |
| `TIMEOUT` | An attempt exceeded the timeout (after retries). |
| `TRANSPORT` | Connection or TLS error, or the thread was interrupted. |
| `PROTOCOL` | Body is not JSON, has duplicate keys or trailing data, a required field is missing or mistyped, `allowed` is true while `reasons` is not empty, the body is too large, or `sql_sha256` does not equal the SHA-256 of the SQL that was sent. |
| `USAGE` | Bad options or arguments, or SQL the JDBC path cannot run safely. |
| `DENIED` (`HaltSQLDeniedException`) | `JdbcGuard` only: the policy denied the SQL. |

`allowed()` on every exception returns `false`. Unknown verdict fields are
ignored ([compatibility rules](verdict.md#stability-guarantees)); unknown
reason codes are kept as strings.

`JdbcGuard` throws `HaltSQLDeniedException` for SQL that a `mode: shadow`
policy would deny, unless you use `new JdbcGuard(client).allowShadow()` (for a
[shadow rollout](tutorials/roll-out-a-policy-safely.md)).

**Search path.** The verdict holds only under the policy's search path
(`verdict.policy().searchPath()`). `queryInTransaction` and
`updateInTransaction` set it for the transaction that runs the SQL, as the
Python guard, the MCP server and `haltsql-proxy` do. `prepare`, `query` and
`update` run one statement on your connection and do not change session
settings: with them, configure the connection or role with that
`search_path`, or have the model write schema-qualified names
([when that is acceptable](#prepare-query-update-one-statement-no-pin)).

## Options

| Builder method | Default | Meaning |
|---|---|---|
| `token(t)` | none | Bearer token for `/v1/*`; never in exception messages or `toString()`. |
| `timeout(d)` | 5s | Connect and per-attempt request timeout. |
| `retries(n, base, max)` | 2, 100ms, 2s | Retries on 503, connection errors and timeouts; exponential backoff with full jitter; `max` also caps `Retry-After`. |
| `maxResponseBytes(n)` | 8 MiB | Response size cap. |
| `sslContext(ctx)` | JVM default trust store | TLS for an `https` sidecar: a trust store with a private CA, a key manager with a client certificate for mutual TLS. |
| `sslParameters(p)` | JVM defaults | TLS protocols and cipher suites. |
| `httpClient(c)` | built-in | Custom `HttpClient` (proxy, executor, TLS); must use `Redirect.NEVER`. Cannot be combined with `sslContext` / `sslParameters`: configure TLS on it instead. |
| `withoutSqlHashCheck()` | check on | Disable the `sql_sha256` check. |

Per call: `verify(sql, context, VerifyOptions.policy("name").withRequestId(id))`.
The request id is sent as `X-Request-Id` (1-200 printable ASCII characters,
else a `USAGE` error before anything is sent).
Context values may be `String`, `Integer`, `Long`, `Short`, `Byte`, `BigInteger`
(within ±2^53), or collections of those.

Other endpoints: `health()`, `ready()` (a 503 returns `ready() == false` and is
not retried), `policies()`.

Every request has a timeout (it covers the connect, the headers and the
response body) and carries
`User-Agent: haltsql-client-java/<VERSION>`. The worst case for one `verify`
is about `(retries + 1) * timeout` plus the backoff delays. Only 503,
connection errors and timeouts are retried; `POST /v1/verify` has no side
effects, so retrying it is safe. An interrupted thread stops at once (kind
`TRANSPORT`, interrupt flag restored).

## TLS and mutual TLS

```java
KeyStore trust = KeyStore.getInstance("PKCS12");
trust.load(null, null);
trust.setCertificateEntry("haltsql-ca", CertificateFactory.getInstance("X.509")
    .generateCertificate(Files.newInputStream(Path.of("/etc/haltsql/ca.crt"))));
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
tmf.init(trust);

KeyStore identity = KeyStore.getInstance("PKCS12");          // client cert + key, for mTLS
identity.load(Files.newInputStream(Path.of("/etc/haltsql/client.p12")), password);
KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
kmf.init(identity, password);

SSLContext tls = SSLContext.getInstance("TLS");
tls.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

HaltSQLClient haltsql = HaltSQLClient.builder("https://haltsql.internal:8443")
    .token(System.getenv("HALTSQL_TOKEN"))
    .sslContext(tls)
    .build();
```

Certificate and host-name verification stay on. An untrusted certificate is a
`TRANSPORT` error.

## Sharing and secrets

- `HaltSQLClient` is immutable and thread-safe. Create one per sidecar and
  share it; the underlying `HttpClient` pools keep-alive connections.
- The token is only placed in the `Authorization` header. It is not in any
  exception message or in `toString()`.

## Development

```sh
cd clients/java
mvn test
```

Tests use a `com.sun.net.httpserver` fake that replays real `haltsql-server`
responses from `src/test/resources/vectors.json`. The PgJDBC tests need
Postgres (`make -C lab up`; `HALTSQL_PG*` variables override the defaults),
create and drop the databases `haltsql_polyglot_java` and
`haltsql_polyglot_java_tx`, and are skipped (JUnit assumptions) when Postgres
is unreachable. With `HALTSQL_REQUIRE_POSTGRES=1` (set in CI) unreachable is a
failure instead.
