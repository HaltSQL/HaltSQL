# HaltSQL Java SDK

`com.haltsql:haltsql-client` (Java 17+): fail-closed client for the HaltSQL sidecar,
plus `JdbcGuard` for running verified SQL through PgJDBC.

```java
HaltSQLClient haltsql = HaltSQLClient.builder("http://127.0.0.1:8080")
    .token(System.getenv("HALTSQL_TOKEN")).build();
List<Long> ids = new JdbcGuard(haltsql).queryInTransaction(conn, sql, Map.of("tenant_id", tenant),
    rs -> { List<Long> out = new ArrayList<>(); while (rs.next()) out.add(rs.getLong(1)); return out; });
```

Every call has a timeout (5 s per attempt by default) and bounded retries; TLS
verification is on by default, and `sslContext(...)` configures a private CA or
mutual TLS. The token never appears in exceptions or `toString()`.

Guide (including how `$n` placeholders are run through JDBC): [docs/sdk-java.md](../../docs/sdk-java.md).

Development: `mvn test` (PgJDBC tests skip without Postgres; `make -C lab up`).
