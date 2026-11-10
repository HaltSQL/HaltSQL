package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class JdbcGuardTest {
  static final String DB = "haltsql_polyglot_java";
  static final String HOST = env("HALTSQL_PGHOST", "localhost");
  static final String PORT = env("HALTSQL_PGPORT", "5417");
  static final String USER = env("HALTSQL_PGUSER", "postgres");
  static final String PASS = env("HALTSQL_PGPASSWORD", "haltlab");

  static String env(String k, String d) {
    String v = System.getenv(k);
    return v == null || v.isEmpty() ? d : v;
  }

  static String url(String db) {
    return "jdbc:postgresql://" + HOST + ":" + PORT + "/" + db + "?connectTimeout=2";
  }

  static boolean pgAvailable;

  @BeforeAll
  static void setup() throws Exception {
    try (Connection admin = DriverManager.getConnection(url("postgres"), USER, PASS);
        Statement s = admin.createStatement()) {
      s.execute("DROP DATABASE IF EXISTS " + DB);
      s.execute("CREATE DATABASE " + DB);
      pgAvailable = true;
    } catch (SQLException e) {
      postgresMissing(e);
      return;
    }
    try (Connection c = DriverManager.getConnection(url(DB), USER, PASS);
        Statement s = c.createStatement()) {
      s.execute("CREATE SCHEMA app");
      s.execute("CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text, customer_id int)");
      s.execute("INSERT INTO app.orders VALUES (1,'acme','open',1),(2,'acme','paid',1),(3,'globex','open',2)");
      s.execute("CREATE TABLE app.customers (id int, tenant_id text, name text)");
      s.execute("INSERT INTO app.customers VALUES (1,'acme','Ada'),(2,'globex','Bob')");
      s.execute("CREATE SCHEMA intapp");
      s.execute("CREATE TABLE intapp.orders (id int PRIMARY KEY, tenant_id bigint NOT NULL)");
      s.execute("INSERT INTO intapp.orders VALUES (10,42),(11,42),(12,7)");
      s.execute("CREATE SCHEMA reporting");
      s.execute("CREATE TABLE reporting.revenue_daily (org_id text, day date, revenue_cents bigint, currency text)");
      s.execute(
          "INSERT INTO reporting.revenue_daily VALUES ('acme','2026-01-01',100,'USD'),"
              + "('acme-eu','2026-01-01',200,'EUR'),('globex','2026-01-01',999,'USD')");
    }
  }

  /**
   * Postgres is not reachable: the tests that need it are skipped, unless
   * HALTSQL_REQUIRE_POSTGRES=1 (set in CI), which makes it a failure.
   */
  static void postgresMissing(SQLException e) {
    if ("1".equals(System.getenv("HALTSQL_REQUIRE_POSTGRES"))) {
      throw new AssertionError("HALTSQL_REQUIRE_POSTGRES=1 but Postgres is not reachable: " + e.getMessage(), e);
    }
    System.out.println("skipping Postgres tests: " + e.getMessage() + " (run: make -C lab up)");
  }

  @AfterAll
  static void teardown() throws Exception {
    if (!pgAvailable) return;
    try (Connection admin = DriverManager.getConnection(url("postgres"), USER, PASS);
        Statement s = admin.createStatement()) {
      s.execute("DROP DATABASE IF EXISTS " + DB + " WITH (FORCE)");
    }
  }

  static Connection conn(String searchPath) throws SQLException {
    Connection c = DriverManager.getConnection(url(DB), USER, PASS);
    try (Statement s = c.createStatement()) {
      s.execute("SET search_path = " + searchPath);
    }
    return c;
  }

  /** Runs a guarded query using the recorded real verdict of vector {@code name}. */
  static List<String> run(String name, String searchPath) throws Exception {
    JsonNode v = FakeServer.vector(name);
    String body = v.get("response").toString();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body));
        Connection c = conn(searchPath)) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).token(v.get("token").asText()).build();
      return new JdbcGuard(hc)
          .query(
              c,
              v.get("request").get("sql").asText(),
              HaltSQLClientTest.ctx(v.get("request")),
              rs -> {
                List<String> out = new ArrayList<>();
                while (rs.next()) out.add(rs.getString(1));
                Collections.sort(out);
                return out;
              });
    }
  }

  @Test
  void boundTextTenant() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    assertEquals(List.of("1", "2"), run("allowed_bound_single_tenant", "app"));
  }

  @Test
  void outOfOrderPlaceholdersJoin() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    // c.tenant_id = $2 appears before o.tenant_id = $1 in the SQL text.
    assertEquals(List.of("1", "2"), run("allowed_join_two_tenant_params", "app"));
  }

  @Test
  void integerContextIntoBigintColumn() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    assertEquals(List.of("10", "11"), run("allowed_integer_context", "intapp"));
  }

  @Test
  void setValuedTenantAsArray() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    assertEquals(List.of("acme", "acme-eu"), run("allowed_set_valued_tenant", "reporting, public"));
  }

  @Test
  void deniedNeverReachesPostgres() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    JsonNode v = FakeServer.vector("denied_multi_statement");
    String body = v.get("response").toString();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body));
        Connection c = conn("app")) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).token(v.get("token").asText()).build();
      HaltSQLDeniedException e =
          assertThrows(
              HaltSQLDeniedException.class,
              () -> new JdbcGuard(hc).prepare(c, v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")));
      assertEquals(List.of("E_MULTI_STATEMENT"), e.codes());
      try (Statement s = c.createStatement();
          ResultSet rs = s.executeQuery("SELECT count(*) FROM app.orders")) {
        assertTrue(rs.next());
        assertEquals(3, rs.getInt(1));
      }
    }
  }

  /**
   * Proves the claim in {@link JdbcSql}: for in-order placeholders PgJDBC sends exactly the
   * verified string. current_query() returns the statement text the server received.
   */
  @Test
  void pgjdbcSendsTheVerifiedStringByteForByte() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    String sql = "SELECT current_query(), $1::text, $2::bigint -- tenant $1\n";
    JdbcSql j = JdbcSql.translate(sql);
    assertTrue(j.byteIdentical());
    try (Connection c = conn("app");
        PreparedStatement ps = c.prepareStatement(j.jdbcSql())) {
      ps.setObject(1, "acme", java.sql.Types.OTHER);
      ps.setObject(2, "42", java.sql.Types.OTHER);
      try (ResultSet rs = ps.executeQuery()) {
        assertTrue(rs.next());
        assertEquals(sql, rs.getString(1));
        assertEquals("acme", rs.getString(2));
        assertEquals(42L, rs.getLong(3));
      }
    }
  }

  // ---- no database needed ----

  /** A Connection proxy reporting the given driver name and counting prepareStatement calls. */
  static Connection fakeConnection(String driverName, AtomicInteger prepares) {
    DatabaseMetaData md =
        (DatabaseMetaData)
            Proxy.newProxyInstance(
                JdbcGuardTest.class.getClassLoader(),
                new Class<?>[] {DatabaseMetaData.class},
                (p, m, a) -> m.getName().equals("getDriverName") ? driverName : null);
    return (Connection)
        Proxy.newProxyInstance(
            JdbcGuardTest.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (p, m, a) -> {
              switch (m.getName()) {
                case "getMetaData":
                  return md;
                case "prepareStatement":
                  prepares.incrementAndGet();
                  throw new SQLException("not expected");
                default:
                  return null;
              }
            });
  }

  @Test
  void deniedVerdictNeverPrepares() throws Exception {
    JsonNode v = FakeServer.vector("denied_column_and_tenant");
    String body = v.get("response").toString();
    AtomicInteger prepares = new AtomicInteger();
    List<Verdict> seen = new ArrayList<>();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).token(v.get("token").asText()).build();
      JdbcGuard g = new JdbcGuard(hc).onVerdict(seen::add);
      HaltSQLDeniedException e =
          assertThrows(
              HaltSQLDeniedException.class,
              () -> g.prepare(fakeConnection(JdbcGuard.PGJDBC_DRIVER_NAME, prepares), v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")));
      assertEquals(List.of("E_COLUMN_DENIED", "E_TENANT_MISSING"), e.codes());
      assertFalse(e.allowed());
    }
    assertEquals(0, prepares.get());
    assertEquals(1, seen.size());
  }

  @Test
  void shadowWouldDenyNeverPreparesWithoutOptIn() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    com.fasterxml.jackson.databind.node.ObjectNode resp = v.get("response").deepCopy();
    resp.putArray("shadow_reasons")
        .addObject()
        .put("code", "E_TENANT_MISSING")
        .put("message", "m")
        .put("rule", "r");
    String body = resp.toString();
    AtomicInteger prepares = new AtomicInteger();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).token(v.get("token").asText()).build();
      HaltSQLDeniedException e =
          assertThrows(
              HaltSQLDeniedException.class,
              () -> new JdbcGuard(hc).prepare(fakeConnection(JdbcGuard.PGJDBC_DRIVER_NAME, prepares), v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")));
      assertTrue(e.getMessage().contains("shadow mode would deny: E_TENANT_MISSING"));
    }
    assertEquals(0, prepares.get());
  }

  @Test
  void sidecarErrorNeverPrepares() throws Exception {
    AtomicInteger prepares = new AtomicInteger();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(500, "{\"error\":{\"code\":\"INTERNAL\",\"message\":\"boom\"}}"))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      assertThrows(
          HaltSQLHttpException.class,
          () -> new JdbcGuard(hc).prepare(fakeConnection(JdbcGuard.PGJDBC_DRIVER_NAME, prepares), "SELECT 1", Map.of()));
    }
    assertEquals(0, prepares.get());
  }

  @Test
  void otherDriversAreRefusedBeforeVerifying() throws Exception {
    AtomicInteger prepares = new AtomicInteger();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(500, "{}"))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      HaltSQLException e =
          assertThrows(
              HaltSQLException.class,
              () -> new JdbcGuard(hc).prepare(fakeConnection("MySQL Connector/J", prepares), "SELECT 1", Map.of()));
      assertEquals(HaltSQLException.Kind.USAGE, e.kind());
      assertEquals(0, srv.count());
    }
    assertEquals(0, prepares.get());
  }

  @Test
  void strictModeRefusesRenumbering() throws Exception {
    AtomicInteger prepares = new AtomicInteger();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(500, "{}"))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      HaltSQLException e =
          assertThrows(
              HaltSQLException.class,
              () ->
                  new JdbcGuard(hc)
                      .requireByteIdenticalSql()
                      .prepare(fakeConnection(JdbcGuard.PGJDBC_DRIVER_NAME, prepares), "SELECT 1 WHERE a = $2 AND b = $1", Map.of()));
      assertEquals(HaltSQLException.Kind.USAGE, e.kind());
      assertEquals(0, srv.count());
    }
  }

  /** What a recording connection saw: the prepared SQL and every setObject call. */
  static final class Recorded {
    final List<String> prepared = new ArrayList<>();
    final List<List<Object>> sets = new ArrayList<>();
  }

  /** A Connection proxy that reports PgJDBC and records prepareStatement / setObject. */
  static Connection recordingConnection(Recorded rec) {
    DatabaseMetaData md =
        (DatabaseMetaData)
            Proxy.newProxyInstance(
                JdbcGuardTest.class.getClassLoader(),
                new Class<?>[] {DatabaseMetaData.class},
                (p, m, a) -> m.getName().equals("getDriverName") ? JdbcGuard.PGJDBC_DRIVER_NAME : null);
    PreparedStatement ps =
        (PreparedStatement)
            Proxy.newProxyInstance(
                JdbcGuardTest.class.getClassLoader(),
                new Class<?>[] {PreparedStatement.class},
                (p, m, a) -> {
                  if (m.getName().equals("setObject")) rec.sets.add(List.of(a));
                  return null;
                });
    return (Connection)
        Proxy.newProxyInstance(
            JdbcGuardTest.class.getClassLoader(),
            new Class<?>[] {Connection.class},
            (p, m, a) -> {
              switch (m.getName()) {
                case "getMetaData":
                  return md;
                case "prepareStatement":
                  rec.prepared.add((String) a[0]);
                  return ps;
                default:
                  return null;
              }
            });
  }

  /** An allow verdict for {@code sql} (valid hash) binding the given values as $1..$n. */
  static String allowBody(String sql, Object... values) throws Exception {
    ObjectNode resp = FakeServer.vector("allowed_bound_single_tenant").get("response").deepCopy();
    resp.put("sql_sha256", HaltSQLClientTest.sha(sql));
    ArrayNode bps = resp.putArray("bind_params");
    for (int i = 0; i < values.length; i++) {
      ObjectNode bp = bps.addObject().put("param", i + 1);
      if (values[i] instanceof List<?> l) {
        ArrayNode arr = bp.putArray("value");
        l.forEach(x -> arr.add((String) x));
      } else {
        bp.put("value", (String) values[i]);
      }
    }
    return resp.toString();
  }

  /** Each ? gets the value of the placeholder number it replaced, not the value at its position. */
  @Test
  void valuesAreBoundByPlaceholderNumberAndTheSqlIsNotAltered() throws Exception {
    String sql =
        "  SELECT o.id FROM orders o JOIN customers c ON c.tenant_id = $2"
            + " WHERE o.tenant_id = $1 AND o.org = ANY($3) OR o.x = $1 \n";
    String body = allowBody(sql, "acme", "globex", List.of("a", "b\"c"));
    Recorded rec = new Recorded();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      new JdbcGuard(hc).prepare(recordingConnection(rec), sql, Map.of("tenant_id", "acme"));
    }
    // Only the placeholders change; leading and trailing whitespace is part of the verified string.
    assertEquals(List.of(sql.replace("$2", "?").replace("$1", "?").replace("$3", "?")), rec.prepared);
    assertEquals(
        List.of(
            List.of(1, "globex", java.sql.Types.OTHER),
            List.of(2, "acme", java.sql.Types.OTHER),
            List.of(3, "{\"a\",\"b\\\"c\"}", java.sql.Types.OTHER),
            List.of(4, "acme", java.sql.Types.OTHER)),
        rec.sets);
  }

  /** The SQL's placeholders and the verdict's bind params must match exactly, else nothing is prepared. */
  @Test
  void placeholderAndBindParamMismatchNeverPrepares() throws Exception {
    String sql = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5";
    for (String body : List.of(allowBody(sql, "acme", "extra"), allowBody(sql))) {
      Recorded rec = new Recorded();
      try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
        HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
        HaltSQLException e =
            assertThrows(
                HaltSQLException.class,
                () -> new JdbcGuard(hc).prepare(recordingConnection(rec), sql, Map.of("tenant_id", "acme")));
        assertEquals(HaltSQLException.Kind.USAGE, e.kind());
      }
      assertEquals(List.of(), rec.prepared);
    }
  }

  /** Shadow would-deny stays refused on every derived guard; only allowShadow() opts in. */
  @Test
  void onlyAllowShadowOptsIntoShadowVerdicts() throws Exception {
    String sql = "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 5";
    ObjectNode resp = (ObjectNode) FakeServer.JSON.readTree(allowBody(sql, "acme"));
    resp.putArray("shadow_reasons").addObject().put("code", "E_TENANT_MISSING").put("message", "m").put("rule", "r");
    String body = resp.toString();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      List<JdbcGuard> refusing =
          List.of(
              new JdbcGuard(hc),
              new JdbcGuard(hc).onVerdict(v -> {}),
              new JdbcGuard(hc).requireByteIdenticalSql(),
              new JdbcGuard(hc).requireByteIdenticalSql().onVerdict(v -> {}));
      for (JdbcGuard g : refusing) {
        Recorded rec = new Recorded();
        assertThrows(
            HaltSQLDeniedException.class,
            () -> g.prepare(recordingConnection(rec), sql, Map.of("tenant_id", "acme")));
        assertEquals(List.of(), rec.prepared);
      }
      Recorded rec = new Recorded();
      new JdbcGuard(hc)
          .allowShadow()
          .onVerdict(v -> {})
          .prepare(recordingConnection(rec), sql, Map.of("tenant_id", "acme"));
      assertEquals(1, rec.prepared.size());
    }
  }

  /** Through the guard, PgJDBC sends the verified string byte for byte (whitespace included). */
  @Test
  void guardSendsTheVerifiedStringToPostgres() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    String sql = "  SELECT current_query(), $1::text, $2::text -- tenant $1\n ";
    String body = allowBody(sql, "acme", "globex");
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body));
        Connection c = conn("app")) {
      HaltSQLClient hc = HaltSQLClient.builder(srv.url()).build();
      List<String> row =
          new JdbcGuard(hc)
              .query(
                  c,
                  sql,
                  Map.of("tenant_id", "acme"),
                  rs -> {
                    assertTrue(rs.next());
                    return List.of(rs.getString(1), rs.getString(2), rs.getString(3));
                  });
      assertEquals(List.of(sql, "acme", "globex"), row);
    }
  }
}
