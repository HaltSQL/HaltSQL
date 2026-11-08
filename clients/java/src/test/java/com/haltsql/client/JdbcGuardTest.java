package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
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
      System.out.println("skipping Postgres tests: " + e.getMessage() + " (run: make -C lab up)");
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
}
