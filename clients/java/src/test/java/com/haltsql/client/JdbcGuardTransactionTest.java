package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link JdbcGuard#queryInTransaction} and {@link JdbcGuard#updateInTransaction}: the
 * transaction-owning guard that pins the verdict's search path. First with a recording connection
 * (the exact statements and their order), then against Postgres (the pin decides which table is
 * read).
 */
class JdbcGuardTransactionTest {
  static final String SQL = "  SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50 -- c\n";
  static final String JDBC_SQL = SQL.replace("$1", "?");
  static final String SET = "SELECT set_config(?, ?, true)";

  // ---- verdicts ----

  /** The recorded allow verdict (search path [app], a select) for {@code sql}, binding $1 = acme. */
  static String body(String sql, Consumer<ObjectNode> patch) throws Exception {
    Object[] values = sql.contains("$1") ? new Object[] {"acme"} : new Object[0];
    ObjectNode resp = (ObjectNode) FakeServer.JSON.readTree(JdbcGuardTest.allowBody(sql, values));
    patch.accept(resp);
    return resp.toString();
  }

  static Consumer<ObjectNode> none() {
    return r -> {};
  }

  static Consumer<ObjectNode> kind(String k) {
    return r -> r.put("statement_kind", k);
  }

  static Consumer<ObjectNode> searchPath(String... schemas) {
    return r -> {
      ArrayNode a = ((ObjectNode) r.get("policy")).putArray("search_path");
      for (String s : schemas) a.add(s);
    };
  }

  static Consumer<ObjectNode> noSearchPath() {
    return r -> ((ObjectNode) r.get("policy")).remove("search_path");
  }

  static Consumer<ObjectNode> shadow() {
    return r ->
        r.putArray("shadow_reasons").addObject().put("code", "E_TENANT_MISSING").put("message", "m").put("rule", "r");
  }

  @FunctionalInterface
  interface GuardUse<T> {
    T apply(JdbcGuard guard) throws Exception;
  }

  /** Runs {@code use} with a guard whose sidecar answers every request with {@code body}. */
  static <T> T withGuard(String body, GuardUse<T> use) throws Exception {
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      return use.apply(new JdbcGuard(HaltSQLClient.builder(srv.url()).build()));
    }
  }

  static final JdbcGuard.ResultSetHandler<List<Integer>> IDS =
      rs -> {
        List<Integer> out = new ArrayList<>();
        while (rs.next()) out.add(rs.getInt(1));
        return out;
      };

  // ---- a recording connection ----

  /** Everything a fake connection was asked to do, in order. */
  static final class Rec {
    final List<String> events = new ArrayList<>();
    boolean autoCommit = true;
    Predicate<String> fail = e -> false;

    void add(String event) throws SQLException {
      events.add(event);
      if (fail.test(event)) throw new SQLException("boom: " + event);
    }
  }

  static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler h) {
    return type.cast(Proxy.newProxyInstance(JdbcGuardTransactionTest.class.getClassLoader(), new Class<?>[] {type}, h));
  }

  static Connection recording(Rec rec) {
    DatabaseMetaData md =
        proxy(DatabaseMetaData.class, (p, m, a) -> m.getName().equals("getDriverName") ? JdbcGuard.PGJDBC_DRIVER_NAME : null);
    ResultSet rs = proxy(ResultSet.class, (p, m, a) -> m.getName().equals("next") ? Boolean.FALSE : null);
    return proxy(
        Connection.class,
        (p, m, a) -> {
          switch (m.getName()) {
            case "getMetaData":
              return md;
            case "isWrapperFor":
              return false;
            case "getAutoCommit":
              return rec.autoCommit;
            case "setAutoCommit":
              rec.autoCommit = (Boolean) a[0];
              rec.add("autocommit=" + a[0]);
              return null;
            case "commit":
              rec.add("COMMIT");
              return null;
            case "rollback":
              rec.add("ROLLBACK");
              return null;
            case "createStatement":
              return proxy(
                  Statement.class,
                  (sp, sm, sa) -> {
                    if (sm.getName().equals("execute")) {
                      rec.add((String) sa[0]);
                      return true;
                    }
                    return null;
                  });
            case "prepareStatement":
              String sql = (String) a[0];
              List<Object> params = new ArrayList<>();
              return proxy(
                  PreparedStatement.class,
                  (sp, sm, sa) -> {
                    switch (sm.getName()) {
                      case "setString":
                      case "setObject":
                        params.add(sa[1]);
                        return null;
                      case "execute":
                        rec.add(sql + " " + params);
                        return true;
                      case "executeQuery":
                        rec.add(sql + " " + params);
                        return rs;
                      case "executeUpdate":
                        rec.add(sql + " " + params);
                        return 7;
                      default:
                        return null;
                    }
                  });
            default:
              return null;
          }
        });
  }

  static Map<String, String> ordered(String... kv) {
    Map<String, String> m = new LinkedHashMap<>();
    for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
    return m;
  }

  @Test
  void selectRunsReadOnlyWithSettingsThenThePinThenTheVerifiedSql() throws Exception {
    Rec rec = new Rec();
    List<Verdict> seen = new ArrayList<>();
    List<Integer> out =
        withGuard(
            body(SQL, none()),
            g ->
                g.transactionSettings(ordered("app.tenant_id", "acme", "search_path", "public"))
                    .onVerdict(seen::add)
                    .queryInTransaction(recording(rec), SQL, Map.of("tenant_id", "acme"), IDS));
    assertEquals(List.of(), out);
    assertEquals(1, seen.size());
    assertEquals(
        List.of(
            "autocommit=false",
            "SET TRANSACTION READ ONLY",
            SET + " [app.tenant_id, acme]",
            SET + " [search_path, public]",
            SET + " [search_path, \"app\"]",
            JDBC_SQL + " [acme]",
            "COMMIT",
            "autocommit=true"),
        rec.events);
  }

  @Test
  void aConnectionWithAutocommitOffKeepsItOff() throws Exception {
    Rec rec = new Rec();
    rec.autoCommit = false;
    withGuard(body(SQL, none()), g -> g.queryInTransaction(recording(rec), SQL, Map.of(), IDS));
    assertEquals(
        List.of("SET TRANSACTION READ ONLY", SET + " [search_path, \"app\"]", JDBC_SQL + " [acme]", "COMMIT"),
        rec.events);
    assertFalse(rec.autoCommit);
  }

  @Test
  void aWriteVerdictIsNotForcedReadOnly() throws Exception {
    for (String k : List.of("insert", "update", "delete")) {
      Rec rec = new Rec();
      int n = withGuard(body(SQL, kind(k)), g -> g.updateInTransaction(recording(rec), SQL, Map.of()));
      assertEquals(7, n);
      assertEquals(
          List.of("autocommit=false", SET + " [search_path, \"app\"]", JDBC_SQL + " [acme]", "COMMIT", "autocommit=true"),
          rec.events,
          k);
    }
    // A select verdict is read-only for updateInTransaction too.
    Rec rec = new Rec();
    withGuard(body(SQL, none()), g -> g.updateInTransaction(recording(rec), SQL, Map.of(), VerifyOptions.NONE));
    assertEquals("SET TRANSACTION READ ONLY", rec.events.get(1));
  }

  @Test
  void schemaNamesAreQuotedAsIdentifiers() throws Exception {
    Verdict v = new Verdict(true, List.of(), List.of(), new PolicyRef("p", "v", List.of("app", "we\"ird", "Mixed", "a,b", "")),
        "select", List.of(), List.of(), List.of(), null, "0".repeat(64), 0);
    assertEquals("\"app\", \"we\"\"ird\", \"Mixed\", \"a,b\", \"\"", JdbcGuard.searchPathSetting(v));
    // An empty list is still pinned (to an empty path); only an absent field is not.
    Verdict empty = new Verdict(true, List.of(), List.of(), new PolicyRef("p", "v", List.of()),
        "select", List.of(), List.of(), List.of(), null, "0".repeat(64), 0);
    assertEquals("", JdbcGuard.searchPathSetting(empty));
    Verdict absent = new Verdict(true, List.of(), List.of(), new PolicyRef("p", "v"),
        "select", List.of(), List.of(), List.of(), null, "0".repeat(64), 0);
    assertNull(JdbcGuard.searchPathSetting(absent));

    Rec rec = new Rec();
    withGuard(body(SQL, searchPath("app", "we\"ird", "Mixed")), g -> g.queryInTransaction(recording(rec), SQL, Map.of(), IDS));
    assertEquals(SET + " [search_path, \"app\", \"we\"\"ird\", \"Mixed\"]", rec.events.get(2));
  }

  /** A verdict from an engine that does not report search_path still runs, without the pin. */
  @Test
  void aVerdictWithoutSearchPathRunsAndDoesNotPin() throws Exception {
    Rec rec = new Rec();
    withGuard(body(SQL, noSearchPath()), g -> g.queryInTransaction(recording(rec), SQL, Map.of(), IDS));
    assertEquals(
        List.of("autocommit=false", "SET TRANSACTION READ ONLY", JDBC_SQL + " [acme]", "COMMIT", "autocommit=true"),
        rec.events);
    Rec rec2 = new Rec();
    withGuard(
        body(SQL, noSearchPath().andThen(kind("update"))),
        g -> g.transactionSettings(Map.of("search_path", "app")).updateInTransaction(recording(rec2), SQL, Map.of()));
    assertEquals(
        List.of("autocommit=false", SET + " [search_path, app]", JDBC_SQL + " [acme]", "COMMIT", "autocommit=true"),
        rec2.events);
  }

  @Test
  void anErrorRollsBackAndRestoresAutocommit() throws Exception {
    for (String failing : List.of("SET TRANSACTION READ ONLY", SET, JDBC_SQL, "COMMIT")) {
      for (boolean auto : List.of(true, false)) {
        Rec rec = new Rec();
        rec.autoCommit = auto;
        rec.fail = e -> e.startsWith(failing);
        SQLException e =
            assertThrows(
                SQLException.class,
                () -> withGuard(body(SQL, none()), g -> g.queryInTransaction(recording(rec), SQL, Map.of(), IDS)));
        assertTrue(e.getMessage().startsWith("boom: " + failing), e.getMessage());
        List<String> tail = rec.events.subList(rec.events.size() - (auto ? 2 : 1), rec.events.size());
        assertEquals(auto ? List.of("ROLLBACK", "autocommit=true") : List.of("ROLLBACK"), tail, failing);
        assertEquals(auto, rec.autoCommit);
        if (!failing.equals(JDBC_SQL) && !failing.equals("COMMIT")) {
          assertFalse(rec.events.contains(JDBC_SQL + " [acme]"), "ran without its pin");
        }
      }
    }
  }

  @Test
  void anErrorFromTheHandlerRollsBack() throws Exception {
    Rec rec = new Rec();
    IllegalStateException mine = new IllegalStateException("stop");
    IllegalStateException e =
        assertThrows(
            IllegalStateException.class,
            () ->
                withGuard(
                    body(SQL, none()),
                    g -> g.queryInTransaction(recording(rec), SQL, Map.of(), rs -> { throw mine; })));
    assertSame(mine, e);
    assertEquals(List.of("ROLLBACK", "autocommit=true"), rec.events.subList(rec.events.size() - 2, rec.events.size()));
    assertFalse(rec.events.contains("COMMIT"));
  }

  @Test
  void aFailedRollbackKeepsTheFirstError() throws Exception {
    Rec rec = new Rec();
    rec.fail = e -> e.startsWith(JDBC_SQL) || e.equals("ROLLBACK") || e.equals("autocommit=true");
    SQLException e =
        assertThrows(
            SQLException.class,
            () -> withGuard(body(SQL, kind("delete")), g -> g.updateInTransaction(recording(rec), SQL, Map.of())));
    assertTrue(e.getMessage().startsWith("boom: " + JDBC_SQL), e.getMessage());
    assertEquals(2, e.getSuppressed().length);
  }

  @Test
  void deniedShadowAndSidecarErrorsNeverTouchTheConnection() throws Exception {
    String denied = FakeServer.vector("denied_multi_statement").get("response").toString();
    String deniedSql = FakeServer.vector("denied_multi_statement").get("request").get("sql").asText();
    record Case(String body, String sql, int status, Class<? extends HaltSQLException> error) {}
    for (Case c :
        List.of(
            new Case(denied, deniedSql, 200, HaltSQLDeniedException.class),
            new Case(body(SQL, shadow()), SQL, 200, HaltSQLDeniedException.class),
            new Case("{\"error\":{\"code\":\"INTERNAL\",\"message\":\"boom\"}}", SQL, 500, HaltSQLHttpException.class),
            // A verdict for other SQL.
            new Case(body("SELECT 1", none()), SQL, 200, HaltSQLException.class))) {
      Rec rec = new Rec();
      try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(c.status(), c.body()))) {
        JdbcGuard g = new JdbcGuard(HaltSQLClient.builder(srv.url()).build());
        assertThrows(c.error(), () -> g.queryInTransaction(recording(rec), c.sql(), Map.of(), IDS));
        assertThrows(c.error(), () -> g.updateInTransaction(recording(rec), c.sql(), Map.of()));
        assertEquals(List.of(), rec.events);
      }
    }
    // allowShadow opts in, as for query().
    Rec rec = new Rec();
    withGuard(body(SQL, shadow()), g -> g.allowShadow().queryInTransaction(recording(rec), SQL, Map.of(), IDS));
    assertEquals("COMMIT", rec.events.get(rec.events.size() - 2));
  }

  @Test
  void settingsAreValidatedAndKeptByDerivedGuards() throws Exception {
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, uncheckedBody()))) {
      JdbcGuard g = new JdbcGuard(HaltSQLClient.builder(srv.url()).build());
      for (String name : List.of("", "bad name", "x;y", "a..b", "1a", "a.", "a\"b")) {
        HaltSQLException e =
            assertThrows(HaltSQLException.class, () -> g.transactionSettings(Map.of(name, "v")), name);
        assertEquals(HaltSQLException.Kind.USAGE, e.kind());
      }
      Map<String, String> nullValue = new LinkedHashMap<>();
      nullValue.put("app.x", null);
      assertThrows(HaltSQLException.class, () -> g.transactionSettings(nullValue));
      assertEquals(0, srv.count());

      JdbcGuard withSettings = g.transactionSettings(Map.of("app.tenant_id", "acme"));
      for (JdbcGuard derived :
          List.of(withSettings.onVerdict(v -> {}), withSettings.allowShadow(), withSettings.requireByteIdenticalSql())) {
        Rec rec = new Rec();
        derived.queryInTransaction(recording(rec), SQL, Map.of(), IDS);
        assertEquals(SET + " [app.tenant_id, acme]", rec.events.get(2));
      }
      // The original guard is unchanged.
      Rec rec = new Rec();
      g.queryInTransaction(recording(rec), SQL, Map.of(), IDS);
      assertEquals(SET + " [search_path, \"app\"]", rec.events.get(2));
    }
  }

  static String uncheckedBody() {
    try {
      return body(SQL, none());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  // ---- against Postgres ----

  static final String DB = "haltsql_polyglot_java_tx";
  static final String ORDERS = "SELECT id FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50";
  static boolean pgAvailable;

  @BeforeAll
  static void setup() throws Exception {
    try (Connection admin = DriverManager.getConnection(JdbcGuardTest.url("postgres"), JdbcGuardTest.USER, JdbcGuardTest.PASS);
        Statement s = admin.createStatement()) {
      s.execute("DROP DATABASE IF EXISTS " + DB + " WITH (FORCE)");
      s.execute("CREATE DATABASE " + DB);
      pgAvailable = true;
    } catch (SQLException e) {
      JdbcGuardTest.postgresMissing(e);
      return;
    }
    try (Connection c = DriverManager.getConnection(JdbcGuardTest.url(DB), JdbcGuardTest.USER, JdbcGuardTest.PASS);
        Statement s = c.createStatement()) {
      s.execute("CREATE SCHEMA app");
      s.execute("CREATE TABLE app.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text)");
      s.execute("INSERT INTO app.orders VALUES (1,'acme','open'),(2,'acme','paid'),(3,'globex','open')");
      s.execute("CREATE TABLE public.orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text)");
      s.execute("INSERT INTO public.orders VALUES (666,'acme','decoy')");
      s.execute("CREATE SCHEMA \"Mixed\"");
      s.execute("CREATE TABLE \"Mixed\".orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text)");
      s.execute("INSERT INTO \"Mixed\".orders VALUES (50,'acme','mixed')");
      s.execute("CREATE SCHEMA \"we\"\"ird, app\"");
      s.execute("CREATE TABLE \"we\"\"ird, app\".orders (id int PRIMARY KEY, tenant_id text NOT NULL, status text)");
      s.execute("INSERT INTO \"we\"\"ird, app\".orders VALUES (70,'acme','weird')");
    }
  }

  @AfterAll
  static void teardown() throws Exception {
    if (!pgAvailable) return;
    try (Connection admin = DriverManager.getConnection(JdbcGuardTest.url("postgres"), JdbcGuardTest.USER, JdbcGuardTest.PASS);
        Statement s = admin.createStatement()) {
      s.execute("DROP DATABASE IF EXISTS " + DB + " WITH (FORCE)");
    }
  }

  /** A session whose search path is {@code public, app}: the decoy table comes first. */
  static Connection conn() throws SQLException {
    Connection c = DriverManager.getConnection(JdbcGuardTest.url(DB), JdbcGuardTest.USER, JdbcGuardTest.PASS);
    try (Statement s = c.createStatement()) {
      s.execute("SET search_path = public, app");
    }
    return c;
  }

  static String one(Connection c, String sql) throws SQLException {
    try (Statement s = c.createStatement();
        ResultSet rs = s.executeQuery(sql)) {
      assertTrue(rs.next());
      return rs.getString(1);
    }
  }

  static List<Integer> pinned(Connection c, String sql, Consumer<ObjectNode> patch) throws Exception {
    return withGuard(body(sql, patch), g -> g.queryInTransaction(c, sql, Map.of("tenant_id", "acme"), IDS));
  }

  @Test
  void theSessionDefaultPointsAtTheDecoyAndTheLowLevelFormFollowsIt() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      assertEquals(List.of(666), withGuard(body(ORDERS, none()), g -> g.query(c, ORDERS, Map.of(), IDS)));
    }
  }

  @Test
  void pinnedTransactionReadsThePolicysTableNotTheDecoy() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));
    }
  }

  @Test
  void thePinIsTransactionLocalAndAutocommitIsRestored() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));
      assertTrue(c.getAutoCommit());
      assertEquals("public, app", one(c, "SHOW search_path"));
      assertEquals("666", one(c, "SELECT id FROM orders"));

      // With autocommit off it stays off, and the guard's transaction is finished.
      c.setAutoCommit(false);
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));
      assertFalse(c.getAutoCommit());
      assertEquals("0", one(c, "SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() AND locktype = 'relation' AND relation = 'app.orders'::regclass"));
      assertEquals("public, app", one(c, "SHOW search_path"));
      c.rollback();
    }
  }

  @Test
  void aSearchPathInTheSettingsDoesNotOverrideThePin() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    String sql =
        "SELECT id, current_setting('app.tenant_id'), current_setting('search_path')"
            + " FROM orders WHERE tenant_id = $1 ORDER BY id LIMIT 50";
    try (Connection c = conn()) {
      List<String> rows =
          withGuard(
              body(sql, none()),
              g ->
                  g.transactionSettings(ordered("search_path", "public, app", "app.tenant_id", "acme"))
                      .queryInTransaction(
                          c,
                          sql,
                          Map.of(),
                          rs -> {
                            List<String> out = new ArrayList<>();
                            while (rs.next()) out.add(rs.getInt(1) + " " + rs.getString(2) + " " + rs.getString(3));
                            return out;
                          }));
      assertEquals(List.of("1 acme \"app\"", "2 acme \"app\""), rows);
    }
  }

  @Test
  void upperCaseAndQuotedSchemaNamesArePinnedAsIdentifiers() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      assertEquals(List.of(50), pinned(c, ORDERS, searchPath("Mixed")));
      assertEquals(List.of(70), pinned(c, ORDERS, searchPath("we\"ird, app")));
      assertEquals(List.of(70), pinned(c, ORDERS, searchPath("nosuch", "we\"ird, app", "app")));
    }
  }

  @Test
  void aVerdictWithoutSearchPathRunsUnderTheSessionsSearchPath() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      assertEquals(List.of(666), pinned(c, ORDERS, noSearchPath()));
      assertEquals(
          List.of(1, 2),
          withGuard(
              body(ORDERS, noSearchPath()),
              g -> g.transactionSettings(Map.of("search_path", "app")).queryInTransaction(c, ORDERS, Map.of(), IDS)));
    }
  }

  @Test
  void postgresReceivesTheVerifiedStringByteForByte() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    for (String sql :
        List.of(
            "  SELECT current_query(), $1::text /* c */ -- tenant $1\n ",
            "\n\tSELECT current_query() -- no params\n\n")) {
      try (Connection c = conn()) {
        String got =
            withGuard(
                body(sql, none()),
                g ->
                    g.requireByteIdenticalSql()
                        .queryInTransaction(c, sql, Map.of(), rs -> { assertTrue(rs.next()); return rs.getString(1); }));
        assertEquals(sql, got);
      }
    }
  }

  @Test
  void anErrorRollsBackAndLeavesTheConnectionUsable() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn()) {
      String bad = "SELECT 1 / (id - id) FROM orders WHERE tenant_id = $1";
      SQLException e = assertThrows(SQLException.class, () -> pinned(c, bad, none()));
      assertEquals("22012", e.getSQLState());
      // Not left in an aborted transaction; autocommit and the search path are back.
      assertTrue(c.getAutoCommit());
      assertEquals("public, app", one(c, "SHOW search_path"));
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));

      // An error from the handler undoes a write that already returned rows.
      String ins = "INSERT INTO orders VALUES (300, $1, 'new') RETURNING id";
      assertThrows(
          IllegalStateException.class,
          () ->
              withGuard(
                  body(ins, kind("insert")),
                  g -> g.queryInTransaction(c, ins, Map.of(), rs -> { throw new IllegalStateException("stop"); })));
      // A failing write leaves nothing behind either.
      String ins2 = "INSERT INTO orders SELECT g, $1, 'x' FROM generate_series(100, 103) g WHERE 10 / (103 - g) > 0";
      assertThrows(
          SQLException.class,
          () -> withGuard(body(ins2, kind("insert")), g -> g.updateInTransaction(c, ins2, Map.of())));
      assertEquals("3", one(c, "SELECT count(*) FROM app.orders"));
      assertTrue(c.getAutoCommit());
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));
    }
  }

  @Test
  void aSelectVerdictRunsReadOnlyAndAnAllowedWriteIsCommitted() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    String ins = "INSERT INTO orders VALUES (200, $1, 'new')";
    try (Connection c = conn();
        Connection other = conn()) {
      SQLException q = assertThrows(SQLException.class, () -> pinned(c, ins, none()));
      assertEquals("25006", q.getSQLState()); // read_only_sql_transaction
      SQLException u =
          assertThrows(
              SQLException.class,
              () -> withGuard(body(ins, none()), g -> g.updateInTransaction(c, ins, Map.of())));
      assertEquals("25006", u.getSQLState());
      assertEquals("3", one(other, "SELECT count(*) FROM app.orders"));

      assertEquals(1, (int) withGuard(body(ins, kind("insert")), g -> g.updateInTransaction(c, ins, Map.of())));
      // Committed (another session sees it), and into the policy's table rather than the decoy.
      assertEquals("acme", one(other, "SELECT tenant_id FROM app.orders WHERE id = 200"));
      assertEquals("1", one(other, "SELECT count(*) FROM public.orders"));
      // The next transaction on this connection is not read-only.
      try (Statement s = c.createStatement()) {
        s.execute("DELETE FROM app.orders WHERE id = 200");
      }
    }
  }

  @Test
  void deniedAndShadowVerdictsNeverReachPostgres() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    String del = "DELETE FROM orders";
    String denied = FakeServer.vector("denied_multi_statement").get("response").toString();
    String deniedSql = FakeServer.vector("denied_multi_statement").get("request").get("sql").asText();
    try (Connection c = conn()) {
      c.setAutoCommit(false);
      assertThrows(
          HaltSQLDeniedException.class,
          () -> withGuard(body(del, shadow().andThen(kind("delete"))), g -> g.updateInTransaction(c, del, Map.of())));
      assertThrows(
          HaltSQLDeniedException.class,
          () -> withGuard(denied, g -> g.queryInTransaction(c, deniedSql, Map.of(), IDS)));
      // No statement was sent, so PgJDBC has not even begun a transaction.
      assertEquals("IDLE", c.unwrap(org.postgresql.core.BaseConnection.class).getTransactionState().name());
      c.setAutoCommit(true);
      assertEquals("3", one(c, "SELECT count(*) FROM app.orders"));
      assertEquals("1", one(c, "SELECT count(*) FROM public.orders"));
    }
  }

  @Test
  void aConnectionInsideATransactionIsRefused() throws Exception {
    Assumptions.assumeTrue(pgAvailable, "Postgres not reachable");
    try (Connection c = conn();
        Connection other = conn()) {
      c.setAutoCommit(false);
      try (Statement s = c.createStatement()) {
        s.execute("INSERT INTO app.orders VALUES (400, 'acme', 'pending')");
      }
      HaltSQLException e = assertThrows(HaltSQLException.class, () -> pinned(c, ORDERS, none()));
      assertEquals(HaltSQLException.Kind.USAGE, e.kind());
      // The caller's work was neither committed nor rolled back.
      assertEquals("0", one(other, "SELECT count(*) FROM app.orders WHERE id = 400"));
      assertEquals("1", one(c, "SELECT count(*) FROM app.orders WHERE id = 400"));
      c.rollback();
      assertEquals(List.of(1, 2), pinned(c, ORDERS, none()));
    }
  }
}
