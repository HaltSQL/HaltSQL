package com.haltsql.client;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/**
 * Guarded execution with PgJDBC: verify with HaltSQL, and only if allowed, run the verified SQL
 * with its bind params.
 *
 * <p>Use {@link #queryInTransaction} and {@link #updateInTransaction} unless you have a reason not
 * to: they run the verified SQL in a transaction that uses the verdict's search path, so the
 * tables it reads are the ones the policy lists.
 *
 * <pre>{@code
 * JdbcGuard guard = new JdbcGuard(haltsql);
 * List<Long> ids = guard.queryInTransaction(conn,
 *     "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 50",
 *     Map.of("tenant_id", session.tenantId()),
 *     rs -> { List<Long> out = new ArrayList<>(); while (rs.next()) out.add(rs.getLong(1)); return out; });
 * }</pre>
 *
 * <p><b>{@link #prepare}, {@link #query} and {@link #update} do not pin the search path.</b> They
 * are the low-level forms: one statement on the connection as it is. The verifier resolved
 * unqualified table names against {@code verdict.policy().searchPath()}, so a role or database
 * default ({@code ALTER ROLE ... SET search_path}) can make a verified {@code orders} read a
 * different table than the one the policy lists. Use them only when the session already uses the
 * policy's search path (set on the connection with {@code currentSchema}, on the role or on the
 * database) or the SQL names every table with its schema.
 *
 * <p>How the SQL reaches Postgres: see {@link JdbcSql}. Each {@code $n} becomes a {@code ?} that
 * PgJDBC renumbers back to {@code $1..$k}; when the verified SQL uses its placeholders in order
 * (the common case) PgJDBC sends the verified string byte for byte. Values are bound with {@code
 * setObject(i, value, Types.OTHER)}, which PgJDBC sends with an unspecified type so the server
 * infers it from the column (a tenant id string binds into {@code text}, {@code bigint} or {@code
 * uuid} columns alike); a set is bound as a Postgres array literal for {@code col = ANY($n)}.
 *
 * <p>Instances are immutable and thread-safe; connections are not, as usual in JDBC.
 */
public final class JdbcGuard {
  /** PgJDBC's {@code DatabaseMetaData.getDriverName()}. */
  static final String PGJDBC_DRIVER_NAME = "PostgreSQL JDBC Driver";

  private static final Pattern SETTING_NAME =
      Pattern.compile("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*");

  /** Reads a result set. */
  @FunctionalInterface
  public interface ResultSetHandler<T> {
    T handle(ResultSet rs) throws SQLException;
  }

  /** What a bound statement does inside the guard's transaction. */
  @FunctionalInterface
  private interface StatementBody<T> {
    T run(PreparedStatement ps) throws SQLException;
  }

  /** A verdict that allows the SQL, with what is needed to bind it. */
  private record Authorized(Verdict verdict, JdbcSql jsql, BindParam[] params) {}

  private final HaltSQLClient client;
  private final Consumer<Verdict> onVerdict;
  private final boolean requireByteIdentical;
  private final boolean allowShadow;
  private final Map<String, String> settings;

  public JdbcGuard(HaltSQLClient client) {
    this(client, v -> {}, false, false, Map.of());
  }

  private JdbcGuard(
      HaltSQLClient client,
      Consumer<Verdict> onVerdict,
      boolean strict,
      boolean allowShadow,
      Map<String, String> settings) {
    this.client = Objects.requireNonNull(client, "client");
    this.onVerdict = Objects.requireNonNull(onVerdict, "onVerdict");
    this.requireByteIdentical = strict;
    this.allowShadow = allowShadow;
    this.settings = settings;
  }

  /**
   * A copy that runs SQL a shadow-mode policy would deny (an allowed verdict with shadow reasons).
   * Without it such a verdict throws {@link HaltSQLDeniedException}, so switching a policy to
   * shadow on the server cannot by itself turn enforcement off in this application.
   */
  public JdbcGuard allowShadow() {
    return new JdbcGuard(client, onVerdict, requireByteIdentical, true, settings);
  }

  /** A copy that calls {@code c} with every verdict (allowed or denied), e.g. for audit logs. */
  public JdbcGuard onVerdict(Consumer<Verdict> c) {
    return new JdbcGuard(client, c, requireByteIdentical, allowShadow, settings);
  }

  /**
   * A copy that refuses SQL whose placeholders are repeated or out of order, so PgJDBC always
   * sends the verified string byte for byte.
   */
  public JdbcGuard requireByteIdenticalSql() {
    return new JdbcGuard(client, onVerdict, true, allowShadow, settings);
  }

  /**
   * A copy whose {@link #queryInTransaction} and {@link #updateInTransaction} apply these
   * transaction-local settings ({@code set_config(name, value, true)}, in the map's iteration
   * order) before the verified statement: for example {@code app.tenant_id} for row-level
   * security, or {@code statement_timeout}. It replaces settings given earlier. A {@code
   * search_path} given here has no effect when the verdict reports one: the pin is applied last.
   * {@link #prepare}, {@link #query} and {@link #update} own no transaction and ignore it.
   *
   * @throws HaltSQLException (usage) if a name is not a setting name or a value is null
   */
  public JdbcGuard transactionSettings(Map<String, String> s) throws HaltSQLException {
    Objects.requireNonNull(s, "settings");
    Map<String, String> copy = new LinkedHashMap<>();
    for (Map.Entry<String, String> e : s.entrySet()) {
      if (e.getKey() == null || !SETTING_NAME.matcher(e.getKey()).matches()) {
        throw HaltSQLClient.usage("invalid setting name: '" + e.getKey() + "'");
      }
      if (e.getValue() == null) {
        throw HaltSQLClient.usage("setting '" + e.getKey() + "' must not be null");
      }
      copy.put(e.getKey(), e.getValue());
    }
    return new JdbcGuard(client, onVerdict, requireByteIdentical, allowShadow, copy);
  }

  /**
   * The value that pins a verdict's search path: each schema of {@code policy().searchPath()}
   * double-quoted (embedded quotes doubled), joined with {@code ", "}; {@code null} when the
   * engine did not report a search path.
   *
   * <p>{@link #queryInTransaction} and {@link #updateInTransaction} apply it for you. If you run
   * verified SQL yourself, execute {@code SELECT set_config('search_path', ?, true)} with this
   * value in the same transaction, before the verified statement.
   */
  public static String searchPathSetting(Verdict verdict) {
    List<String> searchPath = verdict.policy().searchPath();
    if (searchPath == null) return null;
    List<String> quoted = new ArrayList<>();
    for (String schema : searchPath) {
      quoted.add('"' + schema.replace("\"", "\"\"") + '"');
    }
    return String.join(", ", quoted);
  }

  /** Verifies {@code sql}; returns only if it may run. Nothing is sent to the database. */
  private Authorized authorize(
      Connection conn, String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException, SQLException {
    Objects.requireNonNull(conn, "conn");
    Objects.requireNonNull(sql, "sql");
    String driver = conn.getMetaData().getDriverName();
    if (!PGJDBC_DRIVER_NAME.equals(driver)) {
      throw HaltSQLClient.usage(
          "JdbcGuard supports only PgJDBC (org.postgresql), got driver '" + driver + "'");
    }
    JdbcSql jsql = JdbcSql.translate(sql);
    if (requireByteIdentical && !jsql.byteIdentical()) {
      throw HaltSQLClient.usage("placeholders are repeated or out of order; PgJDBC would renumber them");
    }
    Verdict v = client.verify(sql, context, opts);
    onVerdict.accept(v);
    if (!v.allowed() || (!allowShadow && !v.shadowReasons().isEmpty())) {
      throw new HaltSQLDeniedException(v);
    }
    BindParam[] params = BindParams.ordered(v);
    jsql.checkCovers(params.length);
    return new Authorized(v, jsql, params);
  }

  /** Prepares the verified statement and binds the verdict's values. */
  private static PreparedStatement bind(Connection conn, Authorized a) throws SQLException {
    JdbcSql jsql = a.jsql();
    BindParam[] params = a.params();
    PreparedStatement ps = conn.prepareStatement(jsql.jdbcSql());
    try {
      int idx = 1;
      for (int p : jsql.order()) {
        BindParam bp = params[p - 1];
        String value = bp.isSet() ? BindParams.pgArrayLiteral(bp.values()) : bp.value();
        ps.setObject(idx++, value, Types.OTHER);
      }
      return ps;
    } catch (SQLException | RuntimeException e) {
      ps.close();
      throw e;
    }
  }

  /**
   * Low-level form: verifies {@code sql} and returns a bound {@link PreparedStatement} for it. The
   * caller executes and closes it. <b>Does not pin the search path</b> (see the class comment);
   * {@link #queryInTransaction} does.
   *
   * @throws HaltSQLDeniedException if the policy denies the SQL (nothing is prepared)
   * @throws HaltSQLException on any other HaltSQL failure (nothing is prepared)
   */
  public PreparedStatement prepare(
      Connection conn, String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException, SQLException {
    return bind(conn, authorize(conn, sql, context, opts));
  }

  /** {@link #prepare(Connection, String, Map, VerifyOptions)} with no options. */
  public PreparedStatement prepare(Connection conn, String sql, Map<String, ?> context)
      throws HaltSQLException, SQLException {
    return prepare(conn, sql, context, VerifyOptions.NONE);
  }

  /**
   * Low-level form: verifies, runs the query as one statement on the connection as it is, hands
   * the result set to {@code handler}, and closes everything. <b>Does not pin the search path</b>
   * (see the class comment); {@link #queryInTransaction} does.
   */
  public <T> T query(
      Connection conn,
      String sql,
      Map<String, ?> context,
      VerifyOptions opts,
      ResultSetHandler<T> handler)
      throws HaltSQLException, SQLException {
    try (PreparedStatement ps = prepare(conn, sql, context, opts);
        ResultSet rs = ps.executeQuery()) {
      return handler.handle(rs);
    }
  }

  /** {@link #query(Connection, String, Map, VerifyOptions, ResultSetHandler)} with no options. */
  public <T> T query(
      Connection conn, String sql, Map<String, ?> context, ResultSetHandler<T> handler)
      throws HaltSQLException, SQLException {
    return query(conn, sql, context, VerifyOptions.NONE, handler);
  }

  /**
   * Low-level form: verifies and runs a statement that returns no rows; returns the update count.
   * <b>Does not pin the search path</b> (see the class comment); {@link #updateInTransaction}
   * does.
   */
  public int update(Connection conn, String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException, SQLException {
    try (PreparedStatement ps = prepare(conn, sql, context, opts)) {
      return ps.executeUpdate();
    }
  }

  /**
   * Verifies {@code sql} and, only if it is allowed, runs it in a transaction on {@code conn} that
   * uses the verdict's search path, then hands the result set to {@code handler}.
   *
   * <p>In order:
   *
   * <ol>
   *   <li>autocommit is turned off if it was on, which makes PgJDBC send {@code BEGIN};
   *   <li>{@code SET TRANSACTION READ ONLY} when the verdict's statement kind is {@code select};
   *   <li>{@code SELECT set_config(name, value, true)} for each of {@link #transactionSettings};
   *   <li>{@code SELECT set_config('search_path', <verdict.policy().searchPath()>, true)}, every
   *       schema quoted as an identifier. It is transaction-local: the session's own search path
   *       is back afterwards. Skipped when the verdict has no search path (an engine older than
   *       the field);
   *   <li>the verified statement with the verdict's bind params; {@code handler} reads the result
   *       set, which is closed before the transaction ends;
   *   <li>{@code commit()}. On any error, including one thrown by {@code handler}, {@code
   *       rollback()}, and the error is rethrown;
   *   <li>autocommit is turned back on if it was on.
   * </ol>
   *
   * <p>The connection must have no transaction in progress. With autocommit off the guard's
   * transaction is the connection's next one: it is committed or rolled back as above and
   * autocommit stays off. A connection that PgJDBC reports as being inside a transaction is
   * refused with a usage error, because committing would also commit the caller's earlier work.
   *
   * @throws HaltSQLDeniedException if the policy denies the SQL (no transaction is opened)
   * @throws HaltSQLException on any other HaltSQL failure (no transaction is opened)
   */
  public <T> T queryInTransaction(
      Connection conn,
      String sql,
      Map<String, ?> context,
      VerifyOptions opts,
      ResultSetHandler<T> handler)
      throws HaltSQLException, SQLException {
    Objects.requireNonNull(handler, "handler");
    Authorized a = authorize(conn, sql, context, opts);
    return inTransaction(
        conn,
        a,
        ps -> {
          try (ResultSet rs = ps.executeQuery()) {
            return handler.handle(rs);
          }
        });
  }

  /** {@link #queryInTransaction(Connection, String, Map, VerifyOptions, ResultSetHandler)} with no options. */
  public <T> T queryInTransaction(
      Connection conn, String sql, Map<String, ?> context, ResultSetHandler<T> handler)
      throws HaltSQLException, SQLException {
    return queryInTransaction(conn, sql, context, VerifyOptions.NONE, handler);
  }

  /**
   * {@link #queryInTransaction} for a statement that returns no rows (a write allowed by a write
   * policy): the same pinned transaction, read-only only if the verdict is for a select. Returns
   * the update count after the commit.
   */
  public int updateInTransaction(
      Connection conn, String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException, SQLException {
    Authorized a = authorize(conn, sql, context, opts);
    return inTransaction(conn, a, PreparedStatement::executeUpdate);
  }

  /** {@link #updateInTransaction(Connection, String, Map, VerifyOptions)} with no options. */
  public int updateInTransaction(Connection conn, String sql, Map<String, ?> context)
      throws HaltSQLException, SQLException {
    return updateInTransaction(conn, sql, context, VerifyOptions.NONE);
  }

  private <T> T inTransaction(Connection conn, Authorized a, StatementBody<T> body)
      throws HaltSQLException, SQLException {
    String state = transactionState(conn);
    if (state != null && !state.equals("IDLE")) {
      throw HaltSQLClient.usage(
          "the connection has a transaction in progress; commit or roll it back first");
    }
    boolean autoCommit = conn.getAutoCommit();
    if (autoCommit) conn.setAutoCommit(false);
    Throwable failure = null;
    try {
      T result = runPinned(conn, a, body);
      conn.commit();
      return result;
    } catch (SQLException | RuntimeException | Error e) {
      failure = e;
      try {
        conn.rollback();
      } catch (SQLException rollbackFailure) {
        e.addSuppressed(rollbackFailure);
      }
      throw e;
    } finally {
      if (autoCommit) {
        try {
          conn.setAutoCommit(true);
        } catch (SQLException restoreFailure) {
          if (failure == null) throw restoreFailure;
          failure.addSuppressed(restoreFailure);
        }
      }
    }
  }

  /** Inside the transaction: read-only, the settings, the pin, then the verified statement. */
  private <T> T runPinned(Connection conn, Authorized a, StatementBody<T> body)
      throws SQLException {
    if ("select".equals(a.verdict().statementKind())) {
      try (Statement s = conn.createStatement()) {
        s.execute("SET TRANSACTION READ ONLY");
      }
    }
    List<Map.Entry<String, String>> all = new ArrayList<>(settings.entrySet());
    String pin = searchPathSetting(a.verdict());
    // The pin goes last so that it wins over a search_path in the settings.
    if (pin != null) all.add(Map.entry("search_path", pin));
    for (Map.Entry<String, String> e : all) {
      try (PreparedStatement ps = conn.prepareStatement("SELECT set_config(?, ?, true)")) {
        ps.setString(1, e.getKey());
        ps.setString(2, e.getValue());
        ps.execute();
      }
    }
    try (PreparedStatement ps = bind(conn, a)) {
      return body.run(ps);
    }
  }

  /**
   * PgJDBC's transaction state ({@code IDLE}, {@code OPEN} or {@code FAILED}), or {@code null}
   * when it cannot be read (a pool's wrapper that does not unwrap to PgJDBC). Read reflectively:
   * the SDK does not depend on PgJDBC at compile time.
   */
  private static String transactionState(Connection conn) {
    try {
      Class<?> base =
          Class.forName("org.postgresql.core.BaseConnection", false, conn.getClass().getClassLoader());
      if (!conn.isWrapperFor(base)) return null;
      Object state = base.getMethod("getTransactionState").invoke(conn.unwrap(base));
      return state == null ? null : state.toString();
    } catch (ReflectiveOperationException | SQLException | RuntimeException | LinkageError e) {
      return null;
    }
  }
}
