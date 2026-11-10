package com.haltsql.client;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Guarded execution with PgJDBC: verify with HaltSQL, and only if allowed, run the verified SQL
 * with its bind params.
 *
 * <p>How the SQL reaches Postgres: see {@link JdbcSql}. Each {@code $n} becomes a {@code ?} that
 * PgJDBC renumbers back to {@code $1..$k}; when the verified SQL uses its placeholders in order
 * (the common case) PgJDBC sends the verified string byte for byte. Values are bound with {@code
 * setObject(i, value, Types.OTHER)}, which PgJDBC sends with an unspecified type so the server
 * infers it from the column (a tenant id string binds into {@code text}, {@code bigint} or {@code
 * uuid} columns alike); a set is bound as a Postgres array literal for {@code col = ANY($n)}.
 *
 * <pre>{@code
 * JdbcGuard guard = new JdbcGuard(haltsql);
 * List<Long> ids = guard.query(conn,
 *     "SELECT id FROM orders WHERE tenant_id = $1 LIMIT 50",
 *     Map.of("tenant_id", session.tenantId()),
 *     rs -> { List<Long> out = new ArrayList<>(); while (rs.next()) out.add(rs.getLong(1)); return out; });
 * }</pre>
 *
 * <p>Instances are immutable and thread-safe; connections are not, as usual in JDBC.
 */
public final class JdbcGuard {
  /** PgJDBC's {@code DatabaseMetaData.getDriverName()}. */
  static final String PGJDBC_DRIVER_NAME = "PostgreSQL JDBC Driver";

  /** Reads a result set. */
  @FunctionalInterface
  public interface ResultSetHandler<T> {
    T handle(ResultSet rs) throws SQLException;
  }

  private final HaltSQLClient client;
  private final Consumer<Verdict> onVerdict;
  private final boolean requireByteIdentical;
  private final boolean allowShadow;

  public JdbcGuard(HaltSQLClient client) {
    this(client, v -> {}, false, false);
  }

  private JdbcGuard(
      HaltSQLClient client, Consumer<Verdict> onVerdict, boolean strict, boolean allowShadow) {
    this.client = Objects.requireNonNull(client, "client");
    this.onVerdict = Objects.requireNonNull(onVerdict, "onVerdict");
    this.requireByteIdentical = strict;
    this.allowShadow = allowShadow;
  }

  /**
   * A copy that runs SQL a shadow-mode policy would deny (an allowed verdict with shadow reasons).
   * Without it such a verdict throws {@link HaltSQLDeniedException}, so switching a policy to
   * shadow on the server cannot by itself turn enforcement off in this application.
   */
  public JdbcGuard allowShadow() {
    return new JdbcGuard(client, onVerdict, requireByteIdentical, true);
  }

  /** A copy that calls {@code c} with every verdict (allowed or denied), e.g. for audit logs. */
  public JdbcGuard onVerdict(Consumer<Verdict> c) {
    return new JdbcGuard(client, c, requireByteIdentical, allowShadow);
  }

  /**
   * A copy that refuses SQL whose placeholders are repeated or out of order, so PgJDBC always
   * sends the verified string byte for byte.
   */
  public JdbcGuard requireByteIdenticalSql() {
    return new JdbcGuard(client, onVerdict, true, allowShadow);
  }

  /**
   * Verifies {@code sql} and returns a bound {@link PreparedStatement} for it. The caller executes
   * and closes it.
   *
   * @throws HaltSQLDeniedException if the policy denies the SQL (nothing is prepared)
   * @throws HaltSQLException on any other HaltSQL failure (nothing is prepared)
   */
  public PreparedStatement prepare(
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

  /** {@link #prepare(Connection, String, Map, VerifyOptions)} with no options. */
  public PreparedStatement prepare(Connection conn, String sql, Map<String, ?> context)
      throws HaltSQLException, SQLException {
    return prepare(conn, sql, context, VerifyOptions.NONE);
  }

  /** Verifies, runs the query, hands the result set to {@code handler}, and closes everything. */
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

  /** Verifies and runs a statement that returns no rows; returns the update count. */
  public int update(Connection conn, String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException, SQLException {
    try (PreparedStatement ps = prepare(conn, sql, context, opts)) {
      return ps.executeUpdate();
    }
  }
}
