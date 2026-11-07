package com.haltsql.client;

/**
 * Base class of every error this SDK raises. Every error means <b>deny</b>:
 * the SQL must not run. {@link #allowed()} always returns false.
 */
public class HaltSQLException extends Exception {
  private static final long serialVersionUID = 1L;

  /** Classification of the failure. */
  public enum Kind {
    /** The server answered with a non-200 status. */
    HTTP,
    /** The request could not be sent or the connection failed. */
    TRANSPORT,
    /** An attempt did not finish within the configured timeout. */
    TIMEOUT,
    /** The body is not a valid verdict, or its sql_sha256 does not match. */
    PROTOCOL,
    /** Invalid arguments, options, or an SQL string the JDBC path cannot run safely. */
    USAGE,
    /** The policy denied the SQL (guarded execution only). */
    DENIED
  }

  private final Kind kind;
  private final String requestId;

  public HaltSQLException(Kind kind, String message, String requestId, Throwable cause) {
    super("haltsql: " + message, cause);
    this.kind = kind;
    this.requestId = requestId;
  }

  public HaltSQLException(Kind kind, String message) {
    this(kind, message, null, null);
  }

  /** The failure kind. */
  public Kind kind() {
    return kind;
  }

  /** X-Request-Id of the last attempt, or null. */
  public String requestId() {
    return requestId;
  }

  /** Always false: an error is never an allow. */
  public final boolean allowed() {
    return false;
  }
}
