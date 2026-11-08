package com.haltsql.client;

/** The server answered with a non-200 status ({@code {"error":{code,message}}}). */
public final class HaltSQLHttpException extends HaltSQLException {
  private static final long serialVersionUID = 1L;
  private final int status;
  private final String code;

  public HaltSQLHttpException(int status, String code, String message, String requestId) {
    super(Kind.HTTP, "HTTP " + status + " " + code + ": " + message, requestId, null);
    this.status = status;
    this.code = code;
  }

  /** HTTP status code. */
  public int status() {
    return status;
  }

  /** {@code error.code} from the body (e.g. UNAUTHORIZED), or {@code HTTP_<status>}. */
  public String code() {
    return code;
  }
}
