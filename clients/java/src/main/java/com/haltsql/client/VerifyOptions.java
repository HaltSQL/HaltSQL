package com.haltsql.client;

/**
 * Per-call options for {@link HaltSQLClient#verify(String, java.util.Map, VerifyOptions)}.
 *
 * @param policy policy name, or null; with a token it must equal the token's pinned policy
 * @param requestId value for {@code X-Request-Id}, or null
 */
public record VerifyOptions(String policy, String requestId) {
  /** No options. */
  public static final VerifyOptions NONE = new VerifyOptions(null, null);

  /** Options naming a policy. */
  public static VerifyOptions policy(String name) {
    return new VerifyOptions(name, null);
  }

  /** A copy with the given request id. */
  public VerifyOptions withRequestId(String id) {
    return new VerifyOptions(policy, id);
  }
}
