package com.haltsql.client;

import java.util.List;

/** Raised by {@link JdbcGuard} when the policy denies the SQL; nothing reached the database. */
public final class HaltSQLDeniedException extends HaltSQLException {
  private static final long serialVersionUID = 1L;
  private final transient Verdict verdict;

  public HaltSQLDeniedException(Verdict verdict) {
    super(
        Kind.DENIED,
        "denied by policy "
            + verdict.policy().name()
            + ": "
            + (verdict.reasons().isEmpty() ? "no reasons" : String.join(", ", verdict.codes())),
        null,
        null);
    this.verdict = verdict;
  }

  /** The deny verdict; return its reasons (codes, messages, hints) to the agent. */
  public Verdict verdict() {
    return verdict;
  }

  /** Reason codes in server order. */
  public List<String> codes() {
    return verdict.codes();
  }
}
