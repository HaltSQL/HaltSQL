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
            + describe(verdict),
        null,
        null);
    this.verdict = verdict;
  }

  private static String describe(Verdict verdict) {
    if (!verdict.reasons().isEmpty()) return String.join(", ", verdict.codes());
    if (verdict.shadowReasons().isEmpty()) return "no reasons";
    StringBuilder sb = new StringBuilder("shadow mode would deny: ");
    for (int i = 0; i < verdict.shadowReasons().size(); i++) {
      if (i > 0) sb.append(", ");
      sb.append(verdict.shadowReasons().get(i).code());
    }
    return sb.toString();
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
