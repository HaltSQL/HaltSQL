package com.haltsql.client;

import java.util.Objects;
import java.util.OptionalInt;

/**
 * One reason a statement was (or, in shadow mode, would have been) denied.
 * Match on {@link #code()}, never on {@link #message()}.
 *
 * @param code stable reason code such as {@code E_TENANT_MISSING}; unknown codes mean deny
 * @param message human-readable explanation (not stable)
 * @param rule identifier of the rule that produced the reason (not stable)
 * @param loc byte offset into the SQL string, or -1 when unknown
 * @param hint short instruction an LLM agent can follow, or null
 */
public record Reason(String code, String message, String rule, int loc, String hint) {
  public Reason {
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
    Objects.requireNonNull(rule, "rule");
  }

  /** The byte offset, if the server reported one. */
  public OptionalInt location() {
    return loc >= 0 ? OptionalInt.of(loc) : OptionalInt.empty();
  }
}
