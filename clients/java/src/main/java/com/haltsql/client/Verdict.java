package com.haltsql.client;

import java.util.List;

/**
 * The verdict for one SQL string. Only {@code allowed() == true} permits
 * running the SQL, and only the exact string that was verified.
 *
 * @param allowed true only if the caller may run this exact SQL string
 * @param reasons why the statement was denied (empty when allowed)
 * @param shadowReasons shadow mode only: why it would have been denied
 * @param policy the policy that decided
 * @param statementKind select, insert, update, delete, or null
 * @param tables relations read or written ({@code schema.table})
 * @param columns columns read ({@code schema.table.column})
 * @param bindParams values to bind, one per {@code $n}; empty when denied
 * @param fingerprint libpg_query fingerprint, or null if the SQL did not parse
 * @param sqlSha256 lower-case hex SHA-256 of the exact SQL string
 * @param elapsedUs verification time in microseconds
 */
public record Verdict(
    boolean allowed,
    List<Reason> reasons,
    List<Reason> shadowReasons,
    PolicyRef policy,
    String statementKind,
    List<String> tables,
    List<String> columns,
    List<BindParam> bindParams,
    String fingerprint,
    String sqlSha256,
    long elapsedUs) {

  public Verdict {
    reasons = List.copyOf(reasons);
    shadowReasons = List.copyOf(shadowReasons);
    tables = List.copyOf(tables);
    columns = List.copyOf(columns);
    bindParams = List.copyOf(bindParams);
  }

  /** Reason codes in server order. */
  public List<String> codes() {
    return reasons.stream().map(Reason::code).toList();
  }
}
