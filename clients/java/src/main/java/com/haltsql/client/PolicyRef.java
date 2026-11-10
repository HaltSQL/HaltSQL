package com.haltsql.client;

import java.util.List;

/**
 * The policy that produced a verdict.
 *
 * @param name {@code metadata.name} of the policy
 * @param version {@code sha256:<hex>} hash of the normalized policy
 * @param searchPath the schemas unqualified names were resolved against, or {@code null} from an
 *     engine that does not report it. The verdict holds only if the session that runs the SQL
 *     uses this search path.
 */
public record PolicyRef(String name, String version, List<String> searchPath) {
  public PolicyRef {
    searchPath = searchPath == null ? null : List.copyOf(searchPath);
  }

  /** A reference without a search path. */
  public PolicyRef(String name, String version) {
    this(name, version, null);
  }
}
