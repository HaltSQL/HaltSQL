package com.haltsql.client;

import java.util.List;

/**
 * A value the caller must bind to placeholder {@code $param}.
 *
 * @param param placeholder number n of {@code $n} (1-based)
 * @param value the scalar value, or null when this is a set
 * @param values the set value (for {@code col = ANY($n)}), or null when scalar
 */
public record BindParam(int param, String value, List<String> values) {
  public BindParam {
    if (param < 1) throw new IllegalArgumentException("param must be >= 1");
    if ((value == null) == (values == null)) {
      throw new IllegalArgumentException("exactly one of value or values must be set");
    }
    values = values == null ? null : List.copyOf(values);
  }

  /** A scalar bind param. */
  public static BindParam scalar(int param, String value) {
    return new BindParam(param, value, null);
  }

  /** A set-valued bind param. */
  public static BindParam set(int param, List<String> values) {
    return new BindParam(param, null, values);
  }

  /** True when the value is a set of strings. */
  public boolean isSet() {
    return values != null;
  }
}
