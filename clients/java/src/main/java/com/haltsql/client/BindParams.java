package com.haltsql.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Helpers that turn a verdict's bind params into positional driver parameters. */
public final class BindParams {
  private BindParams() {}

  /**
   * Returns the positional parameters for an allowed verdict: element {@code i} is the value of
   * {@code $(i+1)}, a {@code String} or (for a set) an unmodifiable {@code List<String>}.
   *
   * @throws HaltSQLException (USAGE) if the verdict is not an allow, or if the params are not
   *     exactly {@code $1..$n} with each number present once
   */
  public static List<Object> positional(Verdict v) throws HaltSQLException {
    BindParam[] slots = ordered(v);
    List<Object> out = new ArrayList<>(slots.length);
    for (BindParam p : slots) out.add(p.isSet() ? p.values() : p.value());
    return out;
  }

  static BindParam[] ordered(Verdict v) throws HaltSQLException {
    if (v == null || !v.allowed()) {
      throw HaltSQLClient.usage("refusing to build parameters for a denied verdict");
    }
    int n = v.bindParams().size();
    BindParam[] slots = new BindParam[n];
    for (BindParam p : v.bindParams()) {
      if (p.param() < 1 || p.param() > n) {
        throw HaltSQLClient.usage(
            "bind param $" + p.param() + " is outside $1..$" + n + "; placeholders must be contiguous");
      }
      if (slots[p.param() - 1] != null) {
        throw HaltSQLClient.usage("bind param $" + p.param() + " appears more than once");
      }
      slots[p.param() - 1] = p;
    }
    return Arrays.copyOf(slots, n);
  }

  /**
   * Encodes strings as a Postgres array literal ({@code {"a","b"}}). Every element is
   * double-quoted with {@code "} and {@code \} escaped, so the literal is unambiguous.
   */
  public static String pgArrayLiteral(List<String> values) {
    StringBuilder b = new StringBuilder("{");
    for (int i = 0; i < values.size(); i++) {
      if (i > 0) b.append(',');
      b.append('"');
      String s = values.get(i);
      for (int j = 0; j < s.length(); j++) {
        char c = s.charAt(j);
        if (c == '"' || c == '\\') b.append('\\');
        b.append(c);
      }
      b.append('"');
    }
    return b.append('}').toString();
  }
}
