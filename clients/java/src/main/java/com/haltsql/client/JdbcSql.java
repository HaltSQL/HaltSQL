package com.haltsql.client;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Translation of verified PostgreSQL ({@code $n} placeholders) into the JDBC form PgJDBC
 * expects ({@code ?} placeholders).
 *
 * <p>Why: PgJDBC only recognizes {@code ?}; a literal {@code $1} in a {@code PreparedStatement} is
 * sent as-is with zero bound parameters, so the statement fails. PgJDBC itself rewrites each
 * {@code ?} to {@code $1, $2, ...} in order before sending the query. So when the verified SQL
 * uses its placeholders in textual order {@code $1..$k}, each once, replacing them with {@code ?}
 * makes PgJDBC send <b>byte-for-byte the verified string</b> ({@link #byteIdentical()} is true).
 * When placeholders repeat or appear out of order, each occurrence becomes its own {@code ?}
 * bound to the same value; the server then receives the verified statement with renumbered
 * placeholders and the same values in the same positions.
 *
 * <p>The translation is deliberately strict and fails closed. It rejects SQL that contains
 * {@code ?}, {@code {} or {@code }} anywhere (PgJDBC would treat them as placeholders or JDBC
 * escapes), unterminated quotes or comments, and placeholders glued to identifier characters. It
 * understands single-quoted strings (including {@code E''} escapes), quoted identifiers,
 * dollar-quoted strings, line comments and nested block comments, and never touches text inside
 * them.
 *
 * @param jdbcSql the SQL with each code-level {@code $n} replaced by {@code ?}
 * @param order placeholder number for each {@code ?}, in order (1-based)
 * @param byteIdentical true when PgJDBC will send exactly the original string
 */
public record JdbcSql(String jdbcSql, List<Integer> order, boolean byteIdentical) {

  public JdbcSql {
    order = List.copyOf(order);
  }

  private static boolean identChar(char c) {
    return Character.isLetterOrDigit(c) || c == '_' || c == '$' || c >= 0x80;
  }

  private static boolean tagStart(char c) {
    return Character.isLetter(c) || c == '_' || c >= 0x80;
  }

  private static boolean tagChar(char c) {
    return Character.isLetterOrDigit(c) || c == '_' || c >= 0x80;
  }

  /**
   * Translates {@code sql}.
   *
   * @throws HaltSQLException (USAGE) if the SQL cannot be translated safely
   */
  public static JdbcSql translate(String sql) throws HaltSQLException {
    for (int i = 0; i < sql.length(); i++) {
      char c = sql.charAt(i);
      if (c == '?' || c == '{' || c == '}') {
        throw HaltSQLClient.usage(
            "SQL containing '" + c + "' cannot be run safely through JDBC (offset " + i + ")");
      }
    }
    StringBuilder out = new StringBuilder(sql.length());
    List<Integer> order = new ArrayList<>();
    int n = sql.length();
    int i = 0;
    while (i < n) {
      char c = sql.charAt(i);
      char prev = i > 0 ? sql.charAt(i - 1) : '\0';
      if (c == '\'') {
        boolean escapes =
            (prev == 'E' || prev == 'e') && (i < 2 || !identChar(sql.charAt(i - 2)));
        int j = i + 1;
        while (true) {
          if (j >= n) throw HaltSQLClient.usage("unterminated string literal at offset " + i);
          char d = sql.charAt(j);
          if (escapes && d == '\\') {
            j += 2;
            continue;
          }
          if (d == '\'') {
            if (j + 1 < n && sql.charAt(j + 1) == '\'') {
              j += 2;
              continue;
            }
            break;
          }
          j++;
        }
        out.append(sql, i, j + 1);
        i = j + 1;
      } else if (c == '"') {
        int j = i + 1;
        while (true) {
          if (j >= n) throw HaltSQLClient.usage("unterminated quoted identifier at offset " + i);
          if (sql.charAt(j) == '"') {
            if (j + 1 < n && sql.charAt(j + 1) == '"') {
              j += 2;
              continue;
            }
            break;
          }
          j++;
        }
        out.append(sql, i, j + 1);
        i = j + 1;
      } else if (c == '-' && i + 1 < n && sql.charAt(i + 1) == '-') {
        int j = i;
        while (j < n && sql.charAt(j) != '\n' && sql.charAt(j) != '\r') j++;
        out.append(sql, i, j);
        i = j;
      } else if (c == '/' && i + 1 < n && sql.charAt(i + 1) == '*') {
        int depth = 1;
        int j = i + 2;
        while (depth > 0) {
          if (j + 1 >= n) throw HaltSQLClient.usage("unterminated comment at offset " + i);
          if (sql.charAt(j) == '/' && sql.charAt(j + 1) == '*') {
            depth++;
            j += 2;
          } else if (sql.charAt(j) == '*' && sql.charAt(j + 1) == '/') {
            depth--;
            j += 2;
          } else {
            j++;
          }
        }
        out.append(sql, i, j);
        i = j;
      } else if (c == '$' && !identChar(prev)) {
        if (i + 1 < n && Character.isDigit(sql.charAt(i + 1)) && sql.charAt(i + 1) < 0x80) {
          int j = i + 1;
          while (j < n && sql.charAt(j) >= '0' && sql.charAt(j) <= '9') j++;
          if (j < n && identChar(sql.charAt(j))) {
            throw HaltSQLClient.usage("placeholder followed by identifier characters at offset " + i);
          }
          String digits = sql.substring(i + 1, j);
          if (digits.length() > 6) throw HaltSQLClient.usage("placeholder number too large at offset " + i);
          order.add(Integer.parseInt(digits));
          out.append('?');
          i = j;
        } else {
          // Dollar-quoted string: $tag$ ... $tag$ (tag may be empty).
          int j = i + 1;
          if (j < n && tagStart(sql.charAt(j))) {
            j++;
            while (j < n && tagChar(sql.charAt(j))) j++;
          }
          if (j < n && sql.charAt(j) == '$') {
            String tag = sql.substring(i, j + 1);
            int end = sql.indexOf(tag, j + 1);
            if (end < 0) throw HaltSQLClient.usage("unterminated dollar-quoted string at offset " + i);
            out.append(sql, i, end + tag.length());
            i = end + tag.length();
          } else {
            out.append(c);
            i++;
          }
        }
      } else {
        out.append(c);
        i++;
      }
    }
    boolean identical = true;
    for (int k = 0; k < order.size(); k++) identical &= order.get(k) == k + 1;
    return new JdbcSql(out.toString(), order, identical);
  }

  /**
   * Checks that the placeholders used are exactly {@code $1..$n} for {@code n} bind params.
   *
   * @throws HaltSQLException (USAGE) otherwise
   */
  void checkCovers(int n) throws HaltSQLException {
    boolean[] seen = new boolean[n];
    for (int p : order) {
      if (p < 1 || p > n) {
        throw HaltSQLClient.usage("SQL uses $" + p + " but the verdict binds $1..$" + n);
      }
      seen[p - 1] = true;
    }
    for (int k = 0; k < n; k++) {
      if (!seen[k]) throw HaltSQLClient.usage("verdict binds $" + (k + 1) + " but the SQL never uses it");
    }
  }

  @Override
  public String toString() {
    return "JdbcSql[" + jdbcSql + ", order=" + Arrays.toString(order.toArray()) + "]";
  }
}
