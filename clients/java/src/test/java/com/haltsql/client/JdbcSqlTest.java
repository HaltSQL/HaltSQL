package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class JdbcSqlTest {

  /** What PgJDBC sends: each ? replaced by $1, $2, ... in order. */
  static String pgjdbcWire(String jdbc) {
    StringBuilder b = new StringBuilder();
    int k = 1;
    for (char c : jdbc.toCharArray()) {
      if (c == '?') b.append('$').append(k++);
      else b.append(c);
    }
    return b.toString();
  }

  @Test
  void inOrderPlaceholdersRoundTripByteIdentical() throws Exception {
    String sql = "SELECT id FROM orders WHERE tenant_id = $1 AND customer_id = $2 LIMIT 50";
    JdbcSql j = JdbcSql.translate(sql);
    assertEquals("SELECT id FROM orders WHERE tenant_id = ? AND customer_id = ? LIMIT 50", j.jdbcSql());
    assertEquals(List.of(1, 2), j.order());
    assertTrue(j.byteIdentical());
    assertEquals(sql, pgjdbcWire(j.jdbcSql()));
  }

  @Test
  void outOfOrderAndRepeatedMapByOccurrence() throws Exception {
    JdbcSql j =
        JdbcSql.translate(
            "SELECT o.id FROM orders o JOIN customers c ON c.tenant_id = $2 WHERE o.tenant_id = $1 OR o.x = $1 LIMIT 10");
    assertEquals(List.of(2, 1, 1), j.order());
    assertFalse(j.byteIdentical());
    assertEquals(
        "SELECT o.id FROM orders o JOIN customers c ON c.tenant_id = ? WHERE o.tenant_id = ? OR o.x = ? LIMIT 10",
        j.jdbcSql());
  }

  @Test
  void literalsCommentsAndIdentifiersAreNotTouched() throws Exception {
    String sql =
        "SELECT 'cost $1', E'it\\'s $2', \"col$1\", a$1, $$ $1 $$, $tag$ $2 $tag$ -- $3\n"
            + " /* $4 /* nested $5 */ still */ FROM t WHERE x = $1 LIMIT 1";
    JdbcSql j = JdbcSql.translate(sql);
    assertEquals(List.of(1), j.order());
    assertEquals(sql.replace("x = $1", "x = ?"), j.jdbcSql());
    assertTrue(j.byteIdentical());
  }

  @Test
  void doubledQuotesStayInside() throws Exception {
    JdbcSql j = JdbcSql.translate("SELECT 'a''$1', \"b\"\"$1\" FROM t WHERE c = $1");
    assertEquals(List.of(1), j.order());
    assertEquals("SELECT 'a''$1', \"b\"\"$1\" FROM t WHERE c = ?", j.jdbcSql());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "SELECT data ? 'k' FROM t WHERE a = $1",
        "SELECT '?' FROM t",
        "SELECT {fn now()} FROM t",
        "SELECT '{1,2}'::int[] FROM t",
        "SELECT 'unterminated FROM t",
        "SELECT \"unterminated FROM t",
        "SELECT 1 /* unterminated",
        "SELECT $q$ unterminated",
        "SELECT x FROM t WHERE a = $1abc",
        "SELECT x FROM t WHERE a = $1234567",
      })
  void unsafeSqlIsRefused(String sql) {
    HaltSQLException e = assertThrows(HaltSQLException.class, () -> JdbcSql.translate(sql));
    assertEquals(HaltSQLException.Kind.USAGE, e.kind());
  }

  /** With standard_conforming_strings a backslash is an ordinary character outside E'' strings. */
  @Test
  void backslashIsAnEscapeOnlyInEStrings() throws Exception {
    JdbcSql plain = JdbcSql.translate("SELECT 'a\\' , $1 , 'b'");
    assertEquals(List.of(1), plain.order());
    assertEquals("SELECT 'a\\' , ? , 'b'", plain.jdbcSql());
    // "date" ends in e, but date'...' is a typed literal, not an E'' string.
    JdbcSql typed = JdbcSql.translate("SELECT date'2026-01-01\\' , $1 , 'b'");
    assertEquals(List.of(1), typed.order());
    assertEquals("SELECT date'2026-01-01\\' , ? , 'b'", typed.jdbcSql());
    JdbcSql e = JdbcSql.translate("SELECT e'a\\' , $1 , ' FROM t WHERE x = $2");
    assertEquals(List.of(2), e.order());
  }

  @Test
  void lineCommentEndsAtCarriageReturnToo() throws Exception {
    JdbcSql j = JdbcSql.translate("SELECT 1 -- $2 in a comment\r WHERE a = $1 -- $3\n AND b = $2");
    assertEquals(List.of(1, 2), j.order());
    assertEquals("SELECT 1 -- $2 in a comment\r WHERE a = ? -- $3\n AND b = ?", j.jdbcSql());
  }

  @Test
  void placeholderAfterAnInnerCommentEndIsStillInsideTheComment() throws Exception {
    JdbcSql j = JdbcSql.translate("SELECT 1 /* a /* b */ $2 */ WHERE x = $1");
    assertEquals(List.of(1), j.order());
    assertEquals("SELECT 1 /* a /* b */ $2 */ WHERE x = ?", j.jdbcSql());
    assertTrue(j.byteIdentical());
  }

  @Test
  void coverageCheck() throws Exception {
    JdbcSql.translate("SELECT 1 WHERE a = $1 AND b = $2").checkCovers(2);
    assertThrows(HaltSQLException.class, () -> JdbcSql.translate("SELECT 1 WHERE a = $2").checkCovers(2));
    assertThrows(HaltSQLException.class, () -> JdbcSql.translate("SELECT 1 WHERE a = $3").checkCovers(2));
    assertThrows(HaltSQLException.class, () -> JdbcSql.translate("SELECT 1").checkCovers(1));
    assertThrows(HaltSQLException.class, () -> JdbcSql.translate("SELECT 1 WHERE a = $0").checkCovers(1));
    assertThrows(HaltSQLException.class, () -> JdbcSql.translate("SELECT 1 WHERE a = $0 AND b = $1").checkCovers(1));
  }
}
