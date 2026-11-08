package com.haltsql.client;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Strict JSON encoding and decoding of the wire format. Package-private. */
final class Wire {
  private Wire() {}

  private static final Pattern REASON_CODE = Pattern.compile("^E_[A-Z_]+$");
  private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");
  private static final long MAX_SAFE = (1L << 53) - 1;

  static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .build();

  static {
    MAPPER
        .getFactory()
        .setStreamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64).build());
  }

  static final class Invalid extends Exception {
    private static final long serialVersionUID = 1L;

    Invalid(String m) {
      super(m);
    }
  }

  static JsonNode parse(byte[] body) throws Invalid {
    try {
      JsonNode n = MAPPER.readTree(body);
      if (n == null || n.isMissingNode()) throw new Invalid("empty body");
      return n;
    } catch (java.io.IOException e) {
      throw new Invalid("body is not valid JSON");
    }
  }

  private static JsonNode req(JsonNode o, String k, String path) throws Invalid {
    JsonNode v = o.get(k);
    if (v == null) throw new Invalid(path + "." + k + " is missing");
    return v;
  }

  private static String str(JsonNode o, String k, String path) throws Invalid {
    JsonNode v = req(o, k, path);
    if (!v.isTextual()) throw new Invalid(path + "." + k + " must be a string");
    return v.textValue();
  }

  private static String nullableStr(JsonNode o, String k) throws Invalid {
    JsonNode v = req(o, k, "verdict");
    if (v.isNull()) return null;
    if (!v.isTextual()) throw new Invalid(k + " must be a string or null");
    return v.textValue();
  }

  private static List<String> strList(JsonNode o, String k) throws Invalid {
    JsonNode v = req(o, k, "verdict");
    if (!v.isArray()) throw new Invalid(k + " must be an array of strings");
    List<String> out = new ArrayList<>(v.size());
    for (JsonNode e : v) {
      if (!e.isTextual()) throw new Invalid(k + " must be an array of strings");
      out.add(e.textValue());
    }
    return out;
  }

  private static List<Reason> reasons(JsonNode o, String k) throws Invalid {
    JsonNode v = req(o, k, "verdict");
    if (!v.isArray()) throw new Invalid(k + " must be an array");
    List<Reason> out = new ArrayList<>(v.size());
    int i = 0;
    for (JsonNode r : v) {
      String path = k + "[" + i++ + "]";
      if (!r.isObject()) throw new Invalid(path + " must be an object");
      String code = str(r, "code", path);
      if (!REASON_CODE.matcher(code).matches()) throw new Invalid(path + ".code is not a reason code");
      int loc = -1;
      JsonNode l = r.get("loc");
      if (l != null) {
        if (!l.isInt() || l.intValue() < 0) throw new Invalid(path + ".loc must be a non-negative integer");
        loc = l.intValue();
      }
      String hint = null;
      if (r.get("hint") != null) hint = str(r, "hint", path);
      out.add(new Reason(code, str(r, "message", path), str(r, "rule", path), loc, hint));
    }
    return out;
  }

  private static List<BindParam> bindParams(JsonNode o) throws Invalid {
    JsonNode v = req(o, "bind_params", "verdict");
    if (!v.isArray()) throw new Invalid("bind_params must be an array");
    List<BindParam> out = new ArrayList<>(v.size());
    int i = 0;
    for (JsonNode b : v) {
      String path = "bind_params[" + i++ + "]";
      if (!b.isObject()) throw new Invalid(path + " must be an object");
      JsonNode p = req(b, "param", path);
      if (!p.isInt() || p.intValue() < 1) throw new Invalid(path + ".param must be an integer >= 1");
      JsonNode val = req(b, "value", path);
      if (val.isTextual()) {
        out.add(BindParam.scalar(p.intValue(), val.textValue()));
      } else if (val.isArray()) {
        List<String> vs = new ArrayList<>(val.size());
        for (JsonNode e : val) {
          if (!e.isTextual()) throw new Invalid(path + ".value must be a string or an array of strings");
          vs.add(e.textValue());
        }
        out.add(BindParam.set(p.intValue(), vs));
      } else {
        throw new Invalid(path + ".value must be a string or an array of strings");
      }
    }
    return out;
  }

  /** Strictly validates a verdict body; unknown extra fields are ignored. */
  static Verdict verdict(JsonNode o) throws Invalid {
    if (!o.isObject()) throw new Invalid("verdict must be a JSON object");
    JsonNode a = req(o, "allowed", "verdict");
    if (!a.isBoolean()) throw new Invalid("allowed must be a boolean");
    boolean allowed = a.booleanValue();
    List<Reason> reasons = reasons(o, "reasons");
    List<Reason> shadow = reasons(o, "shadow_reasons");
    JsonNode pol = req(o, "policy", "verdict");
    if (!pol.isObject()) throw new Invalid("policy must be an object");
    PolicyRef policy = new PolicyRef(str(pol, "name", "policy"), str(pol, "version", "policy"));
    String kind = nullableStr(o, "statement_kind");
    String fp = nullableStr(o, "fingerprint");
    String sha = str(o, "sql_sha256", "verdict");
    if (!HEX64.matcher(sha).matches()) throw new Invalid("sql_sha256 must be 64 lower-case hex digits");
    JsonNode el = req(o, "elapsed_us", "verdict");
    if (!el.canConvertToLong() || !el.isIntegralNumber() || el.longValue() < 0) {
      throw new Invalid("elapsed_us must be a non-negative integer");
    }
    if (allowed && !reasons.isEmpty()) throw new Invalid("allowed is true but reasons is not empty");
    return new Verdict(
        allowed,
        reasons,
        shadow,
        policy,
        kind,
        strList(o, "tables"),
        strList(o, "columns"),
        bindParams(o),
        fp,
        sha,
        el.longValue());
  }

  static List<PolicySummary> policies(JsonNode o) throws Invalid {
    JsonNode ps = o.isObject() ? o.get("policies") : null;
    if (ps == null || !ps.isArray()) throw new Invalid("policies must be an array");
    List<PolicySummary> out = new ArrayList<>();
    int i = 0;
    for (JsonNode p : ps) {
      String path = "policies[" + i++ + "]";
      if (!p.isObject()) throw new Invalid(path + " must be an object");
      out.add(new PolicySummary(str(p, "name", path), str(p, "version", path), str(p, "mode", path)));
    }
    return out;
  }

  private static boolean scalar(ArrayNode arr, ObjectNode obj, String key, Object v) {
    JsonNodeFactory f = JsonNodeFactory.instance;
    JsonNode n;
    if (v instanceof String s) {
      n = f.textNode(s);
    } else if (v instanceof Integer || v instanceof Short || v instanceof Byte) {
      n = f.numberNode(((Number) v).intValue());
    } else if (v instanceof Long l) {
      if (Math.abs(l) > MAX_SAFE) return false;
      n = f.numberNode(l);
    } else if (v instanceof BigInteger b) {
      if (b.abs().compareTo(BigInteger.valueOf(MAX_SAFE)) > 0) return false;
      n = f.numberNode(b.longValue());
    } else {
      return false;
    }
    if (arr != null) arr.add(n);
    else obj.set(key, n);
    return true;
  }

  /** Encodes a context map; values must be strings, integers, or collections of those. */
  static ObjectNode context(Map<String, ?> ctx) throws HaltSQLException {
    ObjectNode out = JsonNodeFactory.instance.objectNode();
    if (ctx == null) return out;
    for (Map.Entry<String, ?> e : ctx.entrySet()) {
      String k = e.getKey();
      if (k == null) throw new HaltSQLException(HaltSQLException.Kind.USAGE, "context keys must not be null");
      Object v = e.getValue();
      if (scalar(null, out, k, v)) continue;
      if (v instanceof Collection<?> c) {
        ArrayNode arr = out.putArray(k);
        boolean ok = true;
        for (Object x : c) ok &= scalar(arr, null, null, x);
        if (ok) continue;
      }
      throw new HaltSQLException(
          HaltSQLException.Kind.USAGE,
          "context." + k + " must be a string, an integer, or a collection of those");
    }
    return out;
  }
}
