package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class HaltSQLClientTest {

  static HaltSQLClient.Builder fast(String url) throws HaltSQLException {
    return HaltSQLClient.builder(url).retries(2, Duration.ofMillis(1), Duration.ofMillis(5));
  }

  static Map<String, Object> ctx(JsonNode req) {
    Map<String, Object> m = new LinkedHashMap<>();
    JsonNode c = req.get("context");
    if (c == null) return m;
    c.fields()
        .forEachRemaining(
            e -> {
              JsonNode v = e.getValue();
              if (v.isArray()) {
                List<Object> l = new ArrayList<>();
                v.forEach(x -> l.add(x.isInt() ? (Object) x.intValue() : x.asText()));
                m.put(e.getKey(), l);
              } else {
                m.put(e.getKey(), v.isInt() ? (Object) v.intValue() : v.asText());
              }
            });
    return m;
  }

  static List<Object> expectedPositional(JsonNode arr) {
    List<Object> out = new ArrayList<>();
    for (JsonNode x : arr) {
      if (x.isArray()) {
        List<String> l = new ArrayList<>();
        x.forEach(e -> l.add(e.asText()));
        out.add(l);
      } else {
        out.add(x.asText());
      }
    }
    return out;
  }

  @TestFactory
  Stream<DynamicTest> recordedVectors() {
    List<DynamicTest> tests = new ArrayList<>();
    for (JsonNode v : FakeServer.vectors().get("vectors")) {
      tests.add(DynamicTest.dynamicTest(v.get("name").asText(), () -> runVector(v)));
    }
    assertTrue(tests.size() >= 10);
    return tests.stream();
  }

  private void runVector(JsonNode v) throws Exception {
    int status = v.get("status").asInt();
    String resp = v.get("response").toString();
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(status, resp))) {
      HaltSQLClient.Builder b = fast(srv.url());
      String token = v.get("token").isNull() ? null : v.get("token").asText();
      if (token != null) b.token(token);
      HaltSQLClient c = b.build();
      JsonNode req = v.get("request");
      String sql = req.isNull() ? "SELECT 1" : req.get("sql").asText();
      Map<String, Object> context = req.isNull() ? Map.of() : ctx(req);
      VerifyOptions opts =
          !req.isNull() && req.has("policy") ? VerifyOptions.policy(req.get("policy").asText()) : VerifyOptions.NONE;
      JsonNode expect = v.get("expect");
      if (status == 200) {
        Verdict verdict = c.verify(sql, context, opts);
        assertEquals(expect.get("allowed").asBoolean(), verdict.allowed());
        List<String> codes = new ArrayList<>();
        expect.get("codes").forEach(x -> codes.add(x.asText()));
        assertEquals(codes, verdict.codes());
        assertEquals(v.get("response").get("policy").get("version").asText(), verdict.policy().version());
        if (verdict.allowed()) {
          assertEquals(expectedPositional(expect.get("positional")), BindParams.positional(verdict));
        } else {
          HaltSQLException e = assertThrows(HaltSQLException.class, () -> BindParams.positional(verdict));
          assertEquals(HaltSQLException.Kind.USAGE, e.kind());
        }
      } else {
        HaltSQLHttpException e = assertThrows(HaltSQLHttpException.class, () -> c.verify(sql, context, opts));
        assertEquals(status, e.status());
        assertEquals(expect.get("error_code").asText(), e.code());
        assertFalse(e.allowed());
      }
      FakeServer.Request r = srv.requests.get(0);
      assertEquals("POST", r.method());
      assertEquals("/v1/verify", r.path());
      assertEquals(token == null ? null : "Bearer " + token, r.auth());
      if (!req.isNull()) {
        JsonNode sent = FakeServer.JSON.readTree(r.body());
        assertEquals(sql, sent.get("sql").asText());
        JsonNode wantCtx = req.has("context") ? req.get("context") : FakeServer.JSON.createObjectNode();
        assertEquals(wantCtx, sent.get("context"));
        assertEquals(req.get("policy"), sent.get("policy"));
      }
    }
  }

  @Test
  void operations() throws Exception {
    JsonNode vf = FakeServer.vectors();
    try (FakeServer srv =
        new FakeServer(
            (n, r) ->
                switch (r.path()) {
                  case "/healthz" -> FakeServer.Response.of(200, vf.get("healthz").toString());
                  case "/readyz" -> FakeServer.Response.of(200, vf.get("readyz").toString());
                  case "/v1/policies" -> FakeServer.Response.of(200, vf.get("policies").toString());
                  default -> FakeServer.Response.of(404, "{}");
                })) {
      HaltSQLClient c = HaltSQLClient.builder(srv.url()).token("tok").build();
      assertEquals(new HealthStatus("ok"), c.health());
      assertEquals(new ReadyStatus(true, "ready", 2), c.ready());
      List<PolicySummary> ps = c.policies();
      assertEquals(1, ps.size());
      assertEquals("saas-analytics", ps.get(0).name());
      assertEquals("enforce", ps.get(0).mode());
      assertNull(srv.requests.get(0).auth());
      assertNull(srv.requests.get(1).auth());
      assertEquals("Bearer tok", srv.requests.get(2).auth());
    }
  }

  @Test
  void readyNotReadyIsNotRetried() throws Exception {
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(503, "{\"status\":\"not_ready\",\"policies\":0}"))) {
      assertEquals(new ReadyStatus(false, "not_ready", 0), fast(srv.url()).build().ready());
      assertEquals(1, srv.count());
    }
  }

  @Test
  void retries503ThenSucceeds() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    try (FakeServer srv =
        new FakeServer(
            (n, r) ->
                n < 3
                    ? FakeServer.Response.of(503, "{\"error\":{\"code\":\"POLICY_UNAVAILABLE\",\"message\":\"reloading\"}}")
                    : FakeServer.Response.of(200, v.get("response").toString()))) {
      Verdict verdict = fast(srv.url()).build().verify(v.get("request").get("sql").asText(), Map.of("tenant_id", "acme"));
      assertTrue(verdict.allowed());
      assertEquals(3, srv.count());
    }
  }

  @Test
  void persistent503() throws Exception {
    try (FakeServer srv =
        new FakeServer(
            (n, r) ->
                new FakeServer.Response(
                    503, "{\"error\":{\"code\":\"AUDIT_UNAVAILABLE\",\"message\":\"down\"}}", Map.of("Retry-After", "0"), 0))) {
      HaltSQLClient c = HaltSQLClient.builder(srv.url()).retries(3, Duration.ofMillis(1), Duration.ofMillis(5)).build();
      HaltSQLHttpException e = assertThrows(HaltSQLHttpException.class, () -> c.verify("SELECT 1"));
      assertEquals(503, e.status());
      assertEquals("AUDIT_UNAVAILABLE", e.code());
      assertEquals(4, srv.count());
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {400, 401, 403, 404, 413, 500})
  void nonRetryableStatus(int status) throws Exception {
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(status, "{\"error\":{\"code\":\"X\",\"message\":\"m\"}}"))) {
      HaltSQLHttpException e = assertThrows(HaltSQLHttpException.class, () -> fast(srv.url()).build().verify("SELECT 1"));
      assertEquals(status, e.status());
      assertEquals(1, srv.count());
    }
  }

  @Test
  void timeoutIsRetriedThenThrown() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    try (FakeServer srv = new FakeServer((n, r) -> new FakeServer.Response(200, v.get("response").toString(), Map.of(), 400))) {
      HaltSQLClient c =
          HaltSQLClient.builder(srv.url())
              .timeout(Duration.ofMillis(100))
              .retries(1, Duration.ofMillis(1), Duration.ofMillis(1))
              .build();
      HaltSQLException e =
          assertThrows(HaltSQLException.class, () -> c.verify(v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")));
      assertEquals(HaltSQLException.Kind.TIMEOUT, e.kind());
      assertEquals(2, srv.count());
    }
  }

  @Test
  void connectionRefused() throws Exception {
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    HaltSQLClient c = fast("http://127.0.0.1:" + port).build();
    HaltSQLException e = assertThrows(HaltSQLException.class, () -> c.verify("SELECT 1"));
    assertEquals(HaltSQLException.Kind.TRANSPORT, e.kind());
  }

  static String mutate(JsonNode base, Consumer<ObjectNode> f) {
    ObjectNode o = base.deepCopy();
    f.accept(o);
    return o.toString();
  }

  static String sha(String s) throws Exception {
    return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  @TestFactory
  Stream<DynamicTest> failClosedOnBadBodies() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    JsonNode ok = v.get("response");
    JsonNode denied = FakeServer.vector("denied_parse_error").get("response");
    String badHash = sha("SELECT 2");
    Map<String, String> cases = new LinkedHashMap<>();
    cases.put("not json", "not json");
    cases.put("array body", "[" + ok + "]");
    cases.put("trailing tokens", ok + " {}");
    cases.put("duplicate allowed key", "{\"allowed\":false," + ok.toString().substring(1));
    cases.put("allowed string", mutate(ok, o -> o.put("allowed", "true")));
    cases.put("allowed null", mutate(ok, o -> o.putNull("allowed")));
    cases.put("missing allowed", mutate(ok, o -> o.remove("allowed")));
    cases.put("allowed with reasons", mutate(ok, o -> o.putArray("reasons").addObject().put("code", "E_TABLE_DENIED").put("message", "m").put("rule", "r")));
    cases.put("bad reason code", mutate(denied, o -> ((ObjectNode) ((ArrayNode) o.get("reasons")).get(0)).put("code", "nope")));
    cases.put("bind param 0", mutate(ok, o -> o.putArray("bind_params").addObject().put("param", 0).put("value", "a")));
    cases.put("bind value number", mutate(ok, o -> o.putArray("bind_params").addObject().put("param", 1).put("value", 7)));
    cases.put("sql hash mismatch", mutate(ok, o -> o.put("sql_sha256", badHash)));
    cases.put("missing tables", mutate(ok, o -> o.remove("tables")));
    cases.put("missing statement_kind", mutate(ok, o -> o.remove("statement_kind")));
    String sql = v.get("request").get("sql").asText();
    return cases.entrySet().stream()
        .map(
            e ->
                DynamicTest.dynamicTest(
                    e.getKey(),
                    () -> {
                      try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, e.getValue()))) {
                        HaltSQLException ex =
                            assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder(srv.url()).build().verify(sql, Map.of("tenant_id", "acme")));
                        assertEquals(HaltSQLException.Kind.PROTOCOL, ex.kind());
                        assertFalse(ex.allowed());
                      }
                    }));
  }

  @Test
  void redirectIsNotFollowed() throws Exception {
    try (FakeServer srv = new FakeServer((n, r) -> new FakeServer.Response(307, "", Map.of("Location", "http://example.invalid/"), 0))) {
      HaltSQLHttpException e =
          assertThrows(HaltSQLHttpException.class, () -> HaltSQLClient.builder(srv.url()).token("tok").build().verify("SELECT 1"));
      assertEquals(307, e.status());
      assertEquals("HTTP_307", e.code());
      assertEquals(1, srv.count());
    }
  }

  @Test
  void oversizedBodyRejected() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    String big = mutate(v.get("response"), o -> o.put("pad", "x".repeat(5000)));
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, big))) {
      HaltSQLException e =
          assertThrows(
              HaltSQLException.class,
              () -> HaltSQLClient.builder(srv.url()).maxResponseBytes(1024).build().verify(v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")));
      assertEquals(HaltSQLException.Kind.PROTOCOL, e.kind());
    }
  }

  @Test
  void unknownFieldsIgnored() throws Exception {
    JsonNode v = FakeServer.vector("allowed_bound_single_tenant");
    String body = mutate(v.get("response"), o -> o.putObject("future").put("a", 1));
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(200, body))) {
      assertTrue(HaltSQLClient.builder(srv.url()).build().verify(v.get("request").get("sql").asText(), Map.of("tenant_id", "acme")).allowed());
    }
  }

  @Test
  void tokenNeverInErrorsOrToString() throws Exception {
    String token = "super-secret-token-value";
    try (FakeServer srv = new FakeServer((n, r) -> FakeServer.Response.of(401, "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"invalid bearer token\"}}"))) {
      HaltSQLClient c = HaltSQLClient.builder(srv.url()).token(token).build();
      HaltSQLException e = assertThrows(HaltSQLException.class, () -> c.verify("SELECT 1"));
      assertFalse(e.getMessage().contains(token));
      assertFalse(c.toString().contains(token));
    }
  }

  @Test
  void builderValidation() {
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("ftp://x"));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("not a url"));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("http://u:p@h"));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("http://h").token("a\r\nX-Evil: 1"));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("http://h").token(""));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder("http://h").timeout(Duration.ZERO));
    assertThrows(
        HaltSQLException.class,
        () -> HaltSQLClient.builder("http://h").httpClient(java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.ALWAYS).build()));
  }

  @Test
  void contextValidation() throws Exception {
    HaltSQLClient c = HaltSQLClient.builder("http://127.0.0.1:1").build();
    List<Map<String, Object>> bad = new ArrayList<>();
    bad.add(Map.of("t", 1.5));
    bad.add(Map.of("t", true));
    bad.add(Map.of("t", List.of(1, Map.of())));
    bad.add(Map.of("t", 1L << 60));
    bad.add(Map.of("t", BigInteger.TEN.pow(30)));
    Map<String, Object> nullVal = new LinkedHashMap<>();
    nullVal.put("t", null);
    bad.add(nullVal);
    for (Map<String, Object> m : bad) {
      HaltSQLException e = assertThrows(HaltSQLException.class, () -> c.verify("SELECT 1", m));
      assertEquals(HaltSQLException.Kind.USAGE, e.kind(), m.toString());
    }
    Map<String, Object> good = new LinkedHashMap<>();
    good.put("a", "x");
    good.put("b", 7);
    good.put("c", List.of("p", "q"));
    good.put("d", List.of(1L, 2L));
    assertEquals("{\"a\":\"x\",\"b\":7,\"c\":[\"p\",\"q\"],\"d\":[1,2]}", Wire.context(good).toString());
  }

  @Test
  void bindParamsHelper() throws Exception {
    Verdict v = verdict(true, List.of(BindParam.set(2, List.of("a", "b\"c", "d\\e")), BindParam.scalar(1, "t")));
    assertEquals(List.of("t", List.of("a", "b\"c", "d\\e")), BindParams.positional(v));
    assertEquals("{\"a\",\"b\\\"c\",\"d\\\\e\"}", BindParams.pgArrayLiteral(List.of("a", "b\"c", "d\\e")));
    for (Verdict bad :
        List.of(
            verdict(true, List.of(BindParam.scalar(2, "x"))),
            verdict(true, List.of(BindParam.scalar(1, "x"), BindParam.scalar(1, "y"))),
            verdict(false, List.of()))) {
      assertEquals(HaltSQLException.Kind.USAGE, assertThrows(HaltSQLException.class, () -> BindParams.positional(bad)).kind());
    }
  }

  static Verdict verdict(boolean allowed, List<BindParam> bps) {
    return new Verdict(
        allowed, List.of(), List.of(), new PolicyRef("p", "sha256:00"), "select", List.of(), List.of(), bps, null, "0".repeat(64), 1);
  }
}
