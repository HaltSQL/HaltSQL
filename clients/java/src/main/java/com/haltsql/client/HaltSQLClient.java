package com.haltsql.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * Client for the HaltSQL sidecar HTTP API. Thread-safe; create one and reuse it (the underlying
 * {@link HttpClient} pools keep-alive connections).
 *
 * <p>Fail-closed contract: {@link #verify} returns only a strictly validated verdict from an HTTP
 * 200 response. Every other outcome (non-200, timeout, connection error, malformed body, a
 * verdict whose {@code sql_sha256} does not match the SQL that was sent) throws a {@link
 * HaltSQLException}. Run SQL only when {@code verify(...).allowed()} is true.
 *
 * <pre>{@code
 * HaltSQLClient haltsql = HaltSQLClient.builder("http://127.0.0.1:8080")
 *     .token(System.getenv("HALTSQL_TOKEN"))
 *     .build();
 * Verdict v = haltsql.verify(sql, Map.of("tenant_id", session.tenantId()));
 * }</pre>
 */
public final class HaltSQLClient {
  /** SDK version, sent in the User-Agent header. */
  public static final String VERSION = "0.0.1";

  private final URI base;
  private final String token;
  private final HttpClient http;
  private final Duration timeout;
  private final int maxRetries;
  private final long baseDelayMs;
  private final long maxDelayMs;
  private final int maxResponseBytes;
  private final boolean checkSqlHash;

  private HaltSQLClient(Builder b) {
    this.base = b.base;
    this.token = b.token;
    this.timeout = b.timeout;
    this.maxRetries = b.maxRetries;
    this.baseDelayMs = b.baseDelayMs;
    this.maxDelayMs = b.maxDelayMs;
    this.maxResponseBytes = b.maxResponseBytes;
    this.checkSqlHash = b.checkSqlHash;
    if (b.httpClient != null) {
      this.http = b.httpClient;
    } else {
      HttpClient.Builder hb =
          HttpClient.newBuilder()
              .connectTimeout(b.timeout)
              .followRedirects(HttpClient.Redirect.NEVER);
      if (b.sslContext != null) hb.sslContext(b.sslContext);
      if (b.sslParameters != null) hb.sslParameters(b.sslParameters);
      this.http = hb.build();
    }
  }

  /** Starts a builder for the sidecar at {@code baseUrl} (e.g. {@code http://127.0.0.1:8080}). */
  public static Builder builder(String baseUrl) throws HaltSQLException {
    return new Builder(baseUrl);
  }

  /** Builder for {@link HaltSQLClient}. */
  public static final class Builder {
    private final URI base;
    private String token;
    private Duration timeout = Duration.ofSeconds(5);
    private int maxRetries = 2;
    private long baseDelayMs = 100;
    private long maxDelayMs = 2000;
    private int maxResponseBytes = 8 << 20;
    private boolean checkSqlHash = true;
    private HttpClient httpClient;
    private SSLContext sslContext;
    private SSLParameters sslParameters;

    private Builder(String baseUrl) throws HaltSQLException {
      URI u;
      try {
        u = new URI(Objects.requireNonNull(baseUrl, "baseUrl"));
      } catch (java.net.URISyntaxException e) {
        throw usage("baseUrl is not a valid URL");
      }
      String scheme = u.getScheme();
      if (scheme == null
          || !(scheme.equals("http") || scheme.equals("https"))
          || u.getHost() == null) {
        throw usage("baseUrl must be an absolute http or https URL");
      }
      if (u.getUserInfo() != null) throw usage("baseUrl must not contain credentials; use token()");
      String s = u.toString();
      while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
      this.base = URI.create(s);
    }

    /** Bearer token sent to {@code /v1/*}. Must be visible ASCII. Never logged. */
    public Builder token(String token) throws HaltSQLException {
      if (token == null || token.isEmpty()) throw usage("token must not be empty");
      for (int i = 0; i < token.length(); i++) {
        char c = token.charAt(i);
        if (c < 0x21 || c > 0x7e) throw usage("token must be visible ASCII");
      }
      this.token = token;
      return this;
    }

    /** Per-attempt timeout (default 5s). */
    public Builder timeout(Duration d) throws HaltSQLException {
      if (d == null || d.isNegative() || d.isZero()) throw usage("timeout must be positive");
      this.timeout = d;
      return this;
    }

    /**
     * Retries after the first attempt on 503, connection errors and timeouts (default 2), with
     * exponential backoff and full jitter (default 100ms base, 2s cap).
     */
    public Builder retries(int maxRetries, Duration baseDelay, Duration maxDelay)
        throws HaltSQLException {
      if (baseDelay == null || maxDelay == null) throw usage("retry delays must not be null");
      if (maxRetries < 0 || baseDelay.isNegative() || maxDelay.isNegative()) {
        throw usage("retry settings must be non-negative");
      }
      this.maxRetries = maxRetries;
      this.baseDelayMs = baseDelay.toMillis();
      this.maxDelayMs = maxDelay.toMillis();
      return this;
    }

    /** Largest accepted response body (default 8 MiB). */
    public Builder maxResponseBytes(int n) throws HaltSQLException {
      if (n <= 0) throw usage("maxResponseBytes must be positive");
      this.maxResponseBytes = n;
      return this;
    }

    /** Disables the {@code sql_sha256} check. Only for servers that do not echo it. */
    public Builder withoutSqlHashCheck() {
      this.checkSqlHash = false;
      return this;
    }

    /**
     * Uses a custom {@link HttpClient} (custom TLS, proxy, executor). It must not follow
     * redirects; a client that does is rejected.
     */
    public Builder httpClient(HttpClient c) throws HaltSQLException {
      if (c == null) throw usage("httpClient must not be null");
      if (sslContext != null || sslParameters != null) {
        throw usage("configure TLS on the httpClient you pass, not via sslContext()");
      }
      if (c.followRedirects() != HttpClient.Redirect.NEVER) {
        throw usage("httpClient must use HttpClient.Redirect.NEVER");
      }
      this.httpClient = c;
      return this;
    }

    /**
     * TLS context for an {@code https} sidecar: a trust store with a private CA, and a key
     * manager with a client certificate for mutual TLS. Without it the JVM default trust store
     * is used. Certificate and host-name verification stay on. Not combinable with
     * {@link #httpClient}.
     */
    public Builder sslContext(SSLContext ctx) throws HaltSQLException {
      if (ctx == null) throw usage("sslContext must not be null");
      if (httpClient != null) throw usage("configure TLS on the httpClient you passed instead");
      this.sslContext = ctx;
      return this;
    }

    /**
     * TLS parameters (protocols, cipher suites) used with {@link #sslContext}. Not combinable
     * with {@link #httpClient}.
     */
    public Builder sslParameters(SSLParameters params) throws HaltSQLException {
      if (params == null) throw usage("sslParameters must not be null");
      if (httpClient != null) throw usage("configure TLS on the httpClient you passed instead");
      this.sslParameters = params;
      return this;
    }

    public HaltSQLClient build() {
      return new HaltSQLClient(this);
    }
  }

  /** The underlying HTTP client (package-private, for tests). */
  HttpClient httpClient() {
    return http;
  }

  @Override
  public String toString() {
    return "HaltSQLClient[" + base + (token != null ? ", token=<redacted>" : "") + "]";
  }

  /** Verifies one SQL string with no context and default options. */
  public Verdict verify(String sql) throws HaltSQLException {
    return verify(sql, Map.of(), VerifyOptions.NONE);
  }

  /** Verifies one SQL string. */
  public Verdict verify(String sql, Map<String, ?> context) throws HaltSQLException {
    return verify(sql, context, VerifyOptions.NONE);
  }

  /**
   * Verifies one SQL string. Returns the verdict (allowed or denied) for an HTTP 200 answer;
   * throws {@link HaltSQLException} for anything else.
   *
   * @param sql the exact SQL string
   * @param context values from the caller's authenticated session (strings, integers, or
   *     collections of those); never from the prompt or the SQL
   * @param opts policy name and request id; may be {@link VerifyOptions#NONE}
   */
  public Verdict verify(String sql, Map<String, ?> context, VerifyOptions opts)
      throws HaltSQLException {
    if (sql == null) throw usage("sql must not be null");
    if (opts == null) opts = VerifyOptions.NONE;
    ObjectNode body = Wire.MAPPER.createObjectNode();
    body.put("sql", sql);
    body.set("context", Wire.context(context));
    if (opts.policy() != null) {
      if (opts.policy().isEmpty()) throw usage("policy must not be empty");
      body.put("policy", opts.policy());
    }
    byte[] bytes;
    try {
      bytes = Wire.MAPPER.writeValueAsBytes(body);
    } catch (IOException e) {
      throw usage("encoding request: " + e.getMessage());
    }
    Raw res = send("POST", "/v1/verify", bytes, true, true, opts.requestId());
    if (res.status != 200) throw httpError(res);
    Verdict v;
    try {
      v = Wire.verdict(Wire.parse(res.body));
    } catch (Wire.Invalid e) {
      throw protocol(e.getMessage(), res.requestId);
    }
    if (checkSqlHash) {
      byte[] want = HexFormat.of().formatHex(sha256(sql)).getBytes(StandardCharsets.US_ASCII);
      byte[] got = v.sqlSha256().getBytes(StandardCharsets.US_ASCII);
      if (!MessageDigest.isEqual(want, got)) {
        throw protocol("sql_sha256 does not match the SQL that was sent", res.requestId);
      }
    }
    return v;
  }

  /** {@code GET /healthz}; throws unless the server answers 200. */
  public HealthStatus health() throws HaltSQLException {
    Raw res = send("GET", "/healthz", null, false, true, null);
    if (res.status != 200) throw httpError(res);
    return new HealthStatus(statusField(res));
  }

  /**
   * {@code GET /readyz}. A 503 not-ready answer returns {@code ready() == false} and is not
   * retried; other statuses throw.
   */
  public ReadyStatus ready() throws HaltSQLException {
    Raw res = send("GET", "/readyz", null, false, false, null);
    if (res.status != 200 && res.status != 503) throw httpError(res);
    String status = statusField(res);
    int n = 0;
    try {
      JsonNode p = Wire.parse(res.body).get("policies");
      if (p != null && p.isInt()) n = p.intValue();
    } catch (Wire.Invalid e) {
      throw protocol(e.getMessage(), res.requestId);
    }
    return new ReadyStatus(res.status == 200 && status.equals("ready"), status, n);
  }

  /** {@code GET /v1/policies}: the policies this caller may use. */
  public List<PolicySummary> policies() throws HaltSQLException {
    Raw res = send("GET", "/v1/policies", null, true, true, null);
    if (res.status != 200) throw httpError(res);
    try {
      return Wire.policies(Wire.parse(res.body));
    } catch (Wire.Invalid e) {
      throw protocol(e.getMessage(), res.requestId);
    }
  }

  // ---------------------------------------------------------------------------------------------

  private record Raw(int status, byte[] body, String requestId, long retryAfterMs) {}

  private String statusField(Raw res) throws HaltSQLException {
    try {
      JsonNode s = Wire.parse(res.body).get("status");
      if (s == null || !s.isTextual()) throw new Wire.Invalid("body has no status");
      return s.textValue();
    } catch (Wire.Invalid e) {
      throw protocol(e.getMessage(), res.requestId);
    }
  }

  private Raw send(
      String method, String path, byte[] body, boolean auth, boolean retry, String requestId)
      throws HaltSQLException {
    int attempts = retry ? maxRetries + 1 : 1;
    HaltSQLException last = null;
    Raw lastRaw = null;
    for (int i = 0; i < attempts; i++) {
      if (i > 0) {
        long cap = Math.min(maxDelayMs, baseDelayMs << Math.min(i - 1, 30));
        long delay = cap <= 0 ? 0 : ThreadLocalRandom.current().nextLong(cap + 1);
        if (lastRaw != null && lastRaw.retryAfterMs >= 0) delay = Math.min(maxDelayMs, lastRaw.retryAfterMs);
        try {
          Thread.sleep(delay);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new HaltSQLException(HaltSQLException.Kind.TRANSPORT, "interrupted", null, e);
        }
      }
      try {
        Raw r = once(method, path, body, auth, requestId);
        if (r.status == 503 && i + 1 < attempts) {
          last = httpError(r);
          lastRaw = r;
          continue;
        }
        return r;
      } catch (HaltSQLException e) {
        if (e.kind() != HaltSQLException.Kind.TRANSPORT && e.kind() != HaltSQLException.Kind.TIMEOUT) throw e;
        if (Thread.currentThread().isInterrupted()) throw e;
        last = e;
        lastRaw = null;
      }
    }
    throw last != null ? last : new HaltSQLException(HaltSQLException.Kind.TRANSPORT, "no attempt was made");
  }

  private Raw once(String method, String path, byte[] body, boolean auth, String requestId)
      throws HaltSQLException {
    HttpRequest.Builder rb =
        HttpRequest.newBuilder(URI.create(base + path))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("User-Agent", "haltsql-client-java/" + VERSION);
    if (body != null) {
      rb.header("Content-Type", "application/json");
      rb.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
    } else {
      rb.method(method, HttpRequest.BodyPublishers.noBody());
    }
    if (auth && token != null) rb.header("Authorization", "Bearer " + token);
    if (requestId != null) {
      try {
        rb.header("X-Request-Id", requestId);
      } catch (IllegalArgumentException e) {
        throw usage("requestId is not a valid header value");
      }
    }
    HttpResponse<InputStream> resp;
    try {
      resp = http.send(rb.build(), HttpResponse.BodyHandlers.ofInputStream());
    } catch (HttpConnectTimeoutException e) {
      throw new HaltSQLException(HaltSQLException.Kind.TIMEOUT, "connect timed out after " + timeout, null, e);
    } catch (HttpTimeoutException e) {
      throw new HaltSQLException(HaltSQLException.Kind.TIMEOUT, "request timed out after " + timeout, null, e);
    } catch (IOException e) {
      throw new HaltSQLException(HaltSQLException.Kind.TRANSPORT, e.getClass().getSimpleName() + ": " + e.getMessage(), null, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new HaltSQLException(HaltSQLException.Kind.TRANSPORT, "interrupted", null, e);
    }
    String rid = resp.headers().firstValue("x-request-id").orElse(null);
    byte[] data;
    try (InputStream in = resp.body()) {
      long declared = resp.headers().firstValueAsLong("content-length").orElse(-1);
      if (declared > maxResponseBytes) throw protocol("response larger than " + maxResponseBytes + " bytes", rid);
      data = in.readNBytes(maxResponseBytes + 1);
    } catch (HttpTimeoutException e) {
      throw new HaltSQLException(HaltSQLException.Kind.TIMEOUT, "request timed out after " + timeout, rid, e);
    } catch (IOException e) {
      throw new HaltSQLException(HaltSQLException.Kind.TRANSPORT, "reading response: " + e.getMessage(), rid, e);
    }
    if (data.length > maxResponseBytes) throw protocol("response larger than " + maxResponseBytes + " bytes", rid);
    long ra = -1;
    String raH = resp.headers().firstValue("retry-after").orElse(null);
    if (raH != null && raH.matches("\\d{1,6}")) ra = Long.parseLong(raH) * 1000;
    return new Raw(resp.statusCode(), data, rid, ra);
  }

  private static HaltSQLHttpException httpError(Raw r) {
    String code = "HTTP_" + r.status;
    String msg = "unexpected status";
    try {
      JsonNode e = Wire.parse(r.body).get("error");
      if (e != null && e.isObject()) {
        JsonNode c = e.get("code");
        JsonNode m = e.get("message");
        if (c != null && c.isTextual()) code = c.textValue();
        if (m != null && m.isTextual()) msg = m.textValue().length() > 500 ? m.textValue().substring(0, 500) : m.textValue();
      }
    } catch (Wire.Invalid ignored) {
      // non-JSON error body: keep the generic code
    }
    return new HaltSQLHttpException(r.status, code, msg, r.requestId);
  }

  private static byte[] sha256(String s) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  static HaltSQLException usage(String m) {
    return new HaltSQLException(HaltSQLException.Kind.USAGE, m);
  }

  private static HaltSQLException protocol(String m, String rid) {
    return new HaltSQLException(HaltSQLException.Kind.PROTOCOL, "invalid response: " + m, rid, null);
  }
}
