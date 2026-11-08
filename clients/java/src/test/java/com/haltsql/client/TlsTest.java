package com.haltsql.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** TLS options against a local HTTPS fake sidecar with a self-signed certificate. */
class TlsTest {
  static final char[] PW = "changeit".toCharArray();
  @TempDir static Path dir;
  static HttpsServer server;
  static KeyStore keyStore;
  static final AtomicReference<String> userAgent = new AtomicReference<>();
  static JsonNode vector;

  @BeforeAll
  static void start() throws Exception {
    Path keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
    assumeTrue(Files.isExecutable(keytool), "keytool not available");
    Path ks = dir.resolve("server.p12");
    Process p =
        new ProcessBuilder(
                keytool.toString(), "-genkeypair", "-alias", "srv", "-keyalg", "RSA",
                "-keysize", "2048", "-validity", "1", "-dname", "CN=127.0.0.1",
                "-ext", "san=ip:127.0.0.1", "-storetype", "PKCS12", "-keystore", ks.toString(),
                "-storepass", new String(PW), "-keypass", new String(PW))
            .redirectErrorStream(true)
            .start();
    p.getInputStream().readAllBytes();
    assumeTrue(p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0, "keytool failed");
    keyStore = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(ks)) {
      keyStore.load(in, PW);
    }
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore, PW);
    SSLContext serverCtx = SSLContext.getInstance("TLS");
    serverCtx.init(kmf.getKeyManagers(), null, null);

    vector = FakeServer.vector("allowed_bound_single_tenant");
    byte[] body = vector.get("response").toString().getBytes(StandardCharsets.UTF_8);
    server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(serverCtx));
    server.createContext(
        "/",
        ex -> {
          ex.getRequestBody().readAllBytes();
          userAgent.set(ex.getRequestHeaders().getFirst("User-Agent"));
          ex.getResponseHeaders().set("Content-Type", "application/json");
          ex.sendResponseHeaders(200, body.length);
          ex.getResponseBody().write(body);
          ex.close();
        });
    server.start();
  }

  @AfterAll
  static void stop() {
    if (server != null) server.stop(0);
  }

  static String url() {
    return "https://127.0.0.1:" + server.getAddress().getPort();
  }

  static SSLContext trusting() throws Exception {
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("srv", keyStore.getCertificate("srv"));
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trust);
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tmf.getTrustManagers(), null);
    return ctx;
  }

  Verdict verify(HaltSQLClient c) throws HaltSQLException {
    return c.verify(
        vector.get("request").get("sql").asText(),
        Map.of("tenant_id", vector.get("request").get("context").get("tenant_id").asText()));
  }

  @Test
  void untrustedCertificateFailsClosed() throws Exception {
    HaltSQLClient c =
        HaltSQLClient.builder(url()).retries(0, Duration.ZERO, Duration.ZERO).build();
    HaltSQLException e = assertThrows(HaltSQLException.class, () -> verify(c));
    assertEquals(HaltSQLException.Kind.TRANSPORT, e.kind());
    assertFalse(e.allowed());
  }

  @Test
  void privateCaViaSslContext() throws Exception {
    SSLContext ctx = trusting();
    HaltSQLClient c = HaltSQLClient.builder(url()).sslContext(ctx).build();
    assertSame(ctx, c.httpClient().sslContext());
    assertTrue(verify(c).allowed());
    assertEquals("haltsql-client-java/" + HaltSQLClient.VERSION, userAgent.get());
  }

  @Test
  void sslParametersAreApplied() throws Exception {
    SSLParameters params = new SSLParameters();
    params.setProtocols(new String[] {"TLSv1.3"});
    HaltSQLClient c =
        HaltSQLClient.builder(url()).sslContext(trusting()).sslParameters(params).build();
    assertTrue(verify(c).allowed());
  }

  @Test
  void tlsOptionsDoNotMixWithCustomHttpClient() throws Exception {
    HttpClient hc = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    SSLContext ctx = trusting();
    assertThrows(
        HaltSQLException.class, () -> HaltSQLClient.builder(url()).httpClient(hc).sslContext(ctx));
    assertThrows(
        HaltSQLException.class, () -> HaltSQLClient.builder(url()).sslContext(ctx).httpClient(hc));
    assertThrows(HaltSQLException.class, () -> HaltSQLClient.builder(url()).sslContext(null));
    assertThrows(
        HaltSQLException.class,
        () -> HaltSQLClient.builder(url()).retries(1, null, Duration.ofSeconds(1)));
  }
}
