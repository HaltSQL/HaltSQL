package com.haltsql.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** A local fake sidecar built on com.sun.net.httpserver. */
final class FakeServer implements AutoCloseable {
  record Request(String method, String path, String auth, String body) {}

  record Response(int status, String body, Map<String, String> headers, long delayMs) {
    static Response of(int status, String body) {
      return new Response(status, body, Map.of(), 0);
    }
  }

  @FunctionalInterface
  interface Handler {
    Response handle(int n, Request r);
  }

  static final ObjectMapper JSON = new ObjectMapper();

  static JsonNode vectors() {
    try (InputStream in = FakeServer.class.getResourceAsStream("/vectors.json")) {
      return JSON.readTree(in);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static JsonNode vector(String name) {
    for (JsonNode v : vectors().get("vectors")) {
      if (v.get("name").asText().equals(name)) return v;
    }
    throw new IllegalArgumentException("no vector " + name);
  }

  final HttpServer server;
  final List<Request> requests = new CopyOnWriteArrayList<>();
  private final AtomicInteger count = new AtomicInteger();

  FakeServer(Handler h) throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/", ex -> serve(ex, h));
    server.start();
  }

  private void serve(HttpExchange ex, Handler h) throws IOException {
    String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    Request r =
        new Request(
            ex.getRequestMethod(),
            ex.getRequestURI().getPath(),
            ex.getRequestHeaders().getFirst("Authorization"),
            body);
    requests.add(r);
    Response resp = h.handle(count.incrementAndGet(), r);
    if (resp.delayMs() > 0) {
      try {
        Thread.sleep(resp.delayMs());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }
    byte[] out = resp.body().getBytes(StandardCharsets.UTF_8);
    ex.getResponseHeaders().set("Content-Type", "application/json");
    ex.getResponseHeaders().set("X-Request-Id", "req-1");
    resp.headers().forEach((k, v) -> ex.getResponseHeaders().set(k, v));
    ex.sendResponseHeaders(resp.status(), out.length == 0 ? -1 : out.length);
    if (out.length > 0) ex.getResponseBody().write(out);
    ex.close();
  }

  int count() {
    return count.get();
  }

  String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @Override
  public void close() {
    server.stop(0);
  }

  /**
   * A socket-level fake for answers the JDK HttpServer cannot give: for every connection it writes
   * {@code head}, then {@code repeat} for ever (if not null), and never ends the response.
   */
  static final class Raw implements AutoCloseable {
    private final ServerSocket socket;
    private final List<Socket> accepted = new CopyOnWriteArrayList<>();

    Raw(String head, String repeat) throws IOException {
      socket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
      Thread acceptor =
          new Thread(
              () -> {
                try {
                  while (true) {
                    Socket s = socket.accept();
                    accepted.add(s);
                    Thread t = new Thread(() -> answer(s, head, repeat));
                    t.setDaemon(true);
                    t.start();
                  }
                } catch (IOException closed) {
                  // close() ends the loop
                }
              });
      acceptor.setDaemon(true);
      acceptor.start();
    }

    private static void answer(Socket s, String head, String repeat) {
      try {
        s.getInputStream().read(new byte[1 << 16]);
        s.getOutputStream().write(head.getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();
        while (repeat != null) s.getOutputStream().write(repeat.getBytes(StandardCharsets.US_ASCII));
      } catch (IOException gone) {
        // the client went away
      }
    }

    int count() {
      return accepted.size();
    }

    String url() {
      return "http://127.0.0.1:" + socket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      socket.close();
      for (Socket s : accepted) s.close();
    }
  }
}
