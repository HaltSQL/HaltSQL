package com.haltsql.client;

/**
 * Body of {@code GET /healthz}.
 *
 * @param status {@code ok} while the process runs
 */
public record HealthStatus(String status) {}
