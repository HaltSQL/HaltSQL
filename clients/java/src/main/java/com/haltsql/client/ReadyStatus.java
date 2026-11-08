package com.haltsql.client;

/**
 * Result of {@code GET /readyz}.
 *
 * @param ready true only on HTTP 200 with status {@code ready}
 * @param status {@code ready} or {@code not_ready}
 * @param policies number of loaded policies (0 if absent)
 */
public record ReadyStatus(boolean ready, String status, int policies) {}
