package com.haltsql.client;

/**
 * One entry of {@code GET /v1/policies}.
 *
 * @param name policy name
 * @param version policy version hash
 * @param mode {@code enforce} or {@code shadow}
 */
public record PolicySummary(String name, String version, String mode) {}
