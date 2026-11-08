package com.haltsql.client;

/**
 * The policy that produced a verdict.
 *
 * @param name {@code metadata.name} of the policy
 * @param version {@code sha256:<hex>} hash of the normalized policy
 */
public record PolicyRef(String name, String version) {}
