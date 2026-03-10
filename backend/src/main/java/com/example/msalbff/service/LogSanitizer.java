package com.example.msalbff.service;

/**
 * Utility for sanitising potentially sensitive identifiers before they appear in log output.
 */
final class LogSanitizer {

    private LogSanitizer() {}

    /**
     * Returns the last 8 characters of {@code value} prefixed with {@code …}, to avoid
     * logging full user identifiers (OID, tenant ID, Redis keys) as PII.
     * Returns {@code "***"} for null or very short values.
     */
    static String obfuscate(String value) {
        if (value == null || value.length() < 4) {
            return "***";
        }
        int tailLength = Math.min(8, value.length() / 4);
        return "…" + value.substring(value.length() - tailLength);
    }
}
