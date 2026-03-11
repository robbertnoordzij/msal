package com.example.msalbff.service;

import com.microsoft.aad.msal4j.ITokenCacheAccessAspect;

/**
 * Extension of MSAL4J's {@link ITokenCacheAccessAspect} that adds lifecycle management
 * (cache eviction) required by the logout flow.
 *
 * <p>Two implementations are available:
 * <ul>
 *   <li>{@link RedisMsalTokenCache} — stores the token cache in Redis, enabling
 *       shared state across all application instances in a cluster.</li>
 *   <li>{@link CookieMsalTokenCache} — stores the encrypted token cache in an
 *       HTTP-only cookie; self-contained, no infrastructure required, but
 *       single-instance only.</li>
 * </ul>
 *
 * <p>Select the active implementation via the {@code app.token-cache.type} property
 * (values: {@code redis} (default) or {@code cookie}).
 */
public interface MsalTokenCacheService extends ITokenCacheAccessAspect {

    /**
     * Invalidates the cached token data for the given account.
     * Called during logout to prevent a revoked refresh token from being reused.
     *
     * <p><strong>Note on eviction semantics:</strong> Redis-backed implementations evict
     * only the specified account. Cookie-backed implementations ({@link CookieMsalTokenCache})
     * ignore {@code homeAccountId} and clear the entire cookie, since one cookie holds one
     * user's cache. For the current single-user-per-session BFF model this is equivalent,
     * but callers should not assume per-account granularity.
     *
     * @param homeAccountId the MSAL account identifier in {@code oid.tid} format
     */
    void evict(String homeAccountId);
}
