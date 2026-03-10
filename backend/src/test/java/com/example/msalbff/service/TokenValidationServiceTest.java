package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TokenValidationServiceTest {

    @Mock
    private AppProperties appProperties;
    @Mock
    private AppProperties.AzureAd azureAd;

    private TokenValidationService tokenValidationService;

    @BeforeEach
    void setUp() {
        when(appProperties.getAzureAd()).thenReturn(azureAd);
        when(azureAd.getTenantId()).thenReturn("test-tenant-id");
        when(azureAd.getClientId()).thenReturn("test-client-id");
        // We skip @PostConstruct (init) since we can't easily provide a JWK endpoint in unit tests.
        // validateToken tests use direct calls that bypass the JwtDecoder.
        tokenValidationService = new TokenValidationService(appProperties);
    }

    // ─── validateToken with null/empty ────────────────────────────────────────

    @Test
    void validateToken_returnsFalse_whenTokenIsNull() {
        assertFalse(tokenValidationService.validateToken(null));
    }

    @Test
    void validateToken_returnsFalse_whenTokenIsEmpty() {
        assertFalse(tokenValidationService.validateToken(""));
    }

    @Test
    void validateToken_returnsFalse_whenTokenIsBlank() {
        assertFalse(tokenValidationService.validateToken("   "));
    }

    // ─── parseToken ───────────────────────────────────────────────────────────

    @Test
    void parseToken_extractsClaimsCorrectly() throws Exception {
        String token = buildUnsignedJwt("test-subject", "test-tenant-id", "test-client-id",
                Instant.now(), Instant.now().plus(1, ChronoUnit.HOURS));

        // parseToken uses Nimbus directly and does NOT require a JwtDecoder, so no @PostConstruct needed.
        Jwt jwt = tokenValidationService.parseToken(token);

        assertNotNull(jwt);
        assertEquals("test-subject", jwt.getSubject());
    }

    @Test
    void parseToken_throwsIllegalArgumentException_forGarbage() {
        assertThrows(IllegalArgumentException.class,
                () -> tokenValidationService.parseToken("not.a.jwt"));
    }

    @Test
    void parseToken_throwsIllegalArgumentException_forNullToken() {
        assertThrows(IllegalArgumentException.class,
                () -> tokenValidationService.parseToken(null));
    }

    // ─── getUserName ──────────────────────────────────────────────────────────

    @Test
    void getUserName_returnsName_whenNameClaimPresent() {
        Jwt jwt = buildJwt(Map.of("name", "Alice", "sub", "subject-1"));
        assertEquals("Alice", tokenValidationService.getUserName(jwt));
    }

    @Test
    void getUserName_returnsPreferredUsername_whenNameAbsent() {
        Jwt jwt = buildJwt(Map.of("preferred_username", "alice@example.com", "sub", "subject-1"));
        assertEquals("alice@example.com", tokenValidationService.getUserName(jwt));
    }

    @Test
    void getUserName_returnsUpn_whenNameAndPreferredUsernameAbsent() {
        Jwt jwt = buildJwt(Map.of("upn", "alice@corp.com", "sub", "subject-1"));
        assertEquals("alice@corp.com", tokenValidationService.getUserName(jwt));
    }

    @Test
    void getUserName_fallsBackToSubject_whenNoNameClaims() {
        Jwt jwt = buildJwt(Map.of("sub", "subject-fallback"));
        assertEquals("subject-fallback", tokenValidationService.getUserName(jwt));
    }

    // ─── getUserEmail ─────────────────────────────────────────────────────────

    @Test
    void getUserEmail_returnsEmail_whenEmailClaimPresent() {
        Jwt jwt = buildJwt(Map.of("email", "alice@example.com", "sub", "s1"));
        assertEquals("alice@example.com", tokenValidationService.getUserEmail(jwt));
    }

    @Test
    void getUserEmail_returnsPreferredUsername_whenEmailAbsent() {
        Jwt jwt = buildJwt(Map.of("preferred_username", "alice@example.com", "sub", "s1"));
        assertEquals("alice@example.com", tokenValidationService.getUserEmail(jwt));
    }

    @Test
    void getUserEmail_returnsNull_whenNeitherClaimPresent() {
        Jwt jwt = buildJwt(Map.of("sub", "s1"));
        assertNull(tokenValidationService.getUserEmail(jwt));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /**
     * Creates a minimal Jwt object from the given claims map (no signature verification).
     */
    private Jwt buildJwt(Map<String, Object> claims) {
        Map<String, Object> headers = Map.of("alg", "RS256");
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        Map<String, Object> allClaims = new HashMap<>(claims);
        // Ensure 'sub' is always present for Jwt constructor
        allClaims.putIfAbsent("sub", "default-subject");
        return new Jwt("dummy.token.value", issuedAt, expiresAt, headers, allClaims);
    }

    /**
     * Builds a signed (RS256) JWT suitable for parseToken() tests.
     */
    private String buildUnsignedJwt(String subject, String tenantId, String clientId,
                                    Instant issuedAt, Instant expiresAt) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("https://login.microsoftonline.com/" + tenantId + "/v2.0")
                .audience(clientId)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("oid", "test-oid")
                .claim("tid", tenantId)
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256),
                claims);
        signedJWT.sign(new RSASSASigner(keyPair.getPrivate()));
        return signedJWT.serialize();
    }
}
