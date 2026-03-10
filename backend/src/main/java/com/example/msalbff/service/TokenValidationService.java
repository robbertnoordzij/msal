package com.example.msalbff.service;

import com.example.msalbff.config.AppProperties;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * Validates JWT tokens issued by Azure AD and extracts user claims.
 *
 * Token signature is verified using the Azure AD JWK Set endpoint. Issuer and
 * audience are checked strictly against the registered application's tenant and
 * client-id so tokens from other tenants or applications are always rejected.
 */
@Service
public class TokenValidationService {

    private static final Logger logger = LoggerFactory.getLogger(TokenValidationService.class);

    private final AppProperties appProperties;
    private JwtDecoder jwtDecoder;

    public TokenValidationService(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    @PostConstruct
    public void init() {
        String jwkSetUri = appProperties.getAzureAd().getJwkSetUri();
        logger.info("Initialising JWT decoder with JWK Set URI: {}", jwkSetUri);
        this.jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) {
            logger.debug("Token is null or empty");
            return false;
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return validateClaims(jwt);
        } catch (Exception e) {
            logger.warn("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    private boolean validateClaims(Jwt jwt) {
        Instant now = Instant.now();
        if (jwt.getExpiresAt() != null && jwt.getExpiresAt().isBefore(now)) {
            logger.debug("Token is expired");
            return false;
        }

        String tenantId = appProperties.getAzureAd().getTenantId();
        String expectedIssuer = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
        if (jwt.getIssuer() == null) {
            logger.warn("Missing issuer claim in JWT");
            return false;
        }
        String issuer = jwt.getIssuer().toString();
        if (!expectedIssuer.equals(issuer)) {
            logger.warn("Issuer mismatch — expected: {}, got: {}", expectedIssuer, issuer);
            return false;
        }

        String expectedAudience = appProperties.getAzureAd().getClientId();
        List<String> audiences = jwt.getAudience();
        if (audiences == null || !audiences.contains(expectedAudience)) {
            logger.warn("Audience mismatch — expected: {}, got: {}", expectedAudience, audiences);
            return false;
        }

        logger.debug("Token valid for subject: {}", jwt.getSubject());
        return true;
    }

    /**
     * Parses a token that has already been validated by {@link #validateToken}.
     * Uses Nimbus to reconstruct the Jwt object from the raw token value and its claims.
     */
    public Jwt parseToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return new Jwt(
                token,
                signedJWT.getJWTClaimsSet().getIssueTime() != null
                    ? signedJWT.getJWTClaimsSet().getIssueTime().toInstant() : null,
                signedJWT.getJWTClaimsSet().getExpirationTime() != null
                    ? signedJWT.getJWTClaimsSet().getExpirationTime().toInstant() : null,
                signedJWT.getHeader().toJSONObject(),
                signedJWT.getJWTClaimsSet().getClaims()
            );
        } catch (Exception e) {
            logger.error("Failed to parse JWT token", e);
            throw new IllegalArgumentException("Invalid JWT token format", e);
        }
    }

    public String getUserName(Jwt jwt) {
        return Stream.of("name", "preferred_username", "upn")
            .map(jwt::getClaimAsString)
            .filter(Objects::nonNull)
            .findFirst()
            .orElse(jwt.getSubject());
    }

    public String getUserEmail(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        return email != null ? email : jwt.getClaimAsString("preferred_username");
    }
}
