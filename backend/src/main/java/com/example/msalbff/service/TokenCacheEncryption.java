package com.example.msalbff.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Encrypts and decrypts MSAL token cache data using AES-256-GCM before persistence to Redis.
 *
 * <p>Each ciphertext is prefixed with a fresh 12-byte IV, so encrypting the same plaintext
 * twice always produces different output. The 128-bit GCM authentication tag detects
 * any in-flight tampering of the ciphertext.
 *
 * <p>If {@code app.redis.encryption-key} is not set, encryption is disabled and a startup
 * warning is logged. <strong>Always set the key in non-local environments.</strong>
 * Generate a key with: {@code openssl rand -base64 32}
 */
@Service
public class TokenCacheEncryption {

    private static final Logger logger = LoggerFactory.getLogger(TokenCacheEncryption.class);
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int REQUIRED_KEY_BYTES = 32;

    private final SecretKey secretKey;
    private final boolean enabled;

    public TokenCacheEncryption(@Value("${app.redis.encryption-key:}") String base64Key) {
        if (!StringUtils.hasText(base64Key)) {
            this.secretKey = null;
            this.enabled = false;
            logger.warn("SECURITY: Redis token cache encryption is DISABLED. "
                    + "Set app.redis.encryption-key to a 256-bit base64 key in non-local environments. "
                    + "Generate with: openssl rand -base64 32");
        } else {
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            if (keyBytes.length != REQUIRED_KEY_BYTES) {
                throw new IllegalArgumentException(
                        "app.redis.encryption-key must be a base64-encoded 256-bit (32-byte) key; "
                                + "got " + keyBytes.length + " bytes. Generate with: openssl rand -base64 32");
            }
            this.secretKey = new SecretKeySpec(keyBytes, "AES");
            this.enabled = true;
            logger.info("Redis token cache AES-256-GCM encryption enabled");
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Encrypts {@code plaintext} and returns a base64-encoded string containing the IV
     * prepended to the ciphertext. Throws {@link GeneralSecurityException} on failure.
     *
     * @throws IllegalStateException if encryption is not enabled
     */
    public String encrypt(String plaintext) throws GeneralSecurityException {
        if (!enabled) {
            throw new IllegalStateException("Encryption called but no key is configured");
        }
        byte[] iv = generateIv();
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        byte[] ivAndCiphertext = new byte[IV_LENGTH_BYTES + ciphertext.length];
        System.arraycopy(iv, 0, ivAndCiphertext, 0, IV_LENGTH_BYTES);
        System.arraycopy(ciphertext, 0, ivAndCiphertext, IV_LENGTH_BYTES, ciphertext.length);
        return Base64.getEncoder().encodeToString(ivAndCiphertext);
    }

    /**
     * Decrypts a value produced by {@link #encrypt(String)}.
     *
     * @throws IllegalStateException if encryption is not enabled
     */
    public String decrypt(String encryptedValue) throws GeneralSecurityException {
        if (!enabled) {
            throw new IllegalStateException("Decryption called but no key is configured");
        }
        byte[] ivAndCiphertext = Base64.getDecoder().decode(encryptedValue);
        byte[] iv = Arrays.copyOf(ivAndCiphertext, IV_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH_BYTES, ivAndCiphertext.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        return new String(cipher.doFinal(ciphertext), java.nio.charset.StandardCharsets.UTF_8);
    }

    private byte[] generateIv() {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
