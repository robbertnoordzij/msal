package com.example.msalbff.service;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class TokenCacheEncryptionTest {

    private static final String VALID_KEY_BASE64 = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String PLAINTEXT = "{\"AccessToken\":{\"key\":\"value\"}}";

    @Test
    void isEnabled_returnsFalse_whenKeyNotConfigured() {
        TokenCacheEncryption encryption = new TokenCacheEncryption("");

        assertFalse(encryption.isEnabled());
    }

    @Test
    void isEnabled_returnsTrue_whenValidKeyConfigured() {
        TokenCacheEncryption encryption = new TokenCacheEncryption(VALID_KEY_BASE64);

        assertTrue(encryption.isEnabled());
    }

    @Test
    void encryptThenDecrypt_returnsOriginalPlaintext() throws Exception {
        TokenCacheEncryption encryption = new TokenCacheEncryption(VALID_KEY_BASE64);

        String ciphertext = encryption.encrypt(PLAINTEXT);
        String decrypted = encryption.decrypt(ciphertext);

        assertEquals(PLAINTEXT, decrypted);
    }

    @Test
    void encrypt_producesDifferentCiphertext_forSamePlaintext() throws Exception {
        TokenCacheEncryption encryption = new TokenCacheEncryption(VALID_KEY_BASE64);

        String first = encryption.encrypt(PLAINTEXT);
        String second = encryption.encrypt(PLAINTEXT);

        assertNotEquals(first, second, "Each encryption must use a fresh IV");
    }

    @Test
    void encrypt_throwsIllegalStateException_whenDisabled() {
        TokenCacheEncryption encryption = new TokenCacheEncryption("");

        assertThrows(IllegalStateException.class, () -> encryption.encrypt(PLAINTEXT));
    }

    @Test
    void decrypt_throwsIllegalStateException_whenDisabled() {
        TokenCacheEncryption encryption = new TokenCacheEncryption("");

        assertThrows(IllegalStateException.class, () -> encryption.decrypt("any"));
    }

    @Test
    void constructor_throwsIllegalArgumentException_whenKeyIsWrongLength() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);

        assertThrows(IllegalArgumentException.class, () -> new TokenCacheEncryption(shortKey));
    }
}
