package com.github.tmpstpdwn;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

class Vault {

    public enum BytesType {
        SALT_BYTES(16),
        IV_BYTES(12);

        private final int value;

        BytesType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }
    }

    private static final int GCM_TAG_LENGTH = 128;
    private static final int ITERATIONS = 696_969;
    private static final int KEYLENGTH = 256;

    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateBytes(BytesType bytesType) {
        byte[] bytes = new byte[bytesType.getValue()];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static byte[] getKeyBytes(String password, byte[] salt) throws Exception {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEYLENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return hash;
        } catch (Exception e) {
            throw new Exception("Failed to generate key");
        }
    }

    public static SecretKey getAESKey(String password, byte[] salt) throws Exception {
        byte[] keyBytes = getKeyBytes(password, salt);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static byte[] encrypt(String plaintext, SecretKey key) throws Exception {
        try {
            byte[] iv = generateBytes(BytesType.IV_BYTES);

            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

            return result;
        } catch (Exception e) {
            throw new Exception("Encryption failed");
        }
    }

    public static String decrypt(byte[] combined, SecretKey key) throws Exception {
        try {
            byte[] iv = new byte[BytesType.IV_BYTES.getValue()];
            byte[] ciphertext = new byte[combined.length - iv.length];

            System.arraycopy(combined, 0, iv, 0, iv.length);
            System.arraycopy(combined, iv.length, ciphertext, 0, ciphertext.length);

            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new Exception("Decryption failed: Invalid ciphertext or key");
        }
    }

}
