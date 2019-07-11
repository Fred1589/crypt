package com.fb.commons.crypt;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Crypt {

    private static final String ALGORITHM = "AES";
    private static final String CIPHER_SUITE = "AES/CBC/PKCS5Padding";
    private static final Integer IV_LENGTH = 16;
    private static final int MAGIC_NUMBER_3 = 3;
    private static final String UTF_8 = "UTF-8";

    private Crypt() {
        // private constructor
    }

    public static String encrypt(final byte[] key, final String value) throws GeneralSecurityException {
        final byte[] iv = generateIV();
        final SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        final IvParameterSpec ivSpec = new IvParameterSpec(iv);
        final Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        final byte[] encrypted = cipher.doFinal(value.getBytes(Charset.forName(UTF_8)));
        final byte[] ivPlusEncrypted = new byte[IV_LENGTH + encrypted.length + MAGIC_NUMBER_3];
        ivPlusEncrypted[0] = 'I';
        ivPlusEncrypted[1] = 'V';
        ivPlusEncrypted[2] = '*';
        System.arraycopy(iv, 0, ivPlusEncrypted, MAGIC_NUMBER_3, iv.length);
        System.arraycopy(encrypted, 0, ivPlusEncrypted, iv.length + MAGIC_NUMBER_3, encrypted.length);
        return Base64.getEncoder().encodeToString(ivPlusEncrypted);
    }

    public static String decrypt(final byte[] key, final String value) throws GeneralSecurityException {
        final byte[] decoded = Base64.getDecoder().decode(value);
        if (decoded == null) {
            throw new GeneralSecurityException("failed to decode base64-encoded value");
        }
        // check whether to use IV or not
        if (decoded.length >= MAGIC_NUMBER_3 && decoded[0] == 'I' && decoded[1] == 'V' && decoded[2] == '*') {
            final SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            final Cipher cipher = Cipher.getInstance(CIPHER_SUITE);
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(decoded, MAGIC_NUMBER_3, iv, 0, iv.length);
            final IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] cipherText = new byte[decoded.length - iv.length - MAGIC_NUMBER_3];
            System.arraycopy(decoded, iv.length + MAGIC_NUMBER_3, cipherText, 0, cipherText.length);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            final byte[] decrypted = cipher.doFinal(cipherText);
            return new String(decrypted, Charset.forName(UTF_8));
        } else {
            final SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            final byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted, Charset.forName(UTF_8));
        }
    }

    private static byte[] generateIV() {
        final byte[] saltBytes = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(saltBytes);
        return saltBytes;
    }

}
