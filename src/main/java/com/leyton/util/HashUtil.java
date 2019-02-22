
package com.leyton.util;

import java.security.SecureRandom;

public class HashUtil {

    public static final String SHA_256_ALGORITHM = "SHA-256";

    public static final int SALT_DEFAULT_SIZE = 16;

    private HashUtil() {
    }

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_DEFAULT_SIZE];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }
}
