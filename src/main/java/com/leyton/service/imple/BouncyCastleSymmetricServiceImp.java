
package com.leyton.service.imple;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.SymmetricService;

public class BouncyCastleSymmetricServiceImp implements SymmetricService {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(BouncyCastleSymmetricServiceImp.class);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    public String encrypt(String data, Key key, String algorithm) {
        try {
            LOGGER.info("Trying {} BC encrypt...", algorithm);
            Cipher encryptCiper = Cipher.getInstance(algorithm, new BouncyCastleProvider());
            encryptCiper.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherData = encryptCiper.doFinal(data.getBytes(StandardCharsets.UTF_8));
            cipherData = Base64.getEncoder().encode(cipherData);
            return new String(cipherData);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} BC encrypt... ", algorithm, e);
        }
        return null;
    }

    @Override
    public String decrypt(String encryptData, Key key, String algorithm) {
        try {
            LOGGER.info("Trying {} BC decrypt...", algorithm);
            Cipher decryptCiper = Cipher.getInstance(algorithm, new BouncyCastleProvider());
            decryptCiper.init(Cipher.DECRYPT_MODE, key);
            byte[] bytesEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
            byte[] cipherData = decryptCiper.doFinal(bytesEncryptData);
            return new String(cipherData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} BC decrypt... ", algorithm, e);
        }
        return null;
    }
}
