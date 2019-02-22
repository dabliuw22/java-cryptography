
package com.leyton.service.imple;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.AsymmetricService;

public class SimpleAsymmetricServiceImp implements AsymmetricService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleAsymmetricServiceImp.class);

    @Override
    public String encrypt(String data, PublicKey key, String algorithm) {
        try {
            LOGGER.info("Trying {} encrypt...", algorithm);
            Cipher encryptCiper = Cipher.getInstance(algorithm);
            encryptCiper.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherData = encryptCiper.doFinal(data.getBytes(StandardCharsets.UTF_8));
            cipherData = Base64.getEncoder().encode(cipherData);
            return new String(cipherData);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} encrypt... ", algorithm, e);
        }
        return null;
    }

    @Override
    public String decrypt(String encryptData, PrivateKey key, String algorithm) {
        try {
            LOGGER.info("Trying {} decrypt...", algorithm);
            Cipher decryptCiper = Cipher.getInstance(algorithm);
            decryptCiper.init(Cipher.DECRYPT_MODE, key);
            byte[] bytesEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
            byte[] cipherData = decryptCiper.doFinal(bytesEncryptData);
            return new String(cipherData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} decrypt... ", algorithm, e);
        }
        return null;
    }
}
