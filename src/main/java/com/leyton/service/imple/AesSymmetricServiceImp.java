
package com.leyton.service.imple;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.SymmetricService;

public class AesSymmetricServiceImp implements SymmetricService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AesSymmetricServiceImp.class);

    private byte[] initVector;

    public AesSymmetricServiceImp(byte[] initVector) {
        this.initVector = initVector;
    }

    @Override
    public String encrypt(String data, Key key, String algorithm) {
        String encryptdata;
        try {
            LOGGER.info("Trying {} encrypt...", algorithm);
            Cipher encryptCiper = Cipher.getInstance(algorithm);
            IvParameterSpec ivParameterSpec = toIv();
            encryptCiper.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] cipherData = encryptCiper.doFinal(data.getBytes(StandardCharsets.UTF_8));
            cipherData = Base64.getEncoder().encode(cipherData);
            encryptdata = new String(cipherData);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} encrypt... ", algorithm, e);
            encryptdata = null;
        }
        return encryptdata;
    }

    @Override
    public String decrypt(String encryptData, Key key, String algorithm) {
        String decryptData;
        try {
            LOGGER.info("Trying {} decrypt...", algorithm);
            Cipher decryptCiper = Cipher.getInstance(algorithm);
            IvParameterSpec ivParameterSpec = toIv();
            decryptCiper.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            byte[] bytesEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
            byte[] cipherData = decryptCiper.doFinal(bytesEncryptData);
            decryptData = new String(cipherData, StandardCharsets.UTF_8);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} decrypt... ", algorithm, e);
            decryptData = null;
        }
        return decryptData;
    }

    private IvParameterSpec toIv() {
        return new IvParameterSpec(initVector);
    }
}
