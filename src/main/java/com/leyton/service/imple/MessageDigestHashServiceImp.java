
package com.leyton.service.imple;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.HashService;

public class MessageDigestHashServiceImp implements HashService {

    private static final Logger LOGGER = LoggerFactory.getLogger(MessageDigestHashServiceImp.class);

    @Override
    public String hash(String data, String algorithm, byte[] salt) {
        try {
            LOGGER.info("Trying {} MD hash...", algorithm);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(salt);
            byteArrayOutputStream.write(data.getBytes());
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] hash = Base64.getEncoder()
                    .encode(messageDigest.digest(byteArrayOutputStream.toByteArray()));
            return new String(hash);
        } catch (Exception e) {
            LOGGER.error("Error trying {} MD hash: ", algorithm, e);
        }
        return null;
    }
}
