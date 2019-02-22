
package com.leyton.service.imple;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.SignatureService;

public class SignatureServiceImp implements SignatureService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignatureServiceImp.class);

    @Override
    public byte[] sign(byte[] data, PrivateKey key, String algorithm) {
        try {
            LOGGER.info("Trying {} signature...", algorithm);
            Signature signature = Signature.getInstance(algorithm);
            signature.initSign(key);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            LOGGER.error("Error trying to {} signature... ", algorithm, e);
        }
        return new byte[0];
    }

    @Override
    public boolean verify(byte[] data, byte[] signatureToVerify, PublicKey key, String algorithm) {
        try {
            LOGGER.info("Trying {} verify signature...", algorithm);
            Signature signature = Signature.getInstance(algorithm);
            signature.initVerify(key);
            signature.update(data);
            return signature.verify(signatureToVerify);
        } catch (Exception e) {
            LOGGER.error("Error trying to {} verify signature... ", algorithm, e);
        }
        return false;
    }

}
