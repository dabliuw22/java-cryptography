
package com.leyton.service.inter;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface SignatureService {

    byte[] sign(byte[] data, PrivateKey key, String algorithm);

    boolean verify(byte[] data, byte[] signatureToVerify, PublicKey key, String algorithm);
}
