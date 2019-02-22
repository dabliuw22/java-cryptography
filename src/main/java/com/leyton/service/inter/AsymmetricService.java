
package com.leyton.service.inter;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface AsymmetricService {

    String encrypt(String data, PublicKey publicKey, String algorithm);

    String decrypt(String encryptData, PrivateKey privateKey, String algorithm);
}
