
package com.leyton.service.inter;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface HybridService extends SymmetricService {

    String encryptKey(Key data, PublicKey publicKey, String algorithm);

    Key decryptKey(String encryptData, PrivateKey privateKey, String rsaAlgorithm,
            String aesAlgorithm);
}
