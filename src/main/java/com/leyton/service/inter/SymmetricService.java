
package com.leyton.service.inter;

import java.security.Key;

public interface SymmetricService {

    String encrypt(String data, Key key, String algorithm);

    String decrypt(String encryptData, Key key, String algorithm);
}
