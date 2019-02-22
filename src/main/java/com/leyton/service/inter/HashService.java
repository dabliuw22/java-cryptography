
package com.leyton.service.inter;

public interface HashService {

    String hash(String data, String algorithm, byte[] salt);
}
