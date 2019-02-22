
package com.leyton.service.inter;

public interface PasswordEncoder {

    String encode(String password);

    boolean verify(String password, String hashed);
}
