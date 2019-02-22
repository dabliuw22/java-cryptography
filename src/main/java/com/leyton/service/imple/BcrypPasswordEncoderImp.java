
package com.leyton.service.imple;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.inter.PasswordEncoder;

public class BcrypPasswordEncoderImp implements PasswordEncoder {

    private static final Logger LOGGER = LoggerFactory.getLogger(BcrypPasswordEncoderImp.class);

    @Override
    public String encode(String password) {
        LOGGER.info("Trying password hash...");
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    @Override
    public boolean verify(String password, String hashed) {

        LOGGER.info("Trying verify password...");
        return BCrypt.checkpw(password, hashed);
    }
}
