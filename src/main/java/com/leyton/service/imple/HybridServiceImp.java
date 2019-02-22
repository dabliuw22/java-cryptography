
package com.leyton.service.imple;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.leyton.service.inter.AsymmetricService;
import com.leyton.service.inter.HybridService;
import com.leyton.service.inter.SymmetricService;
import com.leyton.util.CryptoUtil;

public class HybridServiceImp implements HybridService {

    private SymmetricService symmetricService;

    private AsymmetricService asymmetricService;

    public HybridServiceImp(SymmetricService symmetricService,
            AsymmetricService asymmetricService) {
        this.symmetricService = symmetricService;
        this.asymmetricService = asymmetricService;
    }

    @Override
    public String encrypt(String data, Key key, String algorithm) {
        return symmetricService.encrypt(data, key, algorithm);
    }

    @Override
    public String decrypt(String encryptData, Key key, String algorithm) {
        return symmetricService.decrypt(encryptData, key, algorithm);
    }

    @Override
    public String encryptKey(Key data, PublicKey publicKey, String algorithm) {
        String dataKey = CryptoUtil.keyToString(data);
        return asymmetricService.encrypt(dataKey, publicKey, algorithm);
    }

    @Override
    public Key decryptKey(String encryptData, PrivateKey privateKey, String rsaAlgorithm,
            String aesAlgorithm) {
        String data = asymmetricService.decrypt(encryptData, privateKey, rsaAlgorithm);
        return CryptoUtil.generateKey(data, aesAlgorithm);
    }
}
