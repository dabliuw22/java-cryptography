
package com.leyton;

import java.security.Key;
import java.security.KeyPair;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.leyton.service.imple.AesSymmetricServiceImp;
import com.leyton.service.imple.BouncyCastleAsymmetricServiceImp;
import com.leyton.service.imple.HybridServiceImp;
import com.leyton.service.imple.MessageDigestHashServiceImp;
import com.leyton.service.imple.SimpleAsymmetricServiceImp;
import com.leyton.service.imple.SimpleSymmetricServiceImp;
import com.leyton.service.inter.AsymmetricService;
import com.leyton.service.inter.HashService;
import com.leyton.service.inter.HybridService;
import com.leyton.service.inter.SymmetricService;
import com.leyton.util.CryptoUtil;
import com.leyton.util.HashUtil;

public class JavaCryptographyApplication {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaCryptographyApplication.class);

    public static void main(String[] args) {
        String data = "Hello World Secret Message";
        Key key = CryptoUtil.generateKey(CryptoUtil.AesAlgorithm.AES_KEY_ALGORITHM,
                CryptoUtil.AesAlgorithm.SIZE_256_BITS);
        LOGGER.info("Symetric...");
        if (Objects.nonNull(key)) {
            SymmetricService aes = new SimpleSymmetricServiceImp();
            String encryptData = aes.encrypt(data, key, CryptoUtil.AesAlgorithm.AES_KEY_ALGORITHM);
            LOGGER.info("{} encrypt data: {}", CryptoUtil.AesAlgorithm.AES_KEY_ALGORITHM,
                    encryptData);
            String decryptData =
                    aes.decrypt(encryptData, key, CryptoUtil.AesAlgorithm.AES_KEY_ALGORITHM);
            LOGGER.info("{} decrypt data: {}", CryptoUtil.AesAlgorithm.AES_KEY_ALGORITHM,
                    decryptData);
        }

        LOGGER.info("Symetric with IV...");
        if (Objects.nonNull(key)) {
            byte[] initVector = CryptoUtil.generateInitializationVector();
            SymmetricService aesService = new AesSymmetricServiceImp(initVector);
            String encryptData = aesService.encrypt(data, key,
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM);
            LOGGER.info("{} encrypt data: {}",
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM,
                    encryptData);
            String decryptData = aesService.decrypt(encryptData, key,
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM);
            LOGGER.info("{} decrypt data: {}",
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM,
                    decryptData);
        }

        LOGGER.info("Hash...");
        byte[] salt = HashUtil.generateSalt();
        if (Objects.nonNull(salt)) {
            HashService hashService = new MessageDigestHashServiceImp();
            String hash1 = hashService.hash("Message Digest", HashUtil.SHA_256_ALGORITHM, salt);
            String hash2 = hashService.hash("Message Digest", HashUtil.SHA_256_ALGORITHM, salt);
            LOGGER.info("Hash 1: {}, Hash 2: {}", hash1, hash2);
        }

        KeyPair keyPair = CryptoUtil.generateKeyPair(CryptoUtil.RsaAlgorihm.RSA_KEY_ALGORITHM,
                CryptoUtil.RsaAlgorihm.SIZE_4096_BITS);

        LOGGER.info("Asymmetric...");
        if (Objects.nonNull(keyPair)) {
            AsymmetricService rsaAsymmetricService = new SimpleAsymmetricServiceImp();
            String encryptData = rsaAsymmetricService.encrypt(data, keyPair.getPublic(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_ALGORITHM);
            LOGGER.info("{} encrypt data: {}",
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_ALGORITHM,
                    encryptData);
            String decryptData = rsaAsymmetricService.decrypt(encryptData, keyPair.getPrivate(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_ALGORITHM);
            LOGGER.info("{} decrypt data: {}",
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_ALGORITHM,
                    decryptData);
        }

        LOGGER.info("Asymmetric BC...");
        if (Objects.nonNull(keyPair)) {
            AsymmetricService rsaBcAsymmetricService = new BouncyCastleAsymmetricServiceImp();
            String encryptData = rsaBcAsymmetricService.encrypt(data, keyPair.getPublic(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM);
            LOGGER.info("{} encrypt data: {}",
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM,
                    encryptData);
            String decryptData = rsaBcAsymmetricService.decrypt(encryptData, keyPair.getPrivate(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM);
            LOGGER.info("{} decrypt data: {}",
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM,
                    decryptData);
        }

        KeyPair keyPairTwo =
                CryptoUtil.generateKeyPair(CryptoUtil.RsaAlgorihm.PUBLIC_KEY_CHAIN_2048_BITS,
                        CryptoUtil.RsaAlgorihm.PRIVATE_KEY_CHAIN_2048_BITS,
                        CryptoUtil.RsaAlgorihm.RSA_KEY_ALGORITHM);
        LOGGER.info("Hybrid...");
        if (Objects.nonNull(key) && Objects.nonNull(keyPairTwo)) {
            byte[] initVector = CryptoUtil.generateInitializationVector();
            HybridService hybridService = new HybridServiceImp(
                    new AesSymmetricServiceImp(initVector), new SimpleAsymmetricServiceImp());
            String encryptKey = hybridService.encryptKey(key, keyPairTwo.getPublic(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM);
            String encryptData = hybridService.encrypt(data, key,
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM);
            LOGGER.info("Hybrid encrypt data: {}, key: {}", encryptData, encryptKey);
            Key decryptKey = hybridService.decryptKey(encryptKey, keyPairTwo.getPrivate(),
                    CryptoUtil.RsaAlgorihm.RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM,
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM);
            String decryptData = hybridService.decrypt(encryptData, decryptKey,
                    CryptoUtil.AesAlgorithm.AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM);
            LOGGER.info("Hybrid decrypt data: {}", decryptData);
        }
    }
}
