
package com.leyton.util;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptoUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtil.class);

    public static final int INIT_VECTOR_DEFAULT_SIZE_BYTES = 16;

    private CryptoUtil() {
    }

    public static Key generateKey(String algorithm) {
        try {
            return KeyGenerator.getInstance(algorithm).generateKey();
        } catch (Exception e) {
            LOGGER.error("Error trying to generate the {} key... ", algorithm, e);
            return null;
        }
    }

    public static Key generateKey(String algorithm, int keySize) {
        try {
            if (algorithm.equals(AesAlgorithm.AES_KEY_ALGORITHM)) {
                SecureRandom secureRandom = new SecureRandom();
                KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
                keyGenerator.init(keySize, secureRandom);
                return keyGenerator.generateKey();
            }
        } catch (Exception e) {
            LOGGER.error("Error trying to generate the {} key, size: {}... ", algorithm, keySize,
                    e);
        }
        return null;
    }

    public static Key generateKey(String key, String algorithm) {
        // byte[] bytesKey = Base64.getDecoder().decode(key)
        byte[] bytesKey = Hex.decode(key);
        return new SecretKeySpec(bytesKey, 0, bytesKey.length, algorithm);
    }

    public static String keyToString(Key key) {
        // return new String(Base64.getEncoder().encode(key.getEncoded()), StandardCharsets.UTF_8)
        return new String(Hex.encode(key.getEncoded()));
    }

    public static KeyPair generateKeyPair(String algorithm, int keySize) {
        try {
            if (algorithm.equals(RsaAlgorihm.RSA_KEY_ALGORITHM)) {
                SecureRandom secureRandom = new SecureRandom();
                KeyPairGenerator keyPairGenerator;
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                keyPairGenerator.initialize(keySize, secureRandom);
                return keyPairGenerator.generateKeyPair();
            }
        } catch (Exception e) {
            LOGGER.error("Error trying to generate the {} pair key, size: {}... ", algorithm,
                    keySize, e);
        }
        return null;
    }

    public static KeyPair generateKeyPair(String publicKey, String privateKey, String algorithm) {
        PublicKey pubKey = generatePublicKey(publicKey, algorithm);
        PrivateKey privKey = generatePrivateKey(privateKey, algorithm);
        if (Objects.nonNull(pubKey) && Objects.nonNull(privKey)) {
            return new KeyPair(pubKey, privKey);
        }
        return null;
    }

    public static PublicKey generatePublicKey(String publicKey, String algorithm) {
        try {
            publicKey = publicKey.replace(RsaAlgorihm.BEGIN_PUBLIC_KEY, "")
                    .replace(RsaAlgorihm.END_PUBLIC_KEY, "");
            byte[] data = Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8));
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(data);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            LOGGER.error("Error trying to generate the {} public key from string... ", algorithm,
                    e);
        }
        return null;
    }

    public static PrivateKey generatePrivateKey(String privateKey, String algorithm) {
        try {
            privateKey = privateKey.replace(RsaAlgorihm.BEGIN_PRIVATE_KEY, "")
                    .replace(RsaAlgorihm.END_PRIVATE_KEY, "");
            byte[] data = Base64.getDecoder().decode(privateKey.getBytes(StandardCharsets.UTF_8));
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(data);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            LOGGER.error("Error trying to generate the {} private key from string... ", algorithm,
                    e);
        }
        return null;
    }

    public static byte[] generateInitializationVector() {
        byte[] initVector = new byte[INIT_VECTOR_DEFAULT_SIZE_BYTES];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initVector);
        return initVector;
    }

    public static class AesAlgorithm {

        public static final int SIZE_128_BITS = 128;

        public static final int SIZE_192_BITS = 192;

        public static final int SIZE_256_BITS = 256;

        public static final String AES_KEY_ALGORITHM = "AES";

        public static final String AES_CIPHER_BLOCK_CHAINING_OPERATION_MODE_ALGORITHM =
                "AES/CBC/PKCS5Padding";

        public static final String AES_ELECTRONIC_CODEBOOK_OPERATION_MODE_ALGORITHM =
                "AES/ECB/PKCS7Padding";

        private AesAlgorithm() {
        }
    }

    public static class DesAlgorithm {

        public static final String DES_ALGORITHM = "DES";

        private DesAlgorithm() {
        }
    }

    public static class RsaAlgorihm {

        public static final int SIZE_1024_BITS = 1024;

        public static final int SIZE_2048_BITS = 2048;

        public static final int SIZE_3072_BITS = 3072;

        public static final int SIZE_4096_BITS = 4096;

        public static final String RSA_KEY_ALGORITHM = "RSA";

        public static final String RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_ALGORITHM =
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

        public static final String RSA_OPTIMAL_ASYMETRIC_ENCRYPTION_PADDING_ENCODING_BC_ALGORITHM =
                "RSA/None/OAEPWithSHA-256AndMGF1Padding";

        public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";

        public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

        public static final String BEGIN_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";

        public static final String END_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

        public static final String PUBLIC_KEY_CHAIN_1024_BITS = "-----BEGIN PUBLIC KEY-----"
                + "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFiAB3U14PunQBaRGR8psPQXXZC4"
                + "7w4Wmxh7aS1xeCxrYJScr/wxrLX5bKz0dThe5XGdPSQiErpgCKYcUCzmUR0UDx3t"
                + "4EhTh85ZEN7GQKhrFfyoNgjnuknEoGWXBPq4AmLUirCnChx4aEQn45VqjDpiPoNa"
                + "hRqfoWWToUjcJIwRAgMBAAE=-----END PUBLIC KEY-----";

        public static final String PRIVATE_KEY_CHAIN_1024_BITS = "-----BEGIN RSA PRIVATE KEY-----"
                + "MIICWgIBAAKBgFiAB3U14PunQBaRGR8psPQXXZC47w4Wmxh7aS1xeCxrYJScr/wx"
                + "rLX5bKz0dThe5XGdPSQiErpgCKYcUCzmUR0UDx3t4EhTh85ZEN7GQKhrFfyoNgjn"
                + "uknEoGWXBPq4AmLUirCnChx4aEQn45VqjDpiPoNahRqfoWWToUjcJIwRAgMBAAEC"
                + "gYAv/AsPJE1+ZSq8kaO7X9GQJ3MV2w/S5bLmTVOzzghInVfafDJ3XT+10y13gXxl"
                + "Oh7RwV27T7Yz04oc9tEJ5z8nD4W+UbITCcBiOxoxRJjTJkOvk/BpnnD8XXfC8zCs"
                + "UNtix+zebo9btScWyxyeQqdGjeopNeQXfqGkrgRa2KDcIQJBAKAfXRkXppNy4CLR"
                + "4MMn1LfNdN8wSvLyf3gs8U7QuNLGjYgwfA6dkbWo+zQyzCd5JSAApP3R85G+k4/3"
                + "01ESCD0CQQCNfek1YIYAFutGtlKdUCEnYgVGDA5k3JODa14vxQaI60p9TSYIRB+k"
                + "e634WU0FTsFczmT/OJFFLbUgkqTXDTxlAkAMNrg8PMCZCK8uGMJDQJuKNaLPj3h4"
                + "FaVBfnQdpfAjK8AJ/mDIIJ7Hs48NyT4nWKdLTKFJNyWUHWxWE/pLeculAkAxJhSV"
                + "KwNBErUFah3GcWgi0wS78UIqvQgstWYRN+JuOzUz01Gru2Y2b5Pd2b9MYa//Od6R"
                + "XSfxHNB3ERlbbkiVAkAw5gHa2tusnSJQMrAgoIQSPhkKfs3NR0Jy5sY5zceqxdan"
                + "2NrZFhCVRIpZ5CdEpbgvI9GGKGTazMQM02kMbKWH-----END RSA PRIVATE KEY-----";

        public static final String PUBLIC_KEY_CHAIN_2048_BITS = "-----BEGIN PUBLIC KEY-----"
                + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq+yddmkdhPIUStN5/nU8"
                + "HCFp6UW/r8L4WFR/27NMRGRUxFzWhW9VGqjX0hZTavDHYn9IBmNZk0gLjr4w4eYv"
                + "mydzqqHgsgm8fLB4VdicoY2rJdJpi87aIMXlxvgsx67G4wK/PX9oIJU9BZG8n1lH"
                + "jEScIPWCdsxdazqtBsjNXwYfyDKYg+u6P4TlhLKFY/0r6JR4uQR6RMHC4F9Rbxyo"
                + "e0KBEzPh/OacJqVblhLeathatXs8eIPdWSWHKZzwVYa7eAY3Iq8G8Ku7AOM8uq5D"
                + "FLycn3spD30XKHouhNR7dHU25HJ1J/LWlELQx/MfgCIndm7gStEwUGFIL+uw4CPn"
                + "gwIDAQAB-----END PUBLIC KEY-----";

        public static final String PRIVATE_KEY_CHAIN_2048_BITS = "-----BEGIN RSA PRIVATE KEY-----"
                + "MIIEowIBAAKCAQEAq+yddmkdhPIUStN5/nU8HCFp6UW/r8L4WFR/27NMRGRUxFzW"
                + "hW9VGqjX0hZTavDHYn9IBmNZk0gLjr4w4eYvmydzqqHgsgm8fLB4VdicoY2rJdJp"
                + "i87aIMXlxvgsx67G4wK/PX9oIJU9BZG8n1lHjEScIPWCdsxdazqtBsjNXwYfyDKY"
                + "g+u6P4TlhLKFY/0r6JR4uQR6RMHC4F9Rbxyoe0KBEzPh/OacJqVblhLeathatXs8"
                + "eIPdWSWHKZzwVYa7eAY3Iq8G8Ku7AOM8uq5DFLycn3spD30XKHouhNR7dHU25HJ1"
                + "J/LWlELQx/MfgCIndm7gStEwUGFIL+uw4CPngwIDAQABAoIBAQCT/eQ1r5pHfJLX"
                + "Ll9PGN+bX2/p665rv6tDbcl590dpf+wv87J9vi5F+p19LNa1sXoQYXxAc3kB/Pxl"
                + "7XXqntjP+A/rC9l9qD/mHYoYa5O4xVhUAGH2hSLjHzcCJVN2uA5gD1dLusaJda3H"
                + "g4IYsSOTrOOww2WAmb64tROISYXvisroMcYQ5h+6hInle/HINKTguQkBTj+u7QAp"
                + "/qeg2aDbg8U/eTNGf3/ZFLeZVP12XS/H7s2+ab46g+dXJZsLWVOdx0NfVyU2zqTy"
                + "BhCqDDrZU6q/J3BC8fyl7hmailLfyDVLwfdgGVL2zfhFEeyJv+Rf9N3LI/XOkLBV"
                + "kssbIGzhAoGBAPMcLBst+0K70+rFSq4s+jHHZ/Y73iE7mDRo7UTDhkRTChT5zAkR"
                + "waY+6oF6V0Nf6hcugnCjyboSXKi95S7mZjWM4HJoRU3mlXPf/N7Lrg1G49u4SQPN"
                + "nvWiQ1aZANT4syV6pw/cyhWPHGML0SPqNvofB/7e7Rgnukgzy7p3UyKpAoGBALUK"
                + "NeQf7bkexISJKRgdbye8+AH3KJy8UuaWdCN9LWnJuIFJFnGFDoO/ZQdL2+JvgV9E"
                + "SiJ4w8X5/CXFBy+Qak3/bYjMVdODfCwrpBe0cKCnsJoeYCvfLT8HquEREJ+7B4Ua"
                + "JiOaWeKlLcQc/1n3SA7SAC4s1W7GheDfOPaSusBLAoGAWPBtkmP4ECn3FWSoNaBu"
                + "x9dTyVmNokrTHBlm9EkzzbszbQkWBBti5RcPY98GHbfxRBnXzq2dF12wWGtgdRAF"
                + "RIINes16zU0WUBYZxMhvHJxar/9zdti61tJOIFhJXaC+qW99vuffZpO8pt+j26fM"
                + "BSVlH3Ee/D9Mfy2z0rvkxkECgYA5ECPWaN30WKdWoykJydVMcDq32+C4Ln/u4INw"
                + "4DbdPlDip1fkpiziCATfHOEM6Vqc3ZiEbw4+K8J3YTgXnOx080riMI3o4mvUPFk3"
                + "g49whAqdOW/UxD6tvEv3LvrPbhM7t/dHh5JHZwsa4oz2HYRf739RDp6jkP2H2LRK"
                + "vAsTKwKBgDfgv8H2rhaAXIt6zBLiObuYKrEXU583bfiy6R+gBns/LEr7VC0JMFSm"
                + "ZMtk8eKZmrw7NKw9M4DyyYKKeL1evcR5kg/0qHpNna3/PUnHk2bgnTGPloN05KOz"
                + "8go3wC68ewni1Uxm/kl9dHrxBn9m3P5SSL0uJQLPK8msfBWTpZVX"
                + "-----END RSA PRIVATE KEY-----";

        private RsaAlgorihm() {
        }
    }
}
