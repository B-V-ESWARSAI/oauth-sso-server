package com.sai.oauth_sso_server;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGenerator {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        String privateKey = Base64.getEncoder()
                .encodeToString(keyPair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder()
                .encodeToString(keyPair.getPublic().getEncoded());

        System.out.println("=== PRIVATE KEY (add to env variables) ===");
        System.out.println(privateKey);
        System.out.println();
        System.out.println("=== PUBLIC KEY (add to env variables) ===");
        System.out.println(publicKey);
    }
}