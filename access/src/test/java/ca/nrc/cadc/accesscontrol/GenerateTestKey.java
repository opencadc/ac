package ca.nrc.cadc.accesscontrol;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Generate test RSA key pair
 */
public class GenerateTestKey {
    
    public static void main(String[] args) throws Exception {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Save private key to file
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        
        try (FileOutputStream fos = new FileOutputStream("src/test/resources/RsaSignaturePriv.key")) {
            fos.write(privateKeyPEM.getBytes());
        }
        
        // Save public key to file
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        
        try (FileOutputStream fos = new FileOutputStream("src/test/resources/RsaSignaturePub.key")) {
            fos.write(publicKeyPEM.getBytes());
        }
        
        System.out.println("RSA key pair generated:");
        System.out.println("Private key: src/test/resources/RsaSignaturePriv.key");
        System.out.println("Public key: src/test/resources/RsaSignaturePub.key");
    }
} 