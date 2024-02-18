package com.example.starter.controller;

import com.example.starter.auth.JwtUtil;
import com.example.starter.utils.LoadRsaKeys;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.annotation.PostConstruct;
import java.lang.invoke.MethodHandles;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@RestController
@RequestMapping("/signing-keys")
public class SigningKeyController {
    static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private KeyPair rsaKeyPair;
    private RSAKey jwkRsaPublicKey;
    @PostConstruct
    public void generateKey() throws NoSuchAlgorithmException, JOSEException {
        this.rsaKeyPair = generateRsaKeyPair(2048);
        logger.info("generate key {}", this.rsaKeyPair.getPublic());
        RSAPublicKey rsaPublicKey = (RSAPublicKey) this.rsaKeyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) this.rsaKeyPair.getPrivate();
        this.jwkRsaPublicKey = new RSAKey.Builder(rsaPublicKey).build();
        logger.info("jwkRsaPublicKey (JWK-Format) {}", this.jwkRsaPublicKey);
    }

    @GetMapping(path = "/ssh-public-key", produces = "application/json")
    public String sshKey() throws JOSEException, IOException {
        logger.info("Keys was called {}", this.jwkRsaPublicKey.toString());
        String encodedString = JwtUtil.encodePublicKey(this.jwkRsaPublicKey.toPublicKey(), "Chall App");
        return "{\n\"  key\": \"" + encodedString + "\"\n}";
    }

    @GetMapping(path = "/openssl-public-key", produces = "application/json")
    public String publicKey() throws JOSEException, IOException {
        logger.info("Keys was called {}", this.jwkRsaPublicKey.toString());
        String out = "\n-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString( rsaKeyPair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----\n";
        return "{\n  \"key\": \"" + out + "\"\n}";
    }

    // @GetMapping(path = "/private-key", produces = "application/json")
    public byte[] getPrivateKey() throws JOSEException {
        RSAKey privateKey = new RSAKey.Builder((RSAPublicKey) this.rsaKeyPair.getPublic()).privateKey(this.rsaKeyPair.getPrivate()).build();
        return privateKey.toRSAPrivateKey().getEncoded();
    }

    @GetMapping(path = "/openssl-private-key", produces = "application/json")
    public String getPrivateKeyString() throws JOSEException {
        RSAKey privateKey = new RSAKey.Builder((RSAPublicKey) this.rsaKeyPair.getPublic()).privateKey(this.rsaKeyPair.getPrivate()).build();
        String out = "\n-----BEGIN RSA PRIVATE KEY-----\n" + Base64.getMimeEncoder().encodeToString( rsaKeyPair.getPrivate().getEncoded()) + "\n-----END RSA PRIVATE KEY-----\n";
        return "{\n  \"key\": \"" + out + "\"\n}";
    }
    private KeyPair generateRsaKeyPair(int keyLengthInt) throws NoSuchAlgorithmException {
        KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
        keypairGenerator.initialize(keyLengthInt, new SecureRandom());
        return keypairGenerator.generateKeyPair();
    }

    @GetMapping(path = "/get-sample-token", produces = "application/json")
    public String getSampleToken() throws JOSEException {
       String out = JwtUtil.createJWT(rsaKeyPair.getPrivate().getEncoded(), "123", "issuer", "subject", "student001", "student");
        return "{\n\"  jwt\": \"" + out + "\"\n}";
    }
}