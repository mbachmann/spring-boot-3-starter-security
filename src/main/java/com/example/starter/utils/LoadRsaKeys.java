package com.example.starter.utils;

import com.example.starter.utils.StringUtils;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.util.Scanner;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class LoadRsaKeys {
    private static final String LINE_SEPARATOR = "\r\n";
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    private LoadRsaKeys() {
    }

    public static RSAPublicKey loadPublicKeyFromFile(String publicKeyFilePath) throws IOException, GeneralSecurityException {
        String publicKeyPem = getFileContent(publicKeyFilePath);
        return loadPublicKeyFromPem(publicKeyPem);
    }

    public static RSAPublicKey loadPublicKeyFromResource(String resourceFilePath) throws IOException, GeneralSecurityException {
        String publicKeyPem = StringUtils.getResourceFileAsString(resourceFilePath);
        return loadPublicKeyFromPem(publicKeyPem);
    }

    public static RSAPublicKey loadPublicKeyFromPem(String publicKeyPem) throws GeneralSecurityException {
        String publicKeyPEMStr = publicKeyPem;
        if (publicKeyPem.startsWith(BEGIN_CERTIFICATE)) {
            publicKeyPEMStr = publicKeyPEMStr.replace(BEGIN_CERTIFICATE, "")
                .replaceAll(LINE_SEPARATOR, "")
                .replace(END_CERTIFICATE, "");
            return (RSAPublicKey) getX509Certificate(publicKeyPEMStr.trim()).getPublicKey();

        } else if (publicKeyPEMStr.startsWith(BEGIN_PUBLIC_KEY)) {
            publicKeyPEMStr = publicKeyPEMStr.replace(BEGIN_PUBLIC_KEY, "")
                .replaceAll(LINE_SEPARATOR, "")
                .replace(END_PUBLIC_KEY, "");
            byte[] encoded = DatatypeConverter.parseBase64Binary(publicKeyPEMStr.trim());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }
        throw new IllegalArgumentException("Content is not a certificate or public key in PEM format");
    }


    private static X509Certificate getX509Certificate(String certificateString) throws CertificateException {
        CertificateFactory cfb = CertificateFactory.getInstance("X509");
        InputStream inputStream = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(certificateString));
        return (X509Certificate) cfb.generateCertificate(inputStream);
    }

    public static RSAPrivateKey loadPrivateKeyFromFile(String privateKeyPath) throws IOException, GeneralSecurityException {
        String privateKeyPem = getFileContent(privateKeyPath);
        return loadPrivateKeyFromPem(privateKeyPem);
    }

    public static RSAPrivateKey loadPrivateKeyFromResource(String resourceFilePath) throws IOException, GeneralSecurityException {
        String privateKeyPem = StringUtils.getResourceFileAsString(resourceFilePath);
        return loadPrivateKeyFromPem(privateKeyPem);
    }

    public static RSAPrivateKey loadPrivateKeyFromPem(String privateKeyPem) throws GeneralSecurityException {
        String privateKey = privateKeyPem.replace(BEGIN_PRIVATE_KEY, "")
            .replaceAll(LINE_SEPARATOR, "")
            .replace(END_PRIVATE_KEY, "")
            .replace(BEGIN_RSA_PRIVATE_KEY, "")
            .replace(END_RSA_PRIVATE_KEY, "");
        byte[] encodedPrivateKey = DatatypeConverter.parseBase64Binary(privateKey);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
    }

    private static String getFileContent(String filePath) throws IOException {
        final StringBuilder sb = new StringBuilder();
        File file = new File(filePath);
        if (file.exists()) {
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                sb.append(scanner.nextLine()).append(LINE_SEPARATOR);
            }
            scanner.close();
            return sb.toString();
        } else {
            throw new IllegalArgumentException("File does not exist");
        }
    }

    /**
     * Read public and private key from file
     * Convert private key to appropriate format:  openssl pkcs8 -topk8 -nocrypt -in private-key.pem -out myrsakey_pcks8
     * @param publicKeyFileName
     * @param privateKeyFileName
     * @return
     */
    public static KeyPair readKeyPairFromResource(final String publicKeyFileName, final String privateKeyFileName) {
        RSAPublicKey pubKey;
        RSAPrivateKey privKey;
        try {
            pubKey = LoadRsaKeys.loadPublicKeyFromResource(publicKeyFileName);
        } catch (GeneralSecurityException | IOException e) {
            throw new JwtException("Could not parse pem file " + publicKeyFileName, e);
        }

        try {
            privKey = LoadRsaKeys.loadPrivateKeyFromResource(privateKeyFileName);
        } catch (IOException | SignatureException | GeneralSecurityException e) {
            throw new JwtException("Could not parse pem file " + privateKeyFileName, e);
        }
        return new KeyPair(pubKey, privKey);
    }
}