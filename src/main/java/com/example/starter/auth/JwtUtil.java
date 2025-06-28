package com.example.starter.auth;

import com.example.starter.utils.StringUtils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public final class JwtUtil {
    public static final long SECOND_IN_MILLIS = 1000;
    public static final long MINUTE_IN_MILLIS = SECOND_IN_MILLIS * 60;
    public static final long HOUR_IN_MILLIS = MINUTE_IN_MILLIS * 60;
    public static final long DAY_IN_MILLIS = HOUR_IN_MILLIS * 24;
    private JwtUtil() {
    }
    public static String createJWT(byte[] privateKey, String id, String issuer, String subject, String userName, String role) {
        //The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
        long nowMillis = System.currentTimeMillis();
        //We will sign our JWT with our ApiKey secret
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory rsaFact = null;
        try {
            rsaFact = KeyFactory.getInstance("RSA");
            RSAPrivateKey key = (RSAPrivateKey) rsaFact.generatePrivate(spec);

            String jwt = Jwts.builder()
                    .header().keyId("shared")

                    .and()

                    .subject(subject)
                    .issuedAt(new Date())
                    .expiration(new Date((new Date()).getTime() + DAY_IN_MILLIS))
                    .claim("role", role)
                    .signWith(signatureAlgorithm, key)
                    .compact();
            return jwt;

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private void readPrivateKeyFromResource() {
        System.out.println("Private Key" + StringUtils.getResourceFileAsString("keypair/private-key.pem"));
    }

    private void readPublicKeyFromResource() {
        System.out.println("Private Key" + StringUtils.getResourceFileAsString("keypair/public-key.pem"));
    }

    /**
     * Encode PublicKey (DSA or RSA encoded) to authorized_keys like string
     *
     * @param publicKey DSA or RSA encoded
     * @param user username for output authorized_keys like string
     * @return authorized_keys like string
     * @throws IOException
     */
    public static String encodePublicKey(PublicKey publicKey, String user)
        throws IOException {
        String publicKeyEncoded;
        if(publicKey.getAlgorithm().equals("RSA")){
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(byteOs);
            dos.writeInt("ssh-rsa".getBytes().length);
            dos.write("ssh-rsa".getBytes());
            dos.writeInt(rsaPublicKey.getPublicExponent().toByteArray().length);
            dos.write(rsaPublicKey.getPublicExponent().toByteArray());
            dos.writeInt(rsaPublicKey.getModulus().toByteArray().length);
            dos.write(rsaPublicKey.getModulus().toByteArray());
            publicKeyEncoded = new String(
                Base64.getEncoder().encode(byteOs.toByteArray()));
            return "ssh-rsa " + publicKeyEncoded + " " + user;
        }
        else if(publicKey.getAlgorithm().equals("DSA")){
            DSAPublicKey dsaPublicKey = (DSAPublicKey) publicKey;
            DSAParams dsaParams = dsaPublicKey.getParams();

            ByteArrayOutputStream byteOs = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(byteOs);
            dos.writeInt("ssh-dss".getBytes().length);
            dos.write("ssh-dss".getBytes());
            dos.writeInt(dsaParams.getP().toByteArray().length);
            dos.write(dsaParams.getP().toByteArray());
            dos.writeInt(dsaParams.getQ().toByteArray().length);
            dos.write(dsaParams.getQ().toByteArray());
            dos.writeInt(dsaParams.getG().toByteArray().length);
            dos.write(dsaParams.getG().toByteArray());
            dos.writeInt(dsaPublicKey.getY().toByteArray().length);
            dos.write(dsaPublicKey.getY().toByteArray());
            publicKeyEncoded = new String(
                Base64.getEncoder().encode(byteOs.toByteArray()));
            return "ssh-dss " + publicKeyEncoded + " " + user;
        }
        else{
            throw new IllegalArgumentException(
                "Unknown public key encoding: " + publicKey.getAlgorithm());
        }
    }


}
