/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.utd.ns.sim.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;

/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class SHA {

    public static byte[] SHA256(String msg) throws NoSuchAlgorithmException {
        // TODO code application logic here
        byte[] output;
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());
        output = md.digest();
        return (output);
    }

    public static String SHA256String(String msg) throws NoSuchAlgorithmException {
        return (Utils.toHex(SHA256(msg)));
    }
    private static final String SHA_HMAC_ALGORITHM = "HMACSHA256";
    private static byte[] abDigest = null;
    private static String szResult = null;
    private static Mac shaMac = null;
    private static SecretKeySpec secretKeySpec = null;

    /**
     * Actual method that generates a hash of the input byte array and returns
     * the Base64 encoded hash string
     *
     * @param inputMsg message whose HMAC has to be calculated
     * @param hmacKey Key
     * @return returns the HMAC as String
     * @throws java.security.SignatureException
     */
    public static String calcSHAHMAC(byte[] inputMsg, String hmacKey)
            throws java.security.SignatureException {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        try {
            shaMac = Mac.getInstance(SHA_HMAC_ALGORITHM);
            secretKeySpec = new SecretKeySpec(hmacKey.getBytes(), SHA_HMAC_ALGORITHM);
            shaMac.init(secretKeySpec);
            abDigest = shaMac.doFinal(inputMsg);
            // convert raw HMAC into Base64
            szResult = base64Encoder.encode(abDigest);
        } catch (NoSuchAlgorithmException e) {
            System.out.println(SHA_HMAC_ALGORITHM + ": no such algorithm!");
            szResult = null;
        } catch (InvalidKeyException e) {
            System.out.println("Invalid key!");
            szResult = null;
        }
        return szResult;
    }
}
