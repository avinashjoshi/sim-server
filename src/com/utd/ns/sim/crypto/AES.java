package com.utd.ns.sim.crypto;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.ArrayList;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class has all Crypto tools needed by the application.
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class AES {

    public static String doEncryptDecryptHMACToString(String receivedText, String key, char mode) {
        return doEncryptDecryptHMAC(receivedText, key, mode).get(1);
    }
    
    /**
     * This is the main function being called
     *
     * @param receivedText is the text to be encrypted or decrypted
     * @param key is the private key that is used for encryption or decryption
     * @param mode is either 'E' for Encryption or 'D' for decryption
     * @return Returns the encrypted or decrypted string. Returns null if the
     * encryption or decryption is not successful
     * @throws NoSuchAlgorithmException
     * @throws Exception
     */
    public static ArrayList<String> doEncryptDecryptHMAC(String receivedText, String key, char mode) {
        ArrayList<String> returnString = new ArrayList();
        try {
            String keyHash = SHA.SHA256String(key);
            String aesKey = keyHash.substring(0, keyHash.length() / 2);
            String hmacKey = keyHash.substring(keyHash.length() / 2);
            StringBuilder encText = new StringBuilder();

            if (mode == 'E') {
                String hash = AES.genHash(receivedText.getBytes("ASCII"), hmacKey);
                encText.append(receivedText);
                encText.append(hash);
                returnString.add(0, "ENCRYPTED");
                returnString.add(1, encrypt(encText.toString(), aesKey));
            } else if (mode == 'D') {
                String decText = decrypt(receivedText, aesKey);
                String oldHash = decText.substring(decText.length() - 44, decText.length());
                String plainText = decText.substring(0, decText.length() - 44);
                String newHash = AES.genHash(plainText.getBytes("ASCII"), hmacKey);

                if (oldHash.equals(newHash)) {
                    //System.out.println("Hash verified");
                    returnString.add(0, "DECRYPTED");
                    returnString.add(1, plainText);
                } else {
                    //System.out.println("Hash not verified");
                    returnString.add(0, "FAILED");
                    returnString.add(1, "The message has been compromised!");
                }
            }
        } catch (IllegalBlockSizeException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (BadPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (ShortBufferException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidAlgorithmParameterException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchProviderException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidKeyException ex) {
            returnString.add(0, "INVALID_KEY");
            returnString.add(1, "Invalid key!");
        } catch (UnsupportedEncodingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (Exception ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        }
        return returnString;
    }

    public static ArrayList<String> doEncryptDecrypt(String receivedText, String key, char mode) {
        ArrayList<String> returnString = new ArrayList();
        try {
            String keyHash = SHA.SHA256String(key);
            StringBuilder encText = new StringBuilder();

            if (mode == 'E') {
                encText.append(receivedText);
                returnString.add(0, "ENCRYPTED");
                returnString.add(1, encrypt(encText.toString(), keyHash));
            } else if (mode == 'D') {
                String decText = decrypt(receivedText, keyHash);
                returnString.add(0, "DECRYPTED");
                returnString.add(1, decText);
            }
        } catch (IllegalBlockSizeException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (BadPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (ShortBufferException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidAlgorithmParameterException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchProviderException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (NoSuchPaddingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, "Some Exception");
        } catch (InvalidKeyException ex) {
            returnString.add(0, "INVALID_KEY");
            returnString.add(1, "Invalid key!");
        } catch (UnsupportedEncodingException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (NoSuchAlgorithmException ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        } catch (Exception ex) {
            returnString.add(0, "FAILED");
            returnString.add(1, ex.getMessage());
        }
        return returnString;
    }

    /**
     * This is the main encryption function
     *
     * @param plainText is the plain text that has to be encrypted
     * @param plainKey is the key with which plainText has to be encrypted
     * @return Returns the encrypted String
     * @throws Exception
     */
    private static String encrypt(String plainText, String plainKey) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = createCtrIvForAES(1, random);
        Key cipherKey = createKeyForAES(256, plainKey);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

        // Encryption step starts here
        ivSpec = new IvParameterSpec(ivSpec.getIV());
        cipher.init(Cipher.ENCRYPT_MODE, cipherKey, ivSpec);

        String finalCipherB64;

        byte[] cipherText = new byte[cipher.getOutputSize(plainText.length())];

        int ctLength = cipher.update(plainText.getBytes(), 0, plainText.length(), cipherText, 0);

        ctLength += cipher.doFinal(cipherText, ctLength);

        /*
         * We could make plaintext to Hex finalCipherHex =
         * Utils.toHex(ivSpec.getIV()) + ":" + Utils.toHex(cipherText);
         */
        finalCipherB64 = Utils.base64Encrypt(ivSpec.getIV()) + ":" + Utils.base64Encrypt(cipherText);

        return Utils.base64Encrypt(finalCipherB64);
    }

    /**
     * This is the main decryption function
     *
     * @param cipherText is the cipher text that has to be decrypted
     * @param plainKey is the key with which plainText has to be decrypted
     * @return Returns the decrypted String
     * @throws Exception
     */
    private static String decrypt(String cipherText, String plainKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, ShortBufferException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
        byte[] plainText = null;
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            IvParameterSpec ivSpec;
            Key cipherKey = createKeyForAES(256, plainKey);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

            byte[] cipherByte = Utils.base64Decrypt(cipherText);
            cipherText = Utils.toString(cipherByte);
            String split[] = cipherText.split(":");
            ivSpec = new IvParameterSpec(Utils.base64Decrypt(split[0]));
            byte[] cipherBytes = Utils.base64Decrypt(split[1]);

            // decryption step starts here
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, ivSpec);
            int ctLength = cipherBytes.length;
            plainText = new byte[cipher.getOutputSize(ctLength)];
            int ptLength = cipher.update(cipherBytes, 0, ctLength, plainText, 0);
            ptLength += cipher.doFinal(plainText, ptLength);


        } catch (IllegalBlockSizeException ex) {
            throw ex;
        } catch (BadPaddingException ex) {
            throw ex;
        } catch (ShortBufferException ex) {
            throw ex;
        } catch (InvalidKeyException ex) {
            throw ex;
        } catch (InvalidAlgorithmParameterException ex) {
            throw ex;
        } catch (NoSuchAlgorithmException ex) {
            throw ex;
        } catch (NoSuchProviderException ex) {
            throw ex;
        } catch (NoSuchPaddingException ex) {
            throw ex;
        }
        return Utils.toString(plainText);
    }
    private static String result = null;

    /**
     * Generate hash of the input byte array Current Algorithm is HMACSHA256
     *
     * @param inBuffer Takes the bytes that have to be hashed
     * @param hmacKey Key for calculating HMAC
     * @return Returns the HMAC string
     */
    public static String genHash(byte[] inBuffer, String hmacKey) {
        try {
            result = SHA.calcSHAHMAC(inBuffer, hmacKey);
        } catch (SignatureException e) {
            System.err.println("genHash(): Signature Exception");
            result = null;
        }
        return result;
    }

    /**
     * Create a key for use with AES.
     *
     * @param bitLength
     * @param random
     * @return an AES key.
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static SecretKey createKeyForAES(
            int bitLength,
            SecureRandom random)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");

        generator.init(256, random);

        return generator.generateKey();
    }

    public static SecretKey createKeyForAES(int bitLength, String key) throws NoSuchAlgorithmException {
        SecretKeySpec skey = new SecretKeySpec(SHA.SHA256(key), "AES");
        return skey;
    }

    /**
     * Create an IV suitable for using with AES in CTR mode. <p> The IV will be
     * composed of 4 bytes of message number, 4 bytes of random data, and a
     * counter of 8 bytes.
     *
     * @param messageNumber the number of the message.
     * @param random a source of randomness
     * @return an initialized IvParameterSpec
     */
    public static IvParameterSpec createCtrIvForAES(
            int messageNumber,
            SecureRandom random) {
        byte[] ivBytes = new byte[16];

        // initially randomize

        random.nextBytes(ivBytes);

        // set the message number bytes

        ivBytes[0] = (byte) (messageNumber >> 24);
        ivBytes[1] = (byte) (messageNumber >> 16);
        ivBytes[2] = (byte) (messageNumber >> 8);
        ivBytes[3] = (byte) (messageNumber);
        // Above is the same as:
        // ivBytes[3] = (byte) (messageNumber >> 0);

        // set the counter bytes to 1
        for (int i = 0; i != 7; i++) {
            ivBytes[8 + i] = 0;
        }

        ivBytes[15] = 1;

        return new IvParameterSpec(ivBytes);
    }
}