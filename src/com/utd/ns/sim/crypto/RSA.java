package com.utd.ns.sim.crypto;


import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

/**
 * Main Class that computes RSA
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */

public class RSA {

    static String PUBLIC_KEY_HEADER = "-----BEGIN RSA PUBLIC KEY-----\n";
    static String PUBLIC_KEY_FOOTER = "\n-----END RSA PUBLIC KEY-----\n";
    static String PRIVATE_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----\n";
    static String PRIVATE_KEY_FOOTER = "\n-----END RSA PRIVATE KEY-----\n";

    /**
     * Generates a Public and Private Key pair and saves it to key.pub and
     * key.priv The keysize is 1024 by default
     */
    public static void generatePubPrivPair() {
        generatePubPrivPair(1024);
    }

    /**
     * Generated a PublicKey and PrivateKey and saves it to key.pub and key.priv
     *
     * @param keysize is the size of key space for RSA
     */
    public static void generatePubPrivPair(int keysize) {
        generatePubPrivPair(keysize, "key");
    }

    /**
     * Generated a PublicKey and PrivateKey and saves it to fileName.pub and
     * fileName.priv
     *
     * @param keysize is the size of key space for RSA
     * @param fileName is the name of file where keys are to be stored
     */
    public static void generatePubPrivPair(int keysize, String fileName) {
        try {
            SecureRandom random = new SecureRandom();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            StringBuilder stringToFile = new StringBuilder();

            generator.initialize(keysize, random);
            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            byte[] encodedPub = pubKey.getEncoded();
            byte[] encodedPriv = privKey.getEncoded();

            /*
             * Generating Public key in Base64 Format
             */
            stringToFile.append(PUBLIC_KEY_HEADER);
            stringToFile.append(Utils.base64Encrypt(encodedPub));
            stringToFile.append(PUBLIC_KEY_FOOTER);
            writeKeyToFile(stringToFile.toString(), fileName + ".pub");

            /*
             * Generating Private key in Base64 Format
             */
            stringToFile = new StringBuilder();
            stringToFile.append(PRIVATE_KEY_HEADER);
            stringToFile.append(Utils.base64Encrypt(encodedPriv));
            stringToFile.append(PRIVATE_KEY_FOOTER);
            writeKeyToFile(stringToFile.toString(), fileName + ".priv");

        } catch (NoSuchAlgorithmException ex) {
        }
    }

    /**
     * Encrypts inputText given the PublicKey key file *.pub
     * Internally calls encrypt(String inputText,PublicKey key)
     * 
     * @param inputText is the text to be encrypted
     * @param fileName contains the public key (.pub format)
     * @return encrypted text in base64 format
     */
    public static String encrypt(String inputText, String fileName) {
        String encryptedText = new String();
        try {
            PublicKey key = RSA.getPublicKey(fileName);
            encryptedText = encrypt(inputText, key);
        } catch (Exception ex) {
        }
        return encryptedText;
    }

    /**
     * Encrypts inputText given the PublicKey key
     * 
     * @param inputText is the text to be encrypted
     * @param key is of type PublicKey
     * @return encrypted text in base64 format
     */
    public static String encrypt(String inputText, PublicKey key) {
        String encryptedText = new String();
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            // Get bytes from input text
            byte[] input = inputText.getBytes();
            SecureRandom random = new SecureRandom();
            cipher.init(Cipher.ENCRYPT_MODE, key, random);
            encryptedText = Utils.base64Encrypt(cipher.doFinal(input));
        } catch (Exception ex) {
        }
        return encryptedText;
    }
    
    /**
     * Decrypts inputText given the Private key file *.priv
     * Internally calls decrypt(String inputText,PrivateKey key)
     * 
     * @param inputText is the cipher text to be decrypted
     * @param fileName contains the private key (.priv format)
     * @return decrypted text
     */
    public static String decrypt(String inputText, String fileName) {
        String decryptedText = new String();
        try {
            PrivateKey key = getPrivateKey(fileName);
            decryptedText = decrypt(inputText, key);
        } catch (Exception ex) {
        }
        return decryptedText;
    }

    /**
     * Decrypts inputText given the PrivateKey key 
     * 
     * @param inputText is the cipher text to be decrypted
     * @param key is of type PrivateKey
     * @return decrypted text
     */
    public static String decrypt(String inputText, PrivateKey key) {
        String decryptedText = new String();
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainText = cipher.doFinal(Utils.base64Decrypt(inputText));
            decryptedText = new String(plainText);
        } catch (Exception ex) {
        }
        return decryptedText;
    }

    /**
     * Writes Key to a file
     * 
     * @param text content to be written
     * @param filename name of file
     * @return boolean true of false
     */
    public static boolean writeKeyToFile(String text, String filename) {
        FileOutputStream fos = null;
        boolean returnValue = false;
        try {
            File f = new File(filename);
            fos = new FileOutputStream(f);
            DataOutputStream dos = new DataOutputStream(fos);
            dos.writeBytes(text);
            dos.close();
            returnValue = true;
        } catch (FileNotFoundException ex) {
        } catch (IOException ex) {
        } finally {
            try {
                fos.close();
            } catch (IOException ex) {
            }
        }
        return returnValue;
    }

    /**
     * Returns the public key of type PublicKey from a .pub file
     * 
     * @param fileName name of .pub file
     * @return PublicKey key
     * @throws FileNotFoundException 
     */
    public static PublicKey getPublicKey(String fileName) throws FileNotFoundException {

        PublicKey publicKey = null;
        try {
            if (!fileName.endsWith(".pub")) {
                fileName = fileName.concat(".pub");
            }
            File f = new File(fileName);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] fileBytes = new byte[(int) f.length()];
            dis.readFully(fileBytes);
            dis.close();
            //System.out.println(keyBytes);
            String keyString = new String(fileBytes);
            keyString = keyString.replaceAll(PUBLIC_KEY_HEADER, "");
            keyString = keyString.replaceAll(PUBLIC_KEY_FOOTER, "");
            //System.out.println(keyString);

            byte[] keyBytes = Utils.base64Decrypt(keyString);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(keySpec);

        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
        } catch (NoSuchAlgorithmException ex) {
        }
        return publicKey;
    }

    /**
     * Returns the private key of type PrivateKey from a .priv file
     * 
     * @param fileName name of .priv file
     * @return PrivateKey key
     * @throws FileNotFoundException 
     */
    public static PrivateKey getPrivateKey(String fileName) throws FileNotFoundException {

        PrivateKey privateKey = null;
        try {
            if (!fileName.endsWith(".priv")) {
                fileName = fileName.concat(".priv");
            }
            File f = new File(fileName);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] fileBytes = new byte[(int) f.length()];
            dis.readFully(fileBytes);
            dis.close();
            //System.out.println(keyBytes);
            String keyString = new String(fileBytes);
            keyString = keyString.replaceAll(PRIVATE_KEY_HEADER, "");
            keyString = keyString.replaceAll(PRIVATE_KEY_FOOTER, "");
            //System.out.println(keyString);

            byte[] keyBytes = Utils.base64Decrypt(keyString);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(keySpec);

        } catch (IOException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
        } catch (NoSuchAlgorithmException ex) {
        }
        return privateKey;
    }
}