package com.utd.ns.sim.crypto;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * General utilities used by our code
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 */
public class Utils {

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @param length the number of bytes to process
     * @return a String representation of bytes
     */
    public static String toString(
            byte[] bytes,
            int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    /**
     * Convert a byte array of 8 bit characters into a String.
     *
     * @param bytes the array containing the characters
     * @return a String representation of bytes
     */
    public static String toString(
            byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    /**
     * Input is a string to encrypt.
     *
     * @return a Base64 encoded string of cipher text
     */
    public static String base64Encrypt(String abPlaintext) {
        return base64Encrypt(abPlaintext.getBytes());
    }

    public static String base64Encrypt(byte[] abPlaintext) {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        try {
            return base64Encoder.encode(abPlaintext);

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Input encrypted String represented in Base64
     *
     * @return a string decrypted in plain text
     */
    public static byte[] base64Decrypt(String base64CipherText) {
        BASE64Decoder base64Decoder = new BASE64Decoder();
        try {
            //return Arrays.toString(base64Decoder.decodeBuffer(base64CipherText));
            return base64Decoder.decodeBuffer(base64CipherText);
        } catch (Exception e) {
            return null;
        }
    }
    private static String digits = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static byte[] hexToByte(String hexString) {
        int len = hexString.length();
        byte[] ba = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            ba[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
        }
        return ba;
    }
}
