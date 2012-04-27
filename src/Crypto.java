
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/*
 * To change this template, choose Tools | Templates and open the template in
 * the editor.
 */
/**
 *
 * @author avinash
 */
public class Crypto {

    public static String sha1(String msg) throws NoSuchAlgorithmException {
        // TODO code application logic here
        byte[] output;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());
        output = md.digest();
        return (bytesToHex(output));
    }

    public static String bytesToHex(byte[] message) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < message.length; i++) {
            hexString.append(Integer.toHexString(0xFF & message[i]));
        }
        return hexString.toString();
    }
}
