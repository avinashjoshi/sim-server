
import java.security.MessageDigest;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author avinash
 */
public class Crypto {

    public static String sha1(String msg) {
        // TODO code application logic here
        byte[] output;
        String digest;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(msg.getBytes());
            output = md.digest();
            digest = bytesToHex(output);
        } catch (Exception e) {
            //System.out.println("Exception: " + e);
            digest = "";
        }
        return digest;
    }

    public static String bytesToHex(byte[] b) {
        char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        StringBuilder buf = new StringBuilder();
        for (int j = 0; j < b.length; j++) {
            buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
            buf.append(hexDigit[b[j] & 0x0f]);
        }
        return buf.toString();
    }
}
