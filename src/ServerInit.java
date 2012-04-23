
import java.util.ResourceBundle;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author avinash
 */
public class ServerInit {
    public static int TCPPort;
    public static String passwdFile;
    
    static {
        ResourceBundle sConfigBundle = ResourceBundle.getBundle("server-conf");
        TCPPort = Integer.parseInt((String) sConfigBundle.getObject("TCPPort"));
        passwdFile = (String) sConfigBundle.getObject("PasswdFile");
    }
}
