
import java.util.ResourceBundle;

/*
 * This file imports all "variables" that are staically declared
 * in server-conf.properties - Uses Apache log4j
 */

/**
 *
 * @author avinash
 */
public class ServerInit {
    public static int TCPPort;
    public static String passwdFile;
    public static String workingDirectory;
    
    static {
        ResourceBundle sConfigBundle = ResourceBundle.getBundle("server-conf");
        TCPPort = Integer.parseInt((String) sConfigBundle.getObject("TCPPort"));
        workingDirectory = (String) sConfigBundle.getObject("WorkingDirectory");
        passwdFile = ServerInit.workingDirectory.concat((String) sConfigBundle.getObject("PasswdFile"));
    }
}
