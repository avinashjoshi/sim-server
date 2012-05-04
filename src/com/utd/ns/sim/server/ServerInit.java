package com.utd.ns.sim.server;

import com.utd.ns.sim.crypto.RSA;
import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * This file imports all "variables" that are staically declared in
 * server-conf.properties - Uses Apache log4j
 */
/**
 *
 * @author avinash
 */
public class ServerInit {

    public static int TCPPort;
    public static String passwdFile;
    public static String workingDirectory;
    public static String keysFolder;
    public static String confFolder;

    static {
        
        ServerInit.confFolder = "src/com/utd/ns/sim/server/conf/";
        
        ResourceBundle sConfigBundle = ResourceBundle.getBundle(ServerInit.confFolder.replaceAll("src/", "") + "server-conf");
        TCPPort = Integer.parseInt((String) sConfigBundle.getObject("TCPPort"));
        workingDirectory = (String) sConfigBundle.getObject("WorkingDirectory");
        File theDir = new File(ServerInit.workingDirectory);
        if (!theDir.exists()) {
            theDir.mkdirs();
        }

        passwdFile = ServerInit.workingDirectory.concat((String) sConfigBundle.getObject("PasswdFile"));
        keysFolder = ServerInit.workingDirectory.concat((String) sConfigBundle.getObject("KeyFolder"));
        theDir = new File(ServerInit.keysFolder);
        if (!theDir.exists()) {
            theDir.mkdirs();
        }
        
    }
}
