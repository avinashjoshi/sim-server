/*
 * Main Server class.
 * Server is a command-line program that Reads from the server-conf property
 * file, the port on which its supposed to run.
 * 
 * This program has different options start, stop, help and quit.
 */

/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
import java.io.*;
import java.util.ArrayList;
import org.apache.log4j.Logger;

public class Server {

    public static Logger log = Logger.getLogger(Server.class);

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException, FileNotFoundException, ClassNotFoundException {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String task = "";
        int i, totalCon;

        System.out.println("Initializing...");
        log.info("Initialized server...");
        System.out.println("Type help to get list of commands");
        System.out.println();
        Flags flag = new Flags();

        while (!"quit".equals(task)) {
            i = 0;
            System.out.print("server> ");
            task = in.readLine();
            if (task.equals("help")) {
                System.out.println("Possible commands: help, start, stop, quit");
            } else if (task.equals("start")) {
                if (Flags.endServer == false) {
                    System.out.println("Server already started!");
                    continue;
                }
                System.out.println("Starting server...");

                File file = new File(ServerInit.passwdFile);
                //If the file exists, read password object from the file
                if (file.exists()) {
                    //Check if password file is use by other 
                    Flags.passwdReadLock.lock();
                    try {
                        log.info("Loading userList");
                        FileInputStream fstream = new FileInputStream(ServerInit.passwdFile);
                        ObjectInputStream obj = new ObjectInputStream(fstream);
                        Flags.usersList = (ArrayList<UserPass>) obj.readObject();
                        obj.close();
                        fstream.close();
                        i = 0;
                        while (i < Flags.usersList.size()) {
                            System.out.println(Flags.usersList.get(i).getUserName() + ":" + Flags.usersList.get(i).getPassed());
                            i++;
                        }
                    } finally {
                        Flags.passwdReadLock.unlock();
                    }
                } else {
                    log.info("Password file does not exist. Will create new one when necessary");
                }
                Flags.endServer = false;
                Flags.clientNumber = 0;
                TCPListener tcpListen = new TCPListener();
                tcpListen.start();
                log.info("Started server...");
            } else if (task.equals("stop")) {
                if (Flags.endServer == true) {
                    System.out.println("Server already stopped!");
                    continue;
                }
                System.out.println("Stopping server...");
                // From 
                totalCon = Flags.allSocketList.size();
                Flags.loggedInUsers.clear();
                while (i < totalCon) {
                    if (Flags.allSocketList.get(i) != null) {
                        if (Flags.allSocketList.get(i).isConnected()) {
                            Flags.allSocketList.get(i).close();
                            log.info("Closing connection with " + Flags.allSocketList.get(i));
                        }
                        Flags.allSocketList.remove(i);
                    }
                    i++;
                }
                Flags.ipUserSession.clear();
                Flags.endServer = true;
                if (Flags.serverSocket != null) {
                    Flags.serverSocket.close();
                }
                // We need to write the state of userpasswd list
                Flags.passwdWriteLock.lock();
                try {
                    log.info("Writing userList state into passwd file");
                    FileOutputStream fstream = new FileOutputStream(ServerInit.passwdFile);
                    ObjectOutputStream obj = new ObjectOutputStream(fstream);
                    obj.writeObject(Flags.usersList);
                    obj.close();
                    fstream.close();
                } finally {
                    Flags.passwdWriteLock.unlock();
                }
                log.info("Server stopped... Total connections this session: " + Flags.totalConnections);
            } else if (task.contains("print")) {
                System.out.println("clientNumber = " + Flags.clientNumber);
            } else if (!task.contains("quit")) {
                System.out.println("Invalid command. Type help for list of commands");
            } else if (task.contains("quit")) {
                if (Flags.endServer == false) {
                    System.out.println("You must first stop the server before quitting!");
                    task = "";
                }
            }
        }
    }
}
