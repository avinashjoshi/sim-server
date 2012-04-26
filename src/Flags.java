
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/*
 * This function has a list of all variables (Flags) that can be accessed
 * anywhere in the program.
 */
/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class Flags {

    public static final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    public static int totalConnections; //Total number of connections
    public static int clientNumber; // Current ClientNumber For adding to hashmap userList
    public static final Lock clientNumberReadLock = readWriteLock.readLock();
    public static final Lock clientNumberWriteLock = readWriteLock.writeLock();
    public static HashMap<Integer, Socket> allSocketList; //A hashmap of all sockets connected via TCP
    public static boolean endServer; // The main thread TCPListener quits if this is true
    public static int tcpPort; // The TCP Port being used by server (from property file)
    public static ArrayList<Integer> clientPorts;
    public static ServerSocket serverSocket;
    public static HashMap<String, Socket> ipUserSession; // List of all logged-in users (IP based session)
    public static ArrayList<UserPass> usersList; // List of all users from passwd file
    //public static boolean passFileInUse; // To ensure no two thread access passwd file same time
    public static final Lock passwdReadLock = readWriteLock.readLock();
    public static final Lock passwdWriteLock = readWriteLock.writeLock();

    public Flags() {
        clientPorts = new ArrayList<Integer>();
        totalConnections = 0;
        tcpPort = ServerInit.TCPPort;
        endServer = true;
        allSocketList = new HashMap<Integer, Socket>();
        clientNumber = 0;
        usersList = new ArrayList<UserPass>();
        ipUserSession = new HashMap<String, Socket>();
    }
}
