
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.log4j.Logger;

/*
 * TCPListner keeps listening for new TCP connections from various clients
 */
/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class TCPListener extends Thread {

    private TCPConnect tcpConnection;
    private int TCPPort;
    public static Logger log = Logger.getLogger(TCPListener.class);
    private Socket listenSock;

    public TCPListener() {
        TCPPort = ServerInit.TCPPort;
    }

    @Override
    public void run() {
        try {
            /*
             * Creating ServerSocket() Note that I user Flags so that the socket
             * can be closed from main()
             */
            Flags.serverSocket = new ServerSocket(TCPPort);
            log.info("Connected to " + Flags.serverSocket);
            while (Flags.endServer == false) {
                // Listening for incoming connections
                listenSock = Flags.serverSocket.accept();
                //Adding entry into userList

                Flags.clientNumberWriteLock.lock();
                try {

                    Flags.allSocketList.put(Flags.clientNumber, listenSock);
                    Flags.clientNumber++;
                    Flags.totalConnections++;
                    
                    //Starting a new thread for actual processing!
                    tcpConnection = new TCPConnect(listenSock, Flags.clientNumber);
                    tcpConnection.start();
                } finally {
                    Flags.clientNumberWriteLock.unlock();
                }

            }
        } catch (Exception e) {
        }
    }
}