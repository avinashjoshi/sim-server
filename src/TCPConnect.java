
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import org.apache.log4j.Logger;

/*
 * TCPConnect is the Main "thread" that handles all communication between a user
 * (client) and the server (this application)
 *
 * Types of "Command" register: User trying register to the server login: User
 * trying to log into the server success.print: Print all success messages
 * success.log: Log all success messages error.print: Display Error messages on
 * client (pop-up) error.log: Log the error. Do not display these messages to
 * the user. A messages like "Oops! Something went wrong!" should do!
 */
/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class TCPConnect extends Thread {

    private Socket sock;
    private Packet packet;
    public static Logger log = Logger.getLogger(TCPConnect.class);
    private Packet sendPacket;
    private String command;
    private String usernameReceived;
    private String password;
    private int nonce;
    private String data;
    private int i;
    private int clientNumber;
    private String[] dataSplit;
    private String sessionUser;
    private String userList;

    public TCPConnect(Socket skt, int clientNumber) throws IOException {
        sock = skt;
        this.clientNumber = clientNumber;
        sessionUser = null;
    }

    @Override
    public void run() {
        try {
            /*
             * If this function is called using object.start(), a connection
             * with client (sock) is successfully established
             */
            log.info("Established connection with " + sock);
            /*
             * Keep waiting for packets from the client until the client dies
             */
            while (true) {
                /*
                 * Read object from socket "sock" and de-serialize that in the
                 * object packet of type Packet
                 */
                packet = (Packet) Serial.readObject(sock);
                sendPacket = new Packet();  // Creating a new packet to send back
                command = packet.getCommand();  // Get the command
                nonce = packet.getNonce();      // Get the Nonce
                data = packet.getData();        // Get the data
                i = 0;

                //Check if the packet really has something or not!
                if (command.equals("")
                        || data.equals("")
                        || nonce == 0) {
                    /*
                     * Warn the client that an invalid packet was sent!
                     */
                    log.warn("Received an invalid pakcet! on " + sock);
                    sendPacket.craftPacket("error.log", nonce + 1, "Invalid packet!");
                    Serial.writeObject(sock, sendPacket);
                    continue;
                } else if (command.equals("register")) {
                    /*
                     * User trying to register from a client the data will be
                     * username:password
                     */

                    dataSplit = data.split(":");
                    usernameReceived = dataSplit[0];
                    password = Crypto.sha1(dataSplit[1]);
                    i = Functions.CheckUser(usernameReceived);

                    if (i > -1) {
                        /*
                         * Yep, already in file
                         */
                        log.warn("Username already exists!");
                        sendPacket.craftPacket("error.print", packet.getNonce(), "User " + usernameReceived + " already Exists!");
                        Serial.writeObject(sock, sendPacket);
                    } else {
                        /*
                         * That user does not exist, creating a new one
                         */
                        UserPass userpass = new UserPass();
                        userpass.createUser(usernameReceived, password);
                        // add userpass object to the ArrayList
                        Flags.usersList.add(userpass);

                        // We need to write the state of userpasswd list
                        log.info("Writing userList state into passwd file");
                        FileOutputStream fstream = new FileOutputStream(ServerInit.passwdFile);
                        ObjectOutputStream obj = new ObjectOutputStream(fstream);
                        obj.writeObject(Flags.usersList);
                        obj.close();
                        fstream.close();

                        sendPacket.craftPacket("success.print", packet.getNonce() + 1, "Registered user ");
                        Serial.writeObject(sock, sendPacket);
                        log.info("Registering user " + usernameReceived);
                    }
                } else if (command.equals("login")) {
                    /*
                     * User trying to log into server... Data field is
                     * username:password
                     */

                    dataSplit = data.split(":");
                    usernameReceived = dataSplit[0];
                    password = Crypto.sha1(dataSplit[1]);
                    i = Functions.CheckUser(usernameReceived);

                    if (i == -1) {
                        /*
                         * Oops, un-registered user trying to log-in
                         */
                        log.warn("Oops, un-registered user trying to log-in!");
                        sendPacket.craftPacket("error.print", nonce, "Invalid username or password!");
                        Serial.writeObject(sock, sendPacket);
                    } else {
                        /*
                         * Username exists!
                         */
                        if (Flags.usersList.get(i).passwd.equals(password)) {
                            /*
                             * User authenticated. Check if user already in
                             * session (ipUserSession)
                             */
                            if (Functions.isLoggedIn(usernameReceived)) {
                                /*
                                 * User already has an existing session!
                                 */
                                sendPacket.craftPacket("error.print", nonce, "You are already logged in from "
                                        + Functions.getUserIPAddress(usernameReceived) + "!");
                                log.info("User trying to log in again from different IP -"
                                        + usernameReceived + ":" + sock.getInetAddress().getHostAddress());
                                Serial.writeObject(sock, sendPacket);
                            } else {
                                /*
                                 * Finally, Totally authenticated the user &
                                 * Adding username into session
                                 */
                                Flags.ipUserSession.put(usernameReceived, sock);
                                this.sessionUser = this.usernameReceived;
                                Flags.loggedInUsers.add(usernameReceived);
                                sendPacket.craftPacket("success.log", nonce, "Logged In!");
                                log.info("User logged in -" + usernameReceived + ":" + sock.getInetAddress().getHostAddress());
                                Serial.writeObject(sock, sendPacket);
                            }
                        } else {
                            /*
                             * Incorrect password
                             */
                            log.warn("Password incorrect for user " + usernameReceived + "!");
                            sendPacket.craftPacket("error.print", nonce, "Invalid username or password!");
                            Serial.writeObject(sock, sendPacket);
                        }
                    }
                } else if (command.equals("quit")) {
                    /*
                     * The client requested to close connection with server :(
                     */
                    Flags.ipUserSession.remove(usernameReceived);
                    Flags.loggedInUsers.remove(usernameReceived);
                    log.info("User " + usernameReceived + " quitting...");
                    break;
                } else if (Flags.loggedInCommands.contains(command)) {
                    /*
                     * Only user in session can access this area
                     */
                    if (sessionUser == null || !Functions.isLoggedIn(sessionUser)) {
                        /*
                         * User not logged in to access this section
                         */
                        log.info("User " + sessionUser + " unauthorized to access \"" + command + "\"");
                        sendPacket.craftPacket("error.print", nonce, "You need to be logged in!");
                        Serial.writeObject(sock, sendPacket);
                        continue;
                    } else if (command.equals("list")) {
                        /*
                         * User is querying to list all logged in users
                         */
                        log.info("Request to list by " + usernameReceived);
                        userList = Functions.getOnlineUsers(usernameReceived);
                        sendPacket.craftPacket("success.print", nonce, userList);
                        Serial.writeObject(sock, sendPacket);
                    } else if (command.equals("talk")) {
                        /*
                         * usernameReceived wanting to talk to another user
                         * Sending a ticket happens here!
                         */
                        
                        /*
                         * Basically, implement Otway-Rees algo!
                         * If user is valid, send:
                         * Key_1{userToTalk:IP:sessionKey}:Ticket
                         * Ticket = Key_2{userReceived:sessionKey:Nonce}
                         */
                        
                    } else if (command.equals("logout")) {
                        // Removing username from the session
                        Flags.ipUserSession.remove(usernameReceived);
                        Flags.loggedInUsers.remove(usernameReceived);
                        sendPacket.craftPacket("error.print", nonce, "Logged out!");
                        Serial.writeObject(sock, sendPacket);
                    }
                } else {
                    /*
                     * Error: command not one of the above "if" condition
                     */
                    log.info("Invalid packet - " + command + "|" + data);
                    sendPacket.craftPacket("error.log", nonce, "Command " + command + ": not found!");
                    Serial.writeObject(sock, sendPacket);
                }
            }
            Flags.clientNumberWriteLock.lock();
            try {
                sock.close();
                if (Flags.ipUserSession.containsValue(Flags.allSocketList.get(this.clientNumber))) {
                    Flags.ipUserSession.remove(usernameReceived);
                }
                Flags.allSocketList.remove(this.clientNumber);
                Flags.clientNumber--;
                System.out.println("ClientNumber = " + Flags.clientNumber);
            } finally {
                Flags.clientNumberWriteLock.unlock();
            }

        } catch (Exception e) {
        }
    }
}