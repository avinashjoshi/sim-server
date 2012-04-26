
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

/*
 * To change this template, choose Tools | Templates and open the template in
 * the editor.
 */
/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class Serial {

    public static void writeObject(Socket sock, Object obj) throws IOException {
        ObjectOutputStream out = new ObjectOutputStream(sock.getOutputStream());
        out.writeObject(obj);
    }

    public static Object readObject(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream in;
        in = new ObjectInputStream(socket.getInputStream());
        Object obj = in.readObject();
        return obj;
    }
}
