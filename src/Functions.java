
import java.util.ArrayList;

/*
 * This class will have all functions that might be necessary in the server
 * application
 */
/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 23, 2012
 */
public class Functions {

    public static ArrayList<String> LoadCommands(String cmdString, String sep) {
        ArrayList<String> commands = new ArrayList<String>();
        String cmdList[] = cmdString.split(sep);
        int i = 0;
        while (i < cmdList.length) {
            commands.add(cmdList[i]);
            i++;
        }
        return commands;
    }

    /**
     *
     * Checks if a user exists in the HashMap
     *
     * @param username user that has to be checked for existance
     * @return If a user is found in the HashMap, the value is returned Else, 0
     * is returned (user not found)
     */
    public static int CheckUser(String username) {
        int userValue = 0;
        int flag = -1;
        while (userValue < Flags.usersList.size()) {
            if (Flags.usersList.get(userValue).userName.equals(username)) {
                flag = userValue;
                break;
            }
            userValue++;
        }
        return flag;
    }

    /**
     *
     * This function checks if a user is already logged into the server
     *
     * @param user is got as a parameter to check if that user is already in
     * ipUserSession list
     * @return true if exist else returns false
     */
    public static boolean isLoggedIn(String user) {
        if (Flags.ipUserSession.containsKey(user)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     *
     * @param user's ip address (String) is returned
     * @return users IPaddress is returned
     */
    public static String getUserIPAddress(String user) {
        return Flags.ipUserSession.get(user).getInetAddress().getHostAddress();
    }

    public static String getOnlineUsers(String username) {
        String onlineUsers = "";
        int i = 0;
        while (i < Flags.loggedInUsers.size()) {
            if (!Flags.loggedInUsers.get(i).equals(username)) {
                onlineUsers = onlineUsers + (onlineUsers.equals("") ? "" : ",") + Flags.loggedInUsers.get(i);
            }
            i++;
        }
        return onlineUsers;
    }
}
