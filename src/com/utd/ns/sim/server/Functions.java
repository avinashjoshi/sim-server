package com.utd.ns.sim.server;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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

/**
     * Decrements long nonce by 1
     *
     * @param nonce nonce of type int
     * @return decremented nonce as String
     */
    public static String nonceFail(long nonce) {
        return (Long.toString(nonce - 1));
    }

    /**
     * Decrements String nonce by 1
     *
     * @param nonce nonce of type String
     * @return decremented nonce as String
     */
    public static String nonceFail(String nonce) {
        return (nonceFail(Long.parseLong(nonce)));
    }

    /**
     * Increments long nonce by 1
     *
     * @param nonce nonce of type int
     * @return incremented nonce as String
     */
    public static String nonceSuccess(long nonce) {
        return (Long.toString(nonce + 1));
    }

    /**
     * Increments String nonce by 1
     *
     * @param nonce nonce of type String
     * @return incremented nonce as String
     */
    public static String nonceSuccess(String nonce) {
        return (nonceSuccess(Long.parseLong(nonce)));
    }

    /**
     * Check if a string is incremented or decremented
     *
     * @param what returned nonce
     * @param toWhat nonce sent
     * @return true or false
     */
    public static boolean checkNonce(String what, long toWhat) {
        return checkNonce(Long.parseLong(what), toWhat);
    }

    /**
     * Check if a string is incremented or decremented
     *
     * @param what returned nonce
     * @param toWhat nonce sent
     * @return true or false
     */
    public static boolean checkNonce(long what, long toWhat) {
        if (what == toWhat) {
            return true;
        } else {
            return false;
        }
    }

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
     * Checks if a user exists in the HashMap (Passwd File) That is list of all
     * users
     *
     * @param username user that has to be checked for existance
     * @return If a user is found in the HashMap, the value is returned Else, 0
     * is returned (user not found)
     */
    public static int checkUser(String username) {
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
     * Get logged in users IP address
     *
     * @param user's ip address (String) is returned
     * @return users IPaddress is returned
     */
    public static String getUserIPAddress(String user) {
        return Flags.ipUserSession.get(user).getInetAddress().getHostAddress();
    }

    /**
     * Gets list of all online users from loggedInUsers String array
     *
     * @param username is the user who queries this function
     * @return Returns the string containing all online users separated by ','
     */
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

    /**
     * Validate username with regular expression
     *
     * @param username username for validation
     * @return true valid username, false invalid username
     */
    public static boolean validateUserName(final String username) {
        Pattern pattern;
        Matcher matcher;
        pattern = Pattern.compile(Flags.USERNAME_PATTERN);
        matcher = pattern.matcher(username);
        return matcher.matches();

    }
}
