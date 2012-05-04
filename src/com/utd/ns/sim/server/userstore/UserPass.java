package com.utd.ns.sim.server.userstore;


import java.io.Serializable;

/*
 * This Object (Class) stores the username and password pair :)
 */

/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class UserPass implements Serializable {
    public String userName;
    public String passwd;
    
    public UserPass() {
        userName = "";
        passwd = "";
    }
    
    public void setUserName (String value) {
        userName = value;
    }
    
    public String getUserName () {
        return userName;
    }
    
    public void setPasswd (String value) {
        passwd = value;
    }
    
    public String getPassed () {
        return passwd;
    }
    
    public void createUser (String uname, String password) {
        userName = uname;
        passwd = password;
    }
}
