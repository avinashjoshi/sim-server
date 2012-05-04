package com.utd.ns.sim.packet;


import java.io.Serializable;

/*
 * This class contains the structure of every packet that is sent on the
 * network.
 *
 * This class implements serializable to send and recieve packet
 *
 * There are "setter" and "getter" functions inside this class Setter is
 * setSomething(value); Getter is getSomething();
 */

/**
 *
 * @author Avinash Joshi <avinash.joshi@utdallas.edu>
 * @since April 19, 2012
 */
public class Packet implements Serializable {

    public String command;
    public int nonce;
    public String data;
    public Packet pkt;

    public Packet() {
        command = "";
        nonce = 0;
        data = "";
        pkt = null;
    }

    /*
     * Setter and Getter function for "command"
     */
    public String getCommand() {
        return command;
    }

    public void setCommand(String value) {
        command = value;
    }

    /*
     * Setter and Getter function for "nonce"
     */
    public int getNonce() {
        return nonce;
    }

    public void setNonce(int value) {
        nonce = value;
    }

    /*
     * Setter and Getter function for "data"
     */
    public String getData() {
        return data;
    }

    public void setData(String value) {
        data = value;
    }

    /*
     * Function created so that we do not have to set data manually!
     */
    public void craftPacket(String command, int nonce, String data) {
        this.command = command;
        this.data = data;
        this.nonce = nonce;
    }
    
    /*
     * Used when we have a Packet object to be passed
     * Internally calls craftPacket (command, user, nonce, data);
     */

    public void craftPacket(String command, int nonce, String data, Packet packet) {
        craftPacket(command, nonce, data);
        this.pkt = packet;
    }
}
