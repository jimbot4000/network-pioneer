package com.networkpioneer;

import java.io.*;
import java.net.*;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.util.NifSelector;

public class UDP {
    
    public UDP(String address, int port) throws UnknownHostException {
        var socket = this.create_socket(port);
        var inetaddress = InetAddress.getByName(address);
        
        // DatagramPacket packet = new DatagramPacket(buf, buf.length, address, 4445);
        
    }

    public DatagramSocket create_socket(int port) {
        try {
            return new DatagramSocket(port);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
    
}
