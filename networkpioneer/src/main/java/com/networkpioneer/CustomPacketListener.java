package com.networkpioneer;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;

public class CustomPacketListener implements PacketListener {

    @Override
    public void gotPacket(Packet packet) {
        System.out.println(packet);

        
    }
    
    
}
