package com.networkpioneer;

import org.pcap4j.packet.Packet;

public interface BaseProtocol {
    public Packet createPacket();
    
}
