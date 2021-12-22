package com.networkpioneer;

import java.net.InetAddress;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

public interface BaseProtocol {

    public Packet createPacket(MacAddress srcMAC, InetAddress srcAddr, InetAddress dstAddr, byte ttl);
    
    public Boolean sendPkt(PcapHandle sendHandle, Packet pkt);

}
