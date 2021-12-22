package com.networkpioneer;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UnknownPacket.Builder;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Code;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;

public class ProtocolICMP implements BaseProtocol {
    
    public Packet createPacket(MacAddress srcMAC, InetAddress srcAddr, InetAddress dstAddr, byte ttl) {
        
        Builder unknownb = new Builder();
        unknownb.rawData(new byte[] {(byte) 0, (byte) 1, (byte) 2, (byte) 3});
    
        IcmpV4EchoPacket.Builder echob = new IcmpV4EchoPacket.Builder();
        echob.identifier((short) 100).sequenceNumber((short) 10).payloadBuilder(unknownb);
    
        // this.type = IcmpV4Type.ECHO;
        // this.code = IcmpV4Code.NO_CODE;
        // this.checksum = (short) 0x1234;
    
        IcmpV4CommonPacket.Builder icmpBuilder = new IcmpV4CommonPacket.Builder();
        icmpBuilder.type(IcmpV4Type.ECHO).code(IcmpV4Code.NO_CODE).checksum((short) 0x1234).correctChecksumAtBuild(false).payloadBuilder(echob);        
        
        // IcmpV4EchoPacket.Builder icmpBuilder = new IcmpV4EchoPacket.Builder();
        // IcmpV4CommonPacket.Builder icmpBuilder = new IcmpV4CommonPacket.Builder();

        // icmpBuilder
        //     .type(IcmpV4Type.ECHO)
        //     .code(IcmpV4Code.NO_CODE)
        //     .correctChecksumAtBuild(true);

        // icmpBuilder.
        // icmpBuilder
        //     .

        IpV4Packet.Builder ipv4b = new IpV4Packet.Builder();
        ipv4b
            .version(IpVersion.IPV4)
            .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
            .identification((short) 100)
            .ttl(ttl)
            .protocol(IpNumber.ICMPV4)
            .srcAddr((Inet4Address)srcAddr)
            .dstAddr((Inet4Address)dstAddr)
            .payloadBuilder(icmpBuilder)
            .correctChecksumAtBuild(true)
            .correctLengthAtBuild(true);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
            .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
            .srcAddr(srcMAC)
            .type(EtherType.IPV4)
            .payloadBuilder(ipv4b)
            .paddingAtBuild(true);
        
        return etherBuilder.build();
    }

    public Boolean sendPkt(PcapHandle sendHandle, Packet pkt) {
        try {
            sendHandle.sendPacket(pkt);
            return true;
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }

        return false;
    }
}
