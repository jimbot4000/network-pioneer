package com.networkpioneer;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.util.MacAddress;

/**
 * Main
 * 
 * libpcap usage: https://www.devdungeon.com/content/packet-capturing-java-pcap4j
 * 
 * Building & running:
 * $ mvn package
 * $ java -jar target/networkpioneer-jar-with-dependencies.jar
 * 
 * IMPORTANT: This application will need root privileges to run, alternatvily
 * you can set the following on linux:
 * $ setcap cap_net_raw,cap_net_admin=eip /path/to/java
 * 
 * Technique for tracerouting:
 * https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html
 * 
 */
public class App 
{
    private static final int PORT = 6789;

    private static final String READ_TIMEOUT_KEY = App.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 30); // [ms]

    private static final String SNAPLEN_KEY = App.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    public static void main( String[] args )
    {
        PcapNetworkInterface iface = null;

        // Pcap4j comes with a convenient method for listing
        // and choosing a network interface from the terminal
        try {
            // List the network devices available with a prompt
            iface = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (iface == null) {
            return;
        }

        PcapHandle handle = null;
        try {
            handle = iface.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e1) {
            e1.printStackTrace();
            return;
        }

        PcapHandle sendHandle = null;
        try {
            sendHandle = iface.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e1) {
            e1.printStackTrace();
            return;
        }

        ExecutorService pool = Executors.newSingleThreadExecutor();
        
        // handle.setFilter(
        //     "arp and src host "
        //         + strDstIpAddress
        //         + " and dst host "
        //         + strSrcIpAddress
        //         + " and ether dst "
        //         + Pcaps.toBpfString(SRC_MAC_ADDR),
        //     BpfCompileMode.OPTIMIZE);        

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // if (packet.contains(ArpPacket.class)) {
                //   ArpPacket arp = packet.get(ArpPacket.class);
                //   if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
                //     SendArpRequest.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
                //   }
                // }
                System.out.println(packet);
            }
        };

        ListenerThread t = new ListenerThread(handle, listener);
        // pool.execute(t);


        ProtocolICMP icmp = new ProtocolICMP();
        Packet pkt;
        try {
            pkt = icmp.createPacket(
                (MacAddress)iface.getLinkLayerAddresses().get(0), 
                Inet4Address.getByName("192.168.0.20"), 
                Inet4Address.getByName("example.com"), (byte)64);
            
                icmp.sendPkt(sendHandle, pkt);
            
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        // try {
        //     new UDP("bbc.co.uk", PORT);
        // } catch (UnknownHostException e) {
        //     e.printStackTrace();
        // }
    }

}
