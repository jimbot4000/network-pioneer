package com.networkpioneer;

import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
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
        Logger logger = LoggerFactory.getLogger(App.class);
        logger.info("Welcome to the Network Pioneer");

        // PcapNetworkInterface iface = null;

        // Pcap4j comes with a convenient method for listing
        // and choosing a network interface from the terminal
        // try {
        //     // List the network devices available with a prompt
        //     iface = new NifSelector().selectNetworkInterface();
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }

        // if (iface == null) {
        //     return;
        // }

        // find the network interface which has a public gateway
        NetworkInterface iface = null;
        PcapNetworkInterface pcapiface = null;
        try (
            DatagramSocket udpSocket = new DatagramSocket()) {
                // connect to any public IP with any port (doesn't matter which)
                udpSocket.connect(InetAddress.getByAddress(new byte[]{1,1,1,1}), 0);
                // get local address of the interface which attempted this external connect
                iface = NetworkInterface.getByInetAddress(udpSocket.getLocalAddress());
                pcapiface = Pcaps.getDevByName(iface.getName());
                logger.info("Discovered {} to use as the interface", iface.getName());

                // udpSocket.close();
        } catch (SocketException | UnknownHostException | PcapNativeException e2) {
            logger.error("Could not find an interface that can connect to the Internet.");
            e2.printStackTrace();
        }


        PcapHandle handle = null;
        try {
            handle = pcapiface.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e1) {
            e1.printStackTrace();
            return;
        }

        PcapHandle sendHandle = null;
        try {
            sendHandle = pcapiface.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);
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

        try {
            // Setup BPF filter 
            handle.setFilter("icmp[icmptype] != icmp-echo", BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException | NotOpenException e1) {
            e1.printStackTrace();
        }

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

        // We now know the interface which has the default gateway, next we need to find
        // the MAC address of the default gateway.  We do this by again sending
        // out a packet and we listen for the response and extract the MAC address 
        // from that.

        String reachableTest = "example.com";
        InetAddress inet;
        try {
            inet = InetAddress.getByName(reachableTest);
        } catch (UnknownHostException e2) {
            logger.error("Could not connect to {} - is it reachable from this network?", reachableTest);
            return;
        }

        try {
            if (!inet.isReachable(iface, 64, 5000)) {
                logger.error("Could not connect to {} - is it reachable from this network?", reachableTest);
            }

        } catch (IOException e2) {
            logger.error("Could not connect to {} - is it reachable from this network?", reachableTest);
            return;
        }

        MacAddress srcMAC = null;
        for (int i = 0; i < 100; i++) {
            try {
                Packet pkt = handle.getNextPacketEx();
                System.out.println(pkt);
                // srcMAC = pkt.getHeader().
                EthernetPacket ethPkt = pkt.get(EthernetPacket.class);
                srcMAC = ethPkt.getHeader().getSrcAddr();
            } catch (EOFException | PcapNativeException | TimeoutException | NotOpenException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
    
        }

        ProtocolICMP icmp = new ProtocolICMP();
        Packet pkt;
        try {
            pkt = icmp.createPacket(
                (MacAddress)pcapiface.getLinkLayerAddresses().get(0),
                srcMAC, 
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

        handle.close();
        sendHandle.close();
    }

}
