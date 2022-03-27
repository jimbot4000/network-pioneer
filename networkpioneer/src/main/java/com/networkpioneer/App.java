package com.networkpioneer;

import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
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
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import org.pcap4j.util.MacAddress;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * Main
 * 
 * libpcap usage:
 * https://www.devdungeon.com/content/packet-capturing-java-pcap4j
 * 
 * Building & running:
 * $ mvn package
 * $ java -jar target/networkpioneer-jar-with-dependencies.jar
 * 
 * IMPORTANT: This application may need root privileges to run, alternatvily
 * you can set the following on linux:
 * $ setcap cap_net_raw,cap_net_admin=eip /path/to/java
 * 
 * Technique for tracerouting:
 * https://0xbharath.github.io/art-of-packet-crafting-with-scapy/network_recon/traceroute/index.html
 * 
 */
public class App {
    private static final int PORT = 6789;

    private static final String READ_TIMEOUT_KEY = App.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 30); // [ms]

    private static final String SNAPLEN_KEY = App.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    public static void main(String[] args) {
        Logger logger = LoggerFactory.getLogger(App.class);
        logger.info("Welcome to the Network Pioneer");

        String targetHost = "example.com";

        // find the network interface which has a public gateway
        NetworkInterface iface = App.discoverInterface();
        PcapNetworkInterface pcapiface;
        try {
            pcapiface = Pcaps.getDevByName(iface.getName());
        } catch (PcapNativeException e3) {
            e3.printStackTrace();
            return;
        }

        PcapHandle handle = null;
        try {
            handle = pcapiface.openLive(SNAPLEN, PromiscuousMode.NONPROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e1) {
            e1.printStackTrace();
            return;
        }

        PcapHandle sendHandle = null;
        try {
            sendHandle = pcapiface.openLive(SNAPLEN, PromiscuousMode.NONPROMISCUOUS, READ_TIMEOUT);
        } catch (PcapNativeException e1) {
            e1.printStackTrace();
            return;
        }

        ExecutorService pool = Executors.newSingleThreadExecutor();

        // handle.setFilter(
        // "arp and src host "
        // + strDstIpAddress
        // + " and dst host "
        // + strSrcIpAddress
        // + " and ether dst "
        // + Pcaps.toBpfString(SRC_MAC_ADDR),
        // BpfCompileMode.OPTIMIZE);

        // try {
        //     // Setup BPF filter
        //     handle.setFilter("icmp[icmptype] != icmp-echo", BpfCompileMode.OPTIMIZE);
        // } catch (PcapNativeException | NotOpenException e1) {
        //     e1.printStackTrace();
        // }

        PacketListener listener = new CustomPacketListener();

        ListenerThread t = new ListenerThread(handle, listener);
        // pool.execute(t);


        // We now know the interface which has the route for the target host, next we need to find
        // the MAC address of the next hop. We do this by again sending
        // out a packet and we listen for the response and extract the MAC address
        // from that.

        ArpTable arpTable = new ArpTable();
        ArrayList<ArpTable.ArpRecord> arpList = arpTable.getTable();

        InetAddress srcAddr = pcapiface.getAddresses().get(0).getAddress();

        InetAddress dstAddr;
        try {
            dstAddr = InetAddress.getByName(targetHost);
        } catch (UnknownHostException e2) {
            logger.error("Could not connect to {} - is it reachable from this network?", targetHost);
            return;
        }

        // work out the destination MAC address
        ArpRequest arp = new ArpRequest(
            sendHandle, 
            (MacAddress) pcapiface.getLinkLayerAddresses().get(0), 
            srcAddr, 
            dstAddr);
        Packet arpReqPacket = arp.buildPacket();

        SendRecv sender = new SendRecv();

        Packet recvpkt = sender.sendPacket(
            sendHandle, 
            arpReqPacket,
            new SendRecv.SendRecvCallback() {
                @Override
                public Packet onRecv(Packet pkt) {
                    if (pkt.contains(ArpPacket.class)) {
                        ArpPacket arp = pkt.get(ArpPacket.class);
            
                        if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
            
                            return pkt;
                        }
                    }

                    return null;
                }
            } 
        );
        
        // sender.sendPacket(sendHandle, arpReqPacket, new SendRecv.SendRecvCallback() {
        //     @Override
        //     public boolean onRecv(Packet pkt) {
        //         System.out.println(pkt);
        //         mypkt = pkt;
        //         return true;
        //     }

        //     @Override
        //     public void onError(Exception e) {
        //         // TODO Auto-generated method stub
                
        //     }
        // });

        try {
            sendHandle.sendPacket(arpReqPacket);
        } catch (PcapNativeException | NotOpenException e1) {
            e1.printStackTrace();
        }
        MacAddress destMAC = arp.resolve();


        //////////////////////////////////////////////

        // try {
        //     if (!dstAddr.isReachable(iface, 64, 5000)) {
        //         logger.error("Could not connect to {} - is it reachable from this network?", targetHost);
        //     }

        // } catch (IOException e2) {
        //     logger.error("Could not connect to {} - is it reachable from this network?", targetHost);
        //     return;
        // }

        // logger.info("Attempting to figure out our source IP and destination MAC...");
        // MacAddress destMAC = null;
        // InetAddress srcIP = null;
        // while (destMAC == null && srcIP == null) {
        //     try {
        //         Packet pkt = handle.getNextPacketEx();
        //         System.out.println(pkt);

        //         // source IP address
        //         IpPacket ipPacket = pkt.get(IpPacket.class);
        //         srcIP = ipPacket.getHeader().getDstAddr();

        //         // destination MAC address
        //         EthernetPacket ethPkt = pkt.get(EthernetPacket.class);
        //         destMAC = ethPkt.getHeader().getSrcAddr();
        //     } catch (EOFException | PcapNativeException | TimeoutException | NotOpenException e1) {
        //         logger.warn("Timed out waiting for response from {}", targetHost);
        //     }
        // }
        // logger.info("Found destinaiton MAC: {}", destMAC);

        ProtocolICMP icmp = new ProtocolICMP();
        Packet pkt;
        pkt = icmp.createPacket(
                (MacAddress) pcapiface.getLinkLayerAddresses().get(0),
                destMAC,
                srcAddr,
                dstAddr, 
                (byte) 64);

        icmp.sendPkt(sendHandle, pkt);


        // try {
        // new UDP("bbc.co.uk", PORT);
        // } catch (UnknownHostException e) {
        // e.printStackTrace();
        // }

        handle.close();
        sendHandle.close();
    }

    public static NetworkInterface discoverInterface() {
        return App.discoverInterface(new byte[] { 4, 2, 2, 2 }, 0);
    }

    public static NetworkInterface discoverInterface(byte[] destinationAddr, int port) {
        Logger logger = LoggerFactory.getLogger(App.class);

        // find the network interface which has a public gateway
        NetworkInterface iface = null;
        try (
            DatagramSocket udpSocket = new DatagramSocket()) {
            // connect to any public IP with any port (doesn't matter which)
            udpSocket.connect(InetAddress.getByAddress(destinationAddr), port);
            // get interface which attempted this external connect
            iface = NetworkInterface.getByInetAddress(udpSocket.getLocalAddress());
            logger.info("Discovered {} to use as the interface", iface.getName());

            return iface;

            // udpSocket.close();
        } catch (SocketException | UnknownHostException e2) {
            logger.error("Could not find an interface that can connect to the Internet.");
            e2.printStackTrace();
        }

        return null;
    }
}
