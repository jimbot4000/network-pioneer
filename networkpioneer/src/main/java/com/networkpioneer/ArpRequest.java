package com.networkpioneer;

import java.io.EOFException;
import java.net.InetAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/** 
 * Use like so:
 *    ArpRequest arp = new ArpRequest(sendHandle);
 *    Packet arpReqPacket = arp.buildPacket(
 *        (MacAddress) pcapiface.getLinkLayerAddresses().get(0), 
 *        srcAddr, 
 *        dstAddr);
 *    try {
 *        sendHandle.sendPacket(arpReqPacket);
 *    } catch (PcapNativeException | NotOpenException e1) {
 *        e1.printStackTrace();
 *    }
 *    MacAddress destMAC = arp.resolve();
 */
public class ArpRequest {

    // private InetAddress dstAddress;
    private ExecutorService pool = Executors.newSingleThreadExecutor();

    private MacAddress resolvedAddr;

    private Boolean stopSignal = false;

    private MacAddress srcMACAddress = null;
    private InetAddress srcAddress = null;
    private InetAddress dstAddress = null;

    // private ArpPacket arpRespPacket = null;

    public ArpRequest(PcapHandle sendHandle, MacAddress srcMACAddress, InetAddress srcAddress, InetAddress dstAddress) {
        // this.dstAddress = dstAddress;
        this.srcMACAddress = srcMACAddress;
        this.srcAddress = srcAddress;
        this.dstAddress = dstAddress;

        PacketTask t = new PacketTask(sendHandle, this);
        pool.execute(t);
    }

    
    /** 
     * @return Packet
     */
    public Packet buildPacket() {
        MacAddress zeroMac = MacAddress.getByName("00:00:00:00:00:00");

        ArpPacket.Builder arpBuilder = new ArpPacket.Builder();
        arpBuilder
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .operation(ArpOperation.REQUEST)
                .srcHardwareAddr(srcMACAddress)
                .srcProtocolAddr(srcAddress)
                .dstHardwareAddr(zeroMac)
                .dstProtocolAddr(dstAddress);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
        etherBuilder
                .dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
                .srcAddr(srcMACAddress)
                .type(EtherType.ARP)
                .payloadBuilder(arpBuilder)
                .paddingAtBuild(true);

        return etherBuilder.build();
    }

    
    /** 
     * @return MacAddress
     */
    public MacAddress resolve() {

        // wait until we have a resolved MAC address
        while (true) {
            synchronized(this) {
                if (this.resolvedAddr != null) {
                    break;
                }
                // wait a moment of time
                // try {
                //     TimeUnit.MILLISECONDS.wait(100);
                //     System.out.println("BBBBBBBBBBB");
                // } catch (InterruptedException e) {
                //     System.out.println("CCCCCCCCCCCC");

                //     e.printStackTrace();
                // }
            }
        }
        synchronized(stopSignal) {
            stopSignal = true;
        }

        return this.resolvedAddr;
    }

    
    /** 
     * Warning: Runs outside of main thread.
     * 
     * @param packet
     */
    // @Override
    // public void gotPacket(Packet packet) {
    //     if (packet.contains(ArpPacket.class)) {
    //         ArpPacket arp = packet.get(ArpPacket.class);

    //         if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {

    //             synchronized(this) {
    //                 // this.arpRespPacket = arp;
    //                 if (arp.getHeader().getDstProtocolAddr() == this.srcAddress) {
    //                     this.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
    //                 }
    //             }
    //         }
    //     }
    //     // System.out.println(packet);

    // }


    private static class PacketTask implements Runnable {

        private PcapHandle handle;
        private ArpRequest listener;

        public PacketTask(PcapHandle handle, ArpRequest listener) {
            this.handle = handle;
            this.listener = listener;
        }

        @Override
        public void run() {
            while (true) {
                Packet packet = null;
                try {
                    packet = handle.getNextPacketEx();
                } catch (EOFException | PcapNativeException | TimeoutException | NotOpenException e1) {
                    e1.printStackTrace();
                }

                if (packet != null) {
                    // listener.gotPacket(packet);

                    if (packet.contains(ArpPacket.class)) {
                        ArpPacket arp = packet.get(ArpPacket.class);
            
                        if (arp.getHeader().getOperation().equals(ArpOperation.REPLY)) {
            
                            synchronized(this.listener) {
                                // this.arpRespPacket = arp;
                                if (arp.getHeader().getDstProtocolAddr() == this.listener.srcAddress) {
                                    this.listener.resolvedAddr = arp.getHeader().getSrcHardwareAddr();
                                }
                            }
                        }
                    }
                }
    
                synchronized(this.listener.stopSignal) {
                    // Stop signal has been set, so exit the thread
                    if (this.listener.stopSignal == true) {
                        return;
                    }
                }
            }

        }
    }
}
