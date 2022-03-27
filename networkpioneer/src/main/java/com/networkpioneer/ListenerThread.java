package com.networkpioneer;

import java.io.EOFException;
import java.util.concurrent.TimeoutException;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

public class ListenerThread implements Runnable {
    private PcapHandle handle;
    private PacketListener listener;

    public ListenerThread(PcapHandle handle, PacketListener listener) {
        this.handle = handle;
        this.listener = listener;
    }

    @Override
    public void run() {
        while (true) {
            Packet pkt = null;
            try {
                pkt = handle.getNextPacketEx();
            } catch (TimeoutException e1) {
                continue;
            } catch (EOFException | PcapNativeException | NotOpenException e1) {
                e1.printStackTrace();
            }

            if (pkt != null) {
                listener.gotPacket(pkt);
            }
        }
    }

}
