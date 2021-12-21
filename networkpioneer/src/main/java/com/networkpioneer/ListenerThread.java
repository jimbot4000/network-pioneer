package com.networkpioneer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;

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
            try {
                handle.loop(1, listener);
            } catch (PcapNativeException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (NotOpenException e) {
                e.printStackTrace();
            }        
        }
    }

}
