package com.networkpioneer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.StringTokenizer;

import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ArpTable {

    private static String OS = System.getProperty("os.name").toLowerCase();

    public class ArpRecord {
        InetAddress ipAddr = null;
        MacAddress macAddr = null;
        String iface = null;

        public ArpRecord(InetAddress ipAddr, MacAddress macAddr, String iface) {
            this.ipAddr = ipAddr;
            this.macAddr = macAddr;
            this.iface = iface;
        }

    }

    public ArrayList<ArpRecord> getTable() {
        // BufferedReader br = null;
        // ArrayList<String> result = new ArrayList<String>();

        // try {
        //     br = new BufferedReader(new FileReader("/proc/net/arp"));
        //     String line;
        //     while ((line = br.readLine()) != null) {
        //         // System.out.println(line);
        //         result.add(line);
        //     }
        // } catch (Exception e) {
        // } finally {
        //     try {
        //         br.close();
        //     } catch (IOException e) {

        //     }
        // }

        // return result;

        Logger logger = LoggerFactory.getLogger(ArpTable.class);

        ArrayList<ArpRecord> results = new ArrayList<ArpRecord>();

        if (isUnix() == false) {
            logger.error("OS {} is not yet supported", OS);
            return results;
        }

        Process result = null;
        try {
            result = Runtime.getRuntime().exec("arp");
        } catch (IOException e) {
            logger.error("Could not run 'arp' command.");
            return results;
        }

        BufferedReader output = new BufferedReader(new InputStreamReader(result.getInputStream()));

        while (true) {
            String thisLine = null;
            try {
                thisLine = output.readLine();
            } catch (IOException e) {
                break;
            }

            if (thisLine == null) {
                break;
            }

            if (thisLine.startsWith("Address")) {
                // skip the line starting with "Address"
                continue;
            }

            results.add(parseArpLineUnix(thisLine));
        }
        
        return results;
    }

    public static boolean isWindows() {
        return OS.contains("win");
    }
 
    public static boolean isMac() {
        return OS.contains("mac");
    }
 
    public static boolean isUnix() {
        return (OS.contains("nix") || OS.contains("nux") || OS.contains("aix"));
    }

    public ArpRecord parseArpLineUnix(String line) {

        StringTokenizer tokenizer = new StringTokenizer(line, " ");
        String ipAddrStr = tokenizer.nextToken();
        tokenizer.nextToken();
        String macAddrStr = tokenizer.nextToken();
        tokenizer.nextToken();
        String iface = tokenizer.nextToken();

        InetAddress ipAddr = null;
        MacAddress macAddr = null;

        try {
            ipAddr = InetAddress.getByName(ipAddrStr);
        } catch (UnknownHostException e) {
        }

        macAddr = MacAddress.getByName(macAddrStr);

        return new ArpRecord(ipAddr, macAddr, iface);
    }

    // public MacAddress getMAC
}
