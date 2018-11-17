package com.poc.whois;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;

public final class IPAddress {
    private static ArrayList<String> ipList = new ArrayList<String>();
    
    static {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface interface1 = (NetworkInterface)interfaces.nextElement();
                Enumeration<InetAddress> ipAddresses = interface1.getInetAddresses();
                while (ipAddresses.hasMoreElements()) {
                    Object current = ipAddresses.nextElement();
                    if (current instanceof Inet4Address) {
                        Inet4Address ip = (Inet4Address)current;
                        if (ip.isLoopbackAddress())
                            continue;
                        ipList.add(ip.getHostAddress());
                    }
                }
            }
        }
        catch(Exception e1) {
            e1.getMessage();
        }
    }
    
    public static ArrayList<String> getAllIPAddresses() {
        return ipList;
    }
    
    public static String getIPAddressByIndex(int index) {
        if (index >= ipList.size())
            return "";
        return ipList.get(index);
    }
}
