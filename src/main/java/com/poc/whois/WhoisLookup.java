package com.poc.whois;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Map;
import org.apache.commons.net.whois.WhoisClient;

public class WhoisLookup implements Runnable {
    public  static final int WHO_IS_TIMEOUT = 30000;
    public  static final int RETRY_TIMEOUT  = 60000;
    private static final String QUERY_LIMIT_EXCEED = "Query limit exceeded";
    
    private ArrayList<String  > domainNameList;
    private Map<String, String> tldList;
    private WhoisParserWriter parser;
    private String threadName;
    private String ipAddress;
    
    public WhoisLookup(String threadName, String ipAddress, Map<String, String> tldList, 
                       ArrayList<String> domainNameList, String outputFilePath) {
        this.domainNameList = domainNameList;
        this.tldList        = tldList;
        this.parser         = new WhoisParserWriter(outputFilePath);
        this.threadName     = threadName;
        this.ipAddress      = ipAddress;
    }
    
    public void run() {
        getWhoisForAllDomain();
    }
    
    public String getThreadName() {
        return threadName;
    }
    
    public void getWhoisForAllDomain() {
        int row = 1;
        for (String domain : domainNameList) {
            String result = "";
            try {
                System.out.println(threadName+"-Processing domain: "+domain+" "+row);
                result = getWhois(domain);
                if (result.equals("ERROR")) {
                    System.out.println(threadName+"-Query limit exceeded, sleeping for " + RETRY_TIMEOUT/1000/60 + " min(s)");
                    Thread.sleep(RETRY_TIMEOUT);
                    result = getWhois(domain);
                }
                parser.writeToFile(result, domain, row);
            }
            catch(Exception e) {
                System.out.println(threadName+"-Error occurred while processing domain: "+domain+" "+row+
                                              " Request will be retried after " + WHO_IS_TIMEOUT/1000/60 + " min(s)");
                System.out.println(e.getMessage());
                try {
                    Thread.sleep(WHO_IS_TIMEOUT);
                    result = getWhois(domain);
                    parser.writeToFile(result, domain, row);
                }
                catch(Exception e1) {} //reject the error in retry
            }
            row++;
        }
        System.out.println(threadName+" is complete");
    }
    
    public String getWhois(String domainName) throws SocketException, IOException {
        String[] domainComponents = domainName.split("\\.");
        if (domainComponents.length == 0)
            return "";
        
        String hostName = "";
        String tldName  = domainComponents[domainComponents.length-1];
        hostName        = tldList.containsKey(tldName) ? tldList.get(tldName) : WhoisClient.DEFAULT_HOST;
        System.out.println(threadName+"-Requesting server1:"+hostName);
        StringBuilder result = new StringBuilder("");
	WhoisClient whois    = new WhoisClient();
        whois.setDefaultTimeout(WHO_IS_TIMEOUT);
        whois.connect(hostName, WhoisClient.DEFAULT_PORT, InetAddress.getByName(ipAddress), 0);
        String whoisData1 = whois.query(domainName);
        result.append(whoisData1);
        whois.disconnect();

        String whoisServerUrl = parser.getWhoisComponent(whoisData1, WhoisParserWriter.whoisPattern, 1);
        if (!whoisServerUrl.equals("")) {
            System.out.println(threadName+"-Requesting server2:"+whoisServerUrl);
            String whoisData2 = queryWithWhoisServer(domainName, whoisServerUrl);
            result.append(whoisData2);
        }
        if (result.indexOf(QUERY_LIMIT_EXCEED) != -1)
            return "ERROR";
	return result.toString();
    }

    private String queryWithWhoisServer(String domainName, String whoisServer) throws SocketException, IOException {
        String result     = "";
	WhoisClient whois = new WhoisClient();
        whois.setDefaultTimeout(WHO_IS_TIMEOUT);
        whois.connect(whoisServer, WhoisClient.DEFAULT_PORT, InetAddress.getByName(ipAddress), 0);
        result = whois.query(domainName);
        whois.disconnect();
	return result;
    }
}
