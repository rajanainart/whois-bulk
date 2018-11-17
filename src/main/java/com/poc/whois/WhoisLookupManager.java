package com.poc.whois;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.List;

import org.apache.commons.csv.CSVRecord;

public final class WhoisLookupManager {

    private ArrayList<String> domainNameList;
    private Map<String, String> tldList;
    private String tldFilePath;
    private String outputFilePath;
    private String domainFilePath;
    
    public WhoisLookupManager(String tldFilePath, String domainFilePath, String outputFilePath) throws IOException, FileNotFoundException {
        tldList        = new HashMap<String, String>();
        domainNameList = new ArrayList<String>();
        
        this.tldFilePath    = tldFilePath;
        this.domainFilePath = domainFilePath;
        this.outputFilePath = outputFilePath;
        
        CSVReader file   = new CSVReader(tldFilePath, new String[] { "TLD", "Server", "Exclude" });
        for (CSVRecord record : file.getParser().getRecords()) {
            if (record.get("Exclude").equals("0")) {
                tldList.put(record.get("TLD"), record.get("Server"));
            }
        }
        file.close();
        
        file = new CSVReader(domainFilePath, new String[] { });
        for (CSVRecord record : file.getParser().getRecords()) {
            domainNameList.add(record.get(0));
        }
        file.close();
    }
    
    public String getTldFilePath() {
        return tldFilePath;
    }
    
    public String getDomainFilePath() {
        return domainFilePath;
    }
    
    public String getOutputFilePath() {
        return outputFilePath;
    }
    
    public Map<String, String> getTldList() {
        return tldList;
    }
    
    public ArrayList<String> getDomainNameList() {
        return domainNameList;
    }
    
    public void process() throws IOException {
        ArrayList<String> ipAddresses = IPAddress.getAllIPAddresses();
        ArrayList<Thread> threads     = new ArrayList<Thread>();
        Map<String, Thread> completed = new HashMap<String, Thread>();
        int index   = 1, start, end;
        int count   = domainNameList.size() / ipAddresses.size();
        File file   = new File(outputFilePath);
        String dir  = file.getParent();
        String fileName = "";
        for (String ip : ipAddresses) {
            ArrayList<String> domains = new ArrayList<String>();
            start = (index-1)*count;
            end   = index == ipAddresses.size() ? domainNameList.size() : (index*count);
            domains.addAll(domainNameList.subList(start, end));
            fileName = Paths.get(dir, "result-"+index+".csv").toString();
            deleteFile(fileName);
            System.out.println("Starting thread: Thread-"+ip+",Range["+start+","+end+"]");
            Thread thread = new Thread(new WhoisLookup("Thread-"+ip, ip, tldList, domains, fileName));
            threads.add(thread);
            thread.start();
            index++;
        }
        
        while (true) {
            for (Thread thread : threads) {
                if (!thread.isAlive()) {
                    if (!completed.containsKey(thread.getName()))
                        completed.put(thread.getName(), thread);
                }
            }
            if (threads.size() == completed.size()) break;
        }
        deleteFile(outputFilePath);
        index = 1;
        CSVWriter writer = new CSVWriter(outputFilePath);
        writer.getPrinter().print("num,domain_name,query_time,create_date,update_date,expiry_date,domain_registrar_id,domain_registrar_name,domain_registrar_whois,domain_registrar_url,registrant_name,registrant_company,registrant_address,registrant_city,registrant_state,registrant_zip,registrant_country,registrant_email,registrant_phone,registrant_fax,administrative_name,administrative_company,administrative_address,administrative_city,administrative_state,administrative_zip,administrative_country,administrative_email,administrative_phone,administrative_fax,technical_name,technical_company,technical_address,technical_city,technical_state,technical_zip,technical_country,technical_email,technical_phone,technical_fax,billing_name,billing_company,billing_address,billing_city,billing_state,billing_zip,billing_country,billing_email,billing_phone,billing_fax,name_server_1,name_server_2,name_server_3,name_server_4,domain_status_1,domain_status_2,domain_status_3,domain_status_4");
        writer.getPrinter().println();
        for (String ip : ipAddresses) {
            fileName = Paths.get(dir, "result-"+index+".csv").toString();
            List<String> lines = Files.readAllLines(Paths.get(fileName));
            
            for (String line : lines) {
                writer.getPrinter().print(line);
                writer.getPrinter().println();
            }
            index++;
        }
        writer.close();
        
        System.out.println("All threads are complete.");
    }
    
    private void deleteFile(String filePath) {
        File file = new File(filePath);
        if (file.exists())
            file.delete();
    }
}
