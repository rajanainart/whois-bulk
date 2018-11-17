package com.poc.whois;

public class Whois {
    public static void main(String[] args) {
        try {
            if (args.length < 3) {
                System.out.println("Required command line arguments are missing");
                System.out.println("Syntax:");
                System.out.println("Whois.jar <<TLD-csv-file-path>> <<input-domain-file-path>> <<output-file-path>>");
                return;
            }
            WhoisLookupManager manager = new WhoisLookupManager(args[0], args[1], args[2]);
            manager.process();
            System.out.println("Exiting...");
        }
        catch(Exception e) {
             System.out.println("Error in Main:\r\n"+e.getMessage());
        }
    }
}
