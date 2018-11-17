package com.poc.whois;

import java.io.FileWriter;
import java.io.IOException;
import org.apache.commons.csv.*;

public class CSVWriter implements AutoCloseable {
    private static final String NEW_LINE_SEPARATOR = "\n";
    private CSVPrinter printer = null;
    private FileWriter writer  = null;
        
    public CSVWriter(String filePath) throws IOException {
        CSVFormat format = CSVFormat.DEFAULT.withRecordSeparator(NEW_LINE_SEPARATOR);
        writer  = new FileWriter(filePath, true);
        printer = new CSVPrinter(writer, format);
    }
    
    public void close() throws IOException {
        writer.flush();
        printer.flush();
        writer.close();
        printer.close();
    }
    
    public CSVPrinter getPrinter() {
        return printer;
    }
}
