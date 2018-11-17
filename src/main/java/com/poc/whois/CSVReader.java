package com.poc.whois;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import org.apache.commons.csv.*;

public class CSVReader implements AutoCloseable {
    private CSVParser  parser = null;
    private FileReader reader = null;
    
    public CSVReader(String filePath, String[] colMapping) throws IOException, FileNotFoundException {
        reader = new FileReader(filePath);
        CSVFormat format = null;
        
        if (colMapping.length > 0)
            format = CSVFormat.DEFAULT.withHeader(colMapping);
        else
            format = CSVFormat.DEFAULT;
        
        parser = new CSVParser(reader, format);
    }
    
    public void close() throws IOException {
        reader.close();
        parser.close();
    }
    
    public CSVParser getParser() {
        return parser;
    }
}
