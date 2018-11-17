package com.poc.whois;

import java.io.IOException;
import java.net.SocketException;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WhoisParserWriter {
    public static Pattern whoisPattern, domainNamePattern, creationDatePattern, updateDatePattern, expiryDatePattern,
                          registrarIdPattern, registrarNamePattern, registrarWhoisPattern, registrarUrlPattern,
                          registrantNamePattern, registrantCompanyPattern, registrantAddressPattern, registrantCityPattern, registrantStatePattern, 
                          registrantZipPattern, registrantCountryPattern, registrantEmailPattern, registrantPhonePattern, registrantFaxPattern,
                          adminNamePattern, adminCompanyPattern, adminAddressPattern, adminCityPattern, adminStatePattern, 
                          adminZipPattern, adminCountryPattern, adminEmailPattern, adminPhonePattern, adminFaxPattern,
                          techNamePattern, techCompanyPattern, techAddressPattern, techCityPattern, techStatePattern, 
                          techZipPattern, techCountryPattern, techEmailPattern, techPhonePattern, techFaxPattern,
                          billNamePattern, billCompanyPattern, billAddressPattern, billCityPattern, billStatePattern, 
                          billZipPattern, billCountryPattern, billEmailPattern, billPhonePattern, billFaxPattern,
                          nsPattern, domainStatusPattern;

    public static final String WHOIS_SERVER_PATTERN = "Whois Server:\\s(.*)";    
    
    public static final String DOMAIN_NAME_PATTERN = "Domain Name:\\s(.*)";
    public static final String CREATION_DATE_PATTERN = "Creation Date:\\s(.*)";
    public static final String UPDATE_DATE_PATTERN = "Updated Date:\\s(.*)";
    public static final String EXPIRY_DATE_PATTERN = "Registrar Registration Expiration Date:\\s(.*)";
    public static final String DOMAIN_REGISTRAR_ID_PATTERN = "Registrar IANA ID:\\s(.*)";
    public static final String DOMAIN_REGISTRAR_NAME_PATTERN = "Registrar:\\s(.*)";
    public static final String DOMAIN_REGISTRAR_WHOIS_PATTERN = "Registrar WHOIS Server:\\s(.*)";
    public static final String DOMAIN_REGISTRAR_URL_PATTERN = "Registrar URL:\\s(.*)";
    public static final String REGISTRANT_NAME_PATTERN = "Registrant Name:\\s(.*)";
    public static final String REGISTRANT_COMPANY_PATTERN = "Registrant Organization:\\s(.*)";
    public static final String REGISTRANT_ADDRESS_PATTERN = "Registrant Street:\\s(.*)";
    public static final String REGISTRANT_CITY_PATTERN = "Registrant City:\\s(.*)";
    public static final String REGISTRANT_STATE_PATTERN = "Registrant State/Province:\\s(.*)";
    public static final String REGISTRANT_ZIP_PATTERN = "Registrant Postal Code:\\s(.*)";
    public static final String REGISTRANT_COUNTRY_PATTERN = "Registrant Country:\\s(.*)";
    public static final String REGISTRANT_EMAIL_PATTERN = "Registrant Email:\\s(.*)";
    public static final String REGISTRANT_PHONE_PATTERN = "Registrant Phone:\\s(.*)";
    public static final String REGISTRANT_FAX_PATTERN = "Registrant Fax:\\s(.*)";
    
    public static final String ADMIN_NAME_PATTERN = "Admin Name:\\s(.*)";
    public static final String ADMIN_COMPANY_PATTERN = "Admin Organization:\\s(.*)";
    public static final String ADMIN_ADDRESS_PATTERN = "Admin Street:\\s(.*)";
    public static final String ADMIN_CITY_PATTERN = "Admin City:\\s(.*)";
    public static final String ADMIN_STATE_PATTERN = "Admin State/Province:\\s(.*)";
    public static final String ADMIN_ZIP_PATTERN = "Admin Postal Code:\\s(.*)";
    public static final String ADMIN_COUNTRY_PATTERN = "Admin Country:\\s(.*)";
    public static final String ADMIN_EMAIL_PATTERN = "Admin Email:\\s(.*)";
    public static final String ADMIN_PHONE_PATTERN = "Admin Phone:\\s(.*)";
    public static final String ADMIN_FAX_PATTERN = "Admin Fax:\\s(.*)";
    
    public static final String TECH_NAME_PATTERN = "Tech Name:\\s(.*)";
    public static final String TECH_COMPANY_PATTERN = "Tech Organization:\\s(.*)";
    public static final String TECH_ADDRESS_PATTERN = "Tech Street:\\s(.*)";
    public static final String TECH_CITY_PATTERN = "Tech City:\\s(.*)";
    public static final String TECH_STATE_PATTERN = "Tech State/Province:\\s(.*)";
    public static final String TECH_ZIP_PATTERN = "Tech Postal Code:\\s(.*)";
    public static final String TECH_COUNTRY_PATTERN = "Tech Country:\\s(.*)";
    public static final String TECH_EMAIL_PATTERN = "Tech Email:\\s(.*)";
    public static final String TECH_PHONE_PATTERN = "Tech Phone:\\s(.*)";
    public static final String TECH_FAX_PATTERN = "Tech Fax:\\s(.*)";
    
    public static final String BILL_NAME_PATTERN = "Billing Name:\\s(.*)";
    public static final String BILL_COMPANY_PATTERN = "Billing Organization:\\s(.*)";
    public static final String BILL_ADDRESS_PATTERN = "Billing Street:\\s(.*)";
    public static final String BILL_CITY_PATTERN = "Billing City:\\s(.*)";
    public static final String BILL_STATE_PATTERN = "Billing State/Province:\\s(.*)";
    public static final String BILL_ZIP_PATTERN = "Billing Postal Code:\\s(.*)";
    public static final String BILL_COUNTRY_PATTERN = "Billing Country:\\s(.*)";
    public static final String BILL_EMAIL_PATTERN = "Billing Email:\\s(.*)";
    public static final String BILL_PHONE_PATTERN = "Billing Phone:\\s(.*)";
    public static final String BILL_FAX_PATTERN = "Billing Fax:\\s(.*)";
    
    public static final String NS_PATTERN = "Name Server:\\s(.*)";
    
    public static final String DOMAIN_STATUS_PATTERN = "Domain Status:\\s(.*)";
    
    private Matcher matcher;
    
    static {
        whoisPattern      = Pattern.compile(WHOIS_SERVER_PATTERN);
        domainNamePattern = Pattern.compile(DOMAIN_NAME_PATTERN);
        creationDatePattern = Pattern.compile(CREATION_DATE_PATTERN);
        updateDatePattern = Pattern.compile(UPDATE_DATE_PATTERN);
        expiryDatePattern = Pattern.compile(EXPIRY_DATE_PATTERN);
        registrarIdPattern = Pattern.compile(DOMAIN_REGISTRAR_ID_PATTERN);
        registrarNamePattern = Pattern.compile(DOMAIN_REGISTRAR_NAME_PATTERN);
        registrarWhoisPattern = Pattern.compile(DOMAIN_REGISTRAR_WHOIS_PATTERN);
        registrarUrlPattern = Pattern.compile(DOMAIN_REGISTRAR_URL_PATTERN);
        
        registrantNamePattern = Pattern.compile(REGISTRANT_NAME_PATTERN);
        registrantCompanyPattern = Pattern.compile(REGISTRANT_COMPANY_PATTERN);
        registrantAddressPattern = Pattern.compile(REGISTRANT_ADDRESS_PATTERN);
        registrantCityPattern = Pattern.compile(REGISTRANT_CITY_PATTERN);
        registrantStatePattern = Pattern.compile(REGISTRANT_STATE_PATTERN);
        registrantZipPattern = Pattern.compile(REGISTRANT_ZIP_PATTERN);
        registrantCountryPattern = Pattern.compile(REGISTRANT_COUNTRY_PATTERN);
        registrantEmailPattern = Pattern.compile(REGISTRANT_EMAIL_PATTERN);
        registrantPhonePattern = Pattern.compile(REGISTRANT_PHONE_PATTERN);
        registrantFaxPattern = Pattern.compile(REGISTRANT_FAX_PATTERN);
        
        adminNamePattern = Pattern.compile(ADMIN_NAME_PATTERN);
        adminCompanyPattern = Pattern.compile(ADMIN_COMPANY_PATTERN);
        adminAddressPattern = Pattern.compile(ADMIN_ADDRESS_PATTERN);
        adminCityPattern = Pattern.compile(ADMIN_CITY_PATTERN);
        adminStatePattern = Pattern.compile(ADMIN_STATE_PATTERN);
        adminZipPattern = Pattern.compile(ADMIN_ZIP_PATTERN);
        adminCountryPattern = Pattern.compile(ADMIN_COUNTRY_PATTERN);
        adminEmailPattern = Pattern.compile(ADMIN_EMAIL_PATTERN);
        adminPhonePattern = Pattern.compile(ADMIN_PHONE_PATTERN);
        adminFaxPattern = Pattern.compile(ADMIN_FAX_PATTERN);
        
        techNamePattern = Pattern.compile(TECH_NAME_PATTERN);
        techCompanyPattern = Pattern.compile(TECH_COMPANY_PATTERN);
        techAddressPattern = Pattern.compile(TECH_ADDRESS_PATTERN);
        techCityPattern = Pattern.compile(TECH_CITY_PATTERN);
        techStatePattern = Pattern.compile(TECH_STATE_PATTERN);
        techZipPattern = Pattern.compile(TECH_ZIP_PATTERN);
        techCountryPattern = Pattern.compile(TECH_COUNTRY_PATTERN);
        techEmailPattern = Pattern.compile(TECH_EMAIL_PATTERN);
        techPhonePattern = Pattern.compile(TECH_PHONE_PATTERN);
        techFaxPattern = Pattern.compile(TECH_FAX_PATTERN);
        
        billNamePattern = Pattern.compile(BILL_NAME_PATTERN);
        billCompanyPattern = Pattern.compile(BILL_COMPANY_PATTERN);
        billAddressPattern = Pattern.compile(BILL_ADDRESS_PATTERN);
        billCityPattern = Pattern.compile(BILL_CITY_PATTERN);
        billStatePattern = Pattern.compile(BILL_STATE_PATTERN);
        billZipPattern = Pattern.compile(BILL_ZIP_PATTERN);
        billCountryPattern = Pattern.compile(BILL_COUNTRY_PATTERN);
        billEmailPattern = Pattern.compile(BILL_EMAIL_PATTERN);
        billPhonePattern = Pattern.compile(BILL_PHONE_PATTERN);
        billFaxPattern = Pattern.compile(BILL_FAX_PATTERN);
        
        nsPattern = Pattern.compile(NS_PATTERN);
        domainStatusPattern = Pattern.compile(DOMAIN_STATUS_PATTERN);
    }
    
    private String outputFilePath;
    
    public WhoisParserWriter(String outputFilePath) {
        this.outputFilePath = outputFilePath;
    }
    
    public void writeToFile(String result, String domain, int row) throws IOException, SocketException {
        System.out.println("Writing domain: "+domain+" "+row);
        CSVWriter writer = new CSVWriter(outputFilePath);
        writer.getPrinter().print(row);
        writer.getPrinter().print(domain);
        writer.getPrinter().print(new Date());
        writer.getPrinter().print(getWhoisComponent(result, creationDatePattern));
        writer.getPrinter().print(getWhoisComponent(result, updateDatePattern));
        writer.getPrinter().print(getWhoisComponent(result, expiryDatePattern));
        writer.getPrinter().print(getWhoisComponent(result, registrarIdPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrarNamePattern));
        writer.getPrinter().print(getWhoisComponent(result, registrarWhoisPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrarUrlPattern));
        
        writer.getPrinter().print(getWhoisComponent(result, registrantNamePattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantCompanyPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantAddressPattern).replace(",", ""));
        writer.getPrinter().print(getWhoisComponent(result, registrantCityPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantStatePattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantZipPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantCountryPattern));
        writer.getPrinter().print(getWhoisComponent(result, registrantEmailPattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, registrantPhonePattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, registrantFaxPattern));
        
        writer.getPrinter().print(getWhoisComponent(result, adminNamePattern));
        writer.getPrinter().print(getWhoisComponent(result, adminCompanyPattern));
        writer.getPrinter().print(getWhoisComponent(result, adminAddressPattern));
        writer.getPrinter().print(getWhoisComponent(result, adminCityPattern));
        writer.getPrinter().print(getWhoisComponent(result, adminStatePattern));
        writer.getPrinter().print(getWhoisComponent(result, adminZipPattern));
        writer.getPrinter().print(getWhoisComponent(result, adminCountryPattern));
        writer.getPrinter().print(getWhoisComponent(result, adminEmailPattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, adminPhonePattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, adminFaxPattern));
        
        writer.getPrinter().print(getWhoisComponent(result, techNamePattern));
        writer.getPrinter().print(getWhoisComponent(result, techCompanyPattern));
        writer.getPrinter().print(getWhoisComponent(result, techAddressPattern));
        writer.getPrinter().print(getWhoisComponent(result, techCityPattern));
        writer.getPrinter().print(getWhoisComponent(result, techStatePattern));
        writer.getPrinter().print(getWhoisComponent(result, techZipPattern));
        writer.getPrinter().print(getWhoisComponent(result, techCountryPattern));
        writer.getPrinter().print(getWhoisComponent(result, techEmailPattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, techPhonePattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, techFaxPattern));
        
        writer.getPrinter().print(getWhoisComponent(result, billNamePattern));
        writer.getPrinter().print(getWhoisComponent(result, billCompanyPattern));
        writer.getPrinter().print(getWhoisComponent(result, billAddressPattern));
        writer.getPrinter().print(getWhoisComponent(result, billCityPattern));
        writer.getPrinter().print(getWhoisComponent(result, billStatePattern));
        writer.getPrinter().print(getWhoisComponent(result, billZipPattern));
        writer.getPrinter().print(getWhoisComponent(result, billCountryPattern));
        writer.getPrinter().print(getWhoisComponent(result, billEmailPattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, billPhonePattern));
        writer.getPrinter().print("'"+getWhoisComponent(result, billFaxPattern));
        
        writer.getPrinter().print(getWhoisComponent(result, nsPattern, 1));
        writer.getPrinter().print(getWhoisComponent(result, nsPattern, 2));
        writer.getPrinter().print(getWhoisComponent(result, nsPattern, 3));
        writer.getPrinter().print(getWhoisComponent(result, nsPattern, 4));
        
        writer.getPrinter().print(getWhoisComponent(result, domainStatusPattern, 1));
        writer.getPrinter().print(getWhoisComponent(result, domainStatusPattern, 2));
        writer.getPrinter().print(getWhoisComponent(result, domainStatusPattern, 3));
        writer.getPrinter().print(getWhoisComponent(result, domainStatusPattern, 4));
        
        writer.getPrinter().println();
        writer.close();
    }

    public String getWhoisComponent(String text, Pattern pattern, int ... groups) {
	String result = "";
        
        int group = 1;
        if (groups.length > 0)
            group = groups[0];

	matcher = pattern.matcher(text);
	while (matcher.find()) {
            if (group > matcher.groupCount())
                group = 1;
            result = matcher.group(group);
	}
	return result.replace(",", " ");
    }
}
