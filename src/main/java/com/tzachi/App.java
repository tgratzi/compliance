package com.tzachi;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.cf.CloudFormationTemplateProcessor;
import com.tzachi.cf.JaxbAccessRequestBuilder;
import com.tzachi.cf.dataTypes.json.SecurityGroup;
import com.tzachi.cf.dataTypes.xml.AccessRequest;
import com.tzachi.common.BuildComplianceLog;
import com.tzachi.common.HttpHelper;
import com.tzachi.st.ViolationHelper;
import com.tzachi.st.dataTypes.SecurityPolicyViolationsForMultiArDTO;
import com.tzachi.st.dataTypes.TagPolicyViolationsCheckRequestDTO;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class App {
    private static final transient Logger LOGGER = Logger.getLogger(App.class.getName());
    private static transient Logger instanceLogger = LOGGER;
    private static final Level LOG_LEVEL = Level.INFO;


    private static void getLog() {
        BuildComplianceLog complianceLog = new BuildComplianceLog(App.class.getName(), Level.INFO, System.out);
        instanceLogger = complianceLog.getLogger();
    }

    private static String formatMessage(String securityGroupName, AccessRequest accessRequest, String status) {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("----------------------------------------------------------------------").append('\n');
        errorMsg.append("Status: ").append(status).append('\n');
        errorMsg.append("Security Group: ").append(securityGroupName).append('\n');
        errorMsg.append("Source: ").append(accessRequest.getSource()).append('\n');
        errorMsg.append("Destination: ").append(accessRequest.getDestination()).append('\n');
        errorMsg.append("Service: ").append(accessRequest.getService()).append('\n');
        errorMsg.append("----------------------------------------------------------------------").append('\n');
        return errorMsg.toString();
    }

    private static void checkUspViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation) throws IOException {
        Map<String, List<SecurityGroup>> securityGroupRules = cf.getSecurityGroupRules();
        if (securityGroupRules.isEmpty()) {
            throw new IOException("Could not security group was found");
        }
        for(Map.Entry<String, List<SecurityGroup>> securityGroupRule :  securityGroupRules.entrySet()) {
            JaxbAccessRequestBuilder rule = new JaxbAccessRequestBuilder(securityGroupRule);
            for (AccessRequest ar: rule.getAccessRequestList()) {
                System.out.println(ar.getService());
                String accessRequestStr = rule.accessRequestBuilder(ar);
//                    System.out.println(accessRequestStr);

                SecurityPolicyViolationsForMultiArDTO violationMultiAr = violation.checkUSPAccessRequestViolation(stHelper, accessRequestStr);
                String statusMsg;
                if (violationMultiAr.getSecurityPolicyViolationsForAr().isViolated()) {
                    statusMsg = "VIOLATION FOUND";
                    throw new IOException(formatMessage(securityGroupRule.getKey(), ar, statusMsg));
                }
                statusMsg = "No violation found";
                System.out.println(formatMessage(securityGroupRule.getKey(), ar, statusMsg));
            }
        }
        System.out.println("No violations were found, GOOD TO GO");
    }

    private static void checkTagPolicyViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        List<TagPolicyViolationsCheckRequestDTO> tagPolicyViolationList = cf.getTagPolicyViolationsCheckRequestList();
        for (TagPolicyViolationsCheckRequestDTO tagPolicyViolation: tagPolicyViolationList) {
            String jsonTagPolicyViolation = mapper.writeValueAsString(tagPolicyViolation);
//            System.out.println(jsonTagPolicyViolation);
            violation.checkTagViolation(stHelper, jsonTagPolicyViolation, "tp-101");
        }
    }

    public static void main( String[] args ) throws IOException {
        try {
            System.out.println("Hello World!");
            String filePath = "C:\\Program Files (x86)\\Jenkins\\workspace\\test\\ci_visualization.json";
            ViolationHelper violation = new ViolationHelper();
            System.out.println("Parsing Cloudformationtemplate");
//            HttpHelper stHelper = new HttpHelper("192.168.204.161", "tzachi", "tzachi");
//            HttpHelper stHelper = new HttpHelper("192.168.1.66", "adam", "adam");
            HttpHelper stHelper = new HttpHelper("hydra", "adam", "adam");
            CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath);
            checkUspViolation(cf, stHelper, violation);
            checkTagPolicyViolation(cf, stHelper, violation);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
