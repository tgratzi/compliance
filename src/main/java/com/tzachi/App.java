package com.tzachi;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.helpers.CloudFormationTemplateProcessor;
import com.tzachi.lib.helpers.JaxbAccessRequestBuilder;
import com.tzachi.lib.dataTypes.securitygroup.SecurityGroup;
import com.tzachi.lib.dataTypes.accessrequest.AccessRequest;
import com.tzachi.lib.helpers.BuildComplianceLog;
import com.tzachi.lib.helpers.HttpHelper;
import com.tzachi.lib.helpers.ViolationHelper;
import com.tzachi.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiArDTO;
import com.tzachi.lib.dataTypes.tagpolicy.TagPolicyViolationsCheckRequestDTO;
import com.tzachi.lib.dataTypes.tagpolicy.TagPolicyViolationsResponseDTO;

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
        System.out.println("Compliance check for AWS security groups pass with no violation");
    }

    private static void checkTagPolicyViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        List<TagPolicyViolationsCheckRequestDTO> tagPolicyViolationList = cf.getTagPolicyViolationsCheckRequestList();
        if (tagPolicyViolationList.isEmpty()) {
            System.out.println("No Instance TAGs were found in the Cloudformation template");
        } else {
            for (TagPolicyViolationsCheckRequestDTO tagPolicyViolation : tagPolicyViolationList) {
                String jsonTagPolicyViolation = mapper.writeValueAsString(tagPolicyViolation);
                //            System.out.println(jsonTagPolicyViolation);
                TagPolicyViolationsResponseDTO tagPolicyViolationsResponse = violation.checkTagViolation(stHelper, jsonTagPolicyViolation, "tp-101");
                System.out.println(tagPolicyViolationsResponse.isViolated());
            }
        }
    }

    public static void main( String[] args ) throws IOException {
        try {
            System.out.println("Hello World!");
            String filePath = "C:\\Program Files (x86)\\Jenkins\\workspace\\test\\blue-green-init.json";
            ViolationHelper violation = new ViolationHelper();
            System.out.println(String.format("Compliance check for Cloudformation template '%s'", "blue-green-init.json"));
            HttpHelper stHelper = new HttpHelper("192.168.204.161", "tzachi", "tzachi");
//            HttpHelper stHelper = new HttpHelper("192.168.1.66", "adam", "adam");
//            HttpHelper stHelper = new HttpHelper("hydra", "adam", "adam");
            CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath);
            checkUspViolation(cf, stHelper, violation);
            checkTagPolicyViolation(cf, stHelper, violation);
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
