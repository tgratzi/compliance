package com.tzachi;


import com.tzachi.cf.CloudFormationTemplateProcessor;
import com.tzachi.cf.JaxbAccessRequestBuilder;
import com.tzachi.cf.dataTypes.json.SecurityGroup;
import com.tzachi.cf.dataTypes.xml.AccessRequest;
import com.tzachi.common.BuildComplianceLog;
import com.tzachi.common.HttpHelper;
import com.tzachi.st.ViolationHelper;
import com.tzachi.st.dataTypes.SecurityPolicyViolationsForMultiArDTO;

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

    private static String formatMessage(String securityGroupName, AccessRequest accessRequest) {
        StringBuffer errorMsg = new StringBuffer();
        errorMsg.append("----------------------------------------------------------------------").append('\n');
        errorMsg.append("VIOLATION WAS FOUND").append('\n');
        errorMsg.append("Security Group: ").append(securityGroupName).append('\n');
        errorMsg.append("Source: ").append(accessRequest.getSource()).append('\n');
        errorMsg.append("Destination: ").append(accessRequest.getDestination()).append('\n');
        errorMsg.append("Service: ").append(accessRequest.getService()).append('\n');
        errorMsg.append("----------------------------------------------------------------------").append('\n');
        return errorMsg.toString();
    }

    public static void main( String[] args ) throws IOException {
        try {
            System.out.println("Hello World!");
            String filePath = "C:\\Users\\tzachi.gratziani\\Desktop\\aws-openvpn-cf.json";
            ViolationHelper violation = new ViolationHelper();
            CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath);
            for(Map.Entry<String, List<SecurityGroup>> securityGroupRule :  cf.securityGroupRules.entrySet()) {
                JaxbAccessRequestBuilder rule = new JaxbAccessRequestBuilder(securityGroupRule);
                for (AccessRequest ar: rule.getAccessRequestList()) {
                    String accessRequestStr = rule.accessRequestBuilder(ar);
                    HttpHelper stHelper = new HttpHelper("192.168.204.161", "tzachi", "tzachi");
                    SecurityPolicyViolationsForMultiArDTO violationMultiAr = violation.checkUSPAccessRequestViolation(stHelper, accessRequestStr);
                    if (violationMultiAr.getSecurityPolicyViolationsForAr().isViolated()) {
                        System.out.println(formatMessage(securityGroupRule.getKey(), ar));
                    }
                }
            }
            System.out.println("No violations were found, good to go");
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
