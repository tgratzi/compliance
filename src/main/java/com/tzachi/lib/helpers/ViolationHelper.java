package com.tzachi.lib.helpers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.datatypes.accessrequest.AccessRequest;
import com.tzachi.lib.datatypes.generic.Severity;
import com.tzachi.lib.datatypes.securitygroup.SecurityGroup;
import com.tzachi.lib.datatypes.securitypolicyviolation.SecurityPolicyViolationsForMultiArDTO;
import com.tzachi.lib.datatypes.tagpolicy.TagPolicyDetailedResponse;
import com.tzachi.lib.datatypes.tagpolicy.TagPolicyViolation;
import com.tzachi.lib.datatypes.tagpolicy.TagPolicyViolationsCheckRequest;
import com.tzachi.lib.datatypes.tagpolicy.TagPolicyViolationsResponse;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ViolationHelper {
    private static final String USP_URL = "https://{0}/securetrack/api/violations/access_requests/sync.json?use_topology=false&ar_domain_mode=false";
    private static final String TAG_URL = "https://{0}/securetrack/api/tagpolicy/violation_check?policy_external_id=";
    private static final String POLICY_URL = "https://{0}/securetrack/api/tagpolicy/policies/";
    private static final String APPLICATION_XML = "application/xml";
    private static final String APPLICATION_JSON = "application/json";

    private ObjectMapper objectMapper = new ObjectMapper();
    private Logger logger;

    public ViolationHelper() {
        logger = Logger.getLogger(ViolationHelper.class.getName());
    }

    public ViolationHelper(Level level, OutputStream outputStream) {
        BuildComplianceLog complianceLog = new BuildComplianceLog(getClass().getName(), level, outputStream);
        this.logger = complianceLog.getLogger();
    }

    public SecurityPolicyViolationsForMultiArDTO checkUSPAccessRequestViolation(HttpHelper stHelper, String str) throws IOException{
        System.out.println("Checking USP access request violation");
        SecurityPolicyViolationsForMultiArDTO violationMultiAr = null;
        JSONObject response = stHelper.post(USP_URL, str, APPLICATION_XML);
        violationMultiAr = new SecurityPolicyViolationsForMultiArDTO(response);
//        JsonNode value = objectMapper.convertValue(response.toString(), JsonNode.class);
//        SecurityPolicyViolationsForMultiArDTO ar = objectMapper.treeToValue(value, SecurityPolicyViolationsForMultiArDTO.class);
//        System.out.print(ar);
        return violationMultiAr;
    }

    public TagPolicyViolationsResponse checkTagViolation(HttpHelper stHelper, String body, String policyId) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        System.out.print(body);
        JSONObject response = (JSONObject) stHelper.post(TAG_URL + policyId, body, APPLICATION_JSON);
        JsonNode JsonNodeResponse = mapper.convertValue(response, JsonNode.class);
        TagPolicyViolationsResponse tagPolicyViolationsResponse = new TagPolicyViolationsResponse(JsonNodeResponse);
        return tagPolicyViolationsResponse;
    }

    public TagPolicyDetailedResponse getTagPolicies(HttpHelper stHelper) throws IOException {
        JSONObject response = stHelper.get(POLICY_URL);
        TagPolicyDetailedResponse tagPolicyDetailedResponse = new TagPolicyDetailedResponse(response);
//        Map<String,String> policyNameId = tagPolicyDetailedResponse.getAllPolicyId();
        return tagPolicyDetailedResponse;
    }

    private String formatMessage(String securityGroupName, String direction, AccessRequest accessRequest, String status) {
        StringBuffer bufferMsg = new StringBuffer();
        bufferMsg.append("----------------------------------------------------------------------").append('\n');
        bufferMsg.append("Status: ").append(status).append('\n');
        bufferMsg.append("Security Group: ").append(securityGroupName).append('\n');
        bufferMsg.append("Source: ").append(accessRequest.getSource()).append('\n');
        bufferMsg.append("Destination: ").append(accessRequest.getDestination()).append('\n');
        bufferMsg.append("Service: ").append(accessRequest.getService()).append('\n');
        bufferMsg.append("Direction: ").append(direction).append('\n');
        bufferMsg.append("----------------------------------------------------------------------").append('\n');
        return bufferMsg.toString();
    }

    public Boolean checkUspViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper, ViolationHelper violation) throws IOException {
        System.out.println("Running compliance check for AWS security group");
        Map<String, List<SecurityGroup>> securityGroupRules = cf.getSecurityGroupRules();
        if (securityGroupRules.isEmpty()) {
            System.out.println("No security group found");
            return false; //If no rules in security group no traffic is allowed
        }
        for(Map.Entry<String, List<SecurityGroup>> securityGroupRule :  securityGroupRules.entrySet()) {
            if (securityGroupRule.getValue().isEmpty()) {
                System.out.println(String.format("Could not parse security group '%s'", securityGroupRule.getKey()));
                return true;
            }
            String direction = securityGroupRule.getValue().get(0).getDirection();
            JaxbAccessRequestBuilder rule = new JaxbAccessRequestBuilder(securityGroupRule);
            for (AccessRequest ar: rule.getAccessRequestList()) {
                String accessRequestStr = rule.accessRequestBuilder(ar);
                SecurityPolicyViolationsForMultiArDTO violationMultiAr = violation.checkUSPAccessRequestViolation(stHelper, accessRequestStr);
                if (violationMultiAr.getSecurityPolicyViolationsForAr().isViolated()) {
                    System.out.println(formatMessage(securityGroupRule.getKey(), direction, ar, "VIOLATION FOUND"));
                    return true;
                }
            }
        }
        System.out.println("USP compliance check for AWS security groups pass successfully");
        return false;
    }

    public int checkTagPolicyViolation(CloudFormationTemplateProcessor cf, HttpHelper stHelper,
                                                   ViolationHelper violation, String policyId) throws IOException {
        int severityLevel = 0;
        ObjectMapper mapper = new ObjectMapper();
        Map<String, TagPolicyViolationsCheckRequest> instanceTagsList = cf.getInstancesTags();
        if (instanceTagsList.isEmpty()) {
            System.out.println("No Instance TAGs were found in the Cloudformation template");
            return severityLevel;
        } else {
            StringBuffer violationMsg = new StringBuffer();
            for (Map.Entry<String, TagPolicyViolationsCheckRequest> instanceTags : instanceTagsList.entrySet()) {
                String jsonTagPolicyViolation = mapper.writeValueAsString(instanceTags.getValue());
                System.out.println(jsonTagPolicyViolation);
                TagPolicyViolationsResponse tagPolicyViolationsResponse = violation.checkTagViolation(stHelper, jsonTagPolicyViolation, policyId);
                if (tagPolicyViolationsResponse.isViolated()) {
                    for (TagPolicyViolation tagViolation: tagPolicyViolationsResponse.getViolations()) {
                        int violatedSeverity = Severity.getSeverityValueByName(tagViolation.getRequirementSeverity().toUpperCase());
                        severityLevel =  violatedSeverity > severityLevel ? violatedSeverity : severityLevel;
                        violationMsg.append("Instance Name: ").append(instanceTags.getKey()).append(", ");
                        violationMsg.append(tagViolation.toString()).append("\n");
                    }
                    System.out.print(violationMsg.toString());
                    return severityLevel;
                }
            }
            System.out.println("No instance TAG violation was found");
        }
        return severityLevel;
    }
}
