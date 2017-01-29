package com.tzachi.lib.helpers;

import com.tzachi.lib.dataTypes.securitypolicyviolation.SecurityPolicyViolationsForMultiArDTO;
import com.tzachi.lib.dataTypes.tagpolicy.TagPolicyDetailedResponse;
import com.tzachi.lib.dataTypes.tagpolicy.TagPolicyViolationsResponseDTO;
import org.json.simple.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ViolationHelper {
    private static final String USP_URL = "https://{0}/securetrack/api/violations/access_requests/sync.json?use_topology=false&ar_domain_mode=false";
    private static final String TAG_URL = "https://{0}/securetrack/api/tagpolicy/violation_check?policy_external_id=";
    private static final String POLICY_URL = "https://{0}/securetrack/api/tagpolicy/policies/";
    private static final String APPLICATION_XML = "application/xml";
    private static final String APPLICATION_JSON = "application/json";

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
        return violationMultiAr;
    }

    public TagPolicyViolationsResponseDTO checkTagViolation(HttpHelper stHelper, String body, String policyId) throws IOException {
        JSONObject response = stHelper.post(TAG_URL + policyId, body, APPLICATION_JSON);
        TagPolicyViolationsResponseDTO tagPolicyViolationsResponse = new TagPolicyViolationsResponseDTO(response);
        return tagPolicyViolationsResponse;
    }

    public Map<String,String> getTagPolicies(HttpHelper stHelper) throws IOException {
        JSONObject response = stHelper.get(POLICY_URL);
        TagPolicyDetailedResponse tagPolicyDetailedResponse = new TagPolicyDetailedResponse(response);
        Map<String,String> policyNameId = tagPolicyDetailedResponse.getAllPolicyId();
        System.out.println(policyNameId);
        System.out.println(tagPolicyDetailedResponse.getTags());
        System.out.println(tagPolicyDetailedResponse.getAllTagsValues());
        return policyNameId;
    }
}
