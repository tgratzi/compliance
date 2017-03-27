package com.tzachi.lib.datatypes.securitypolicyviolation;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

import static com.tzachi.lib.datatypes.generic.Elements.SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR;

public class SecurityPolicyViolationsForMultiAr {
    @JsonProperty("security_policy_violations_for_multi_ar")
    private SecurityPolicyViolationForAr securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiAr(JSONObject json) {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode topElement = mapper.convertValue(json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR), JsonNode.class);
        JsonNode securityPolicyViolationsForArElement =  topElement.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForAr(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForAr getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}
