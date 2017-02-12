package com.tzachi.lib.datatypes.securitypolicyviolation;


import com.fasterxml.jackson.annotation.JsonProperty;
import com.tzachi.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

public class SecurityPolicyViolationsForMultiAr {
    @JsonProperty("security_policy_violations_for_multi_ar")
    public SecurityPolicyViolationForAr securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiAr(JSONObject json) {
//        System.out.println(json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR));
        JSONObject topElement = (JSONObject) json.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR);
        JSONObject securityPolicyViolationsForArElement =  (JSONObject) topElement.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForAr(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForAr getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}
