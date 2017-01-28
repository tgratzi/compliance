package com.tzachi.lib.dataTypes.securitypolicyviolation;


import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

public class SecurityPolicyViolationsForMultiArDTO {
    private SecurityPolicyViolationForArDTO securityPolicyViolationsForAr;

    public SecurityPolicyViolationsForMultiArDTO(JSONObject json) {
//        System.out.println(json.get(SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR));
        JSONObject topElement = (JSONObject) json.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_MULTI_AR);
        JSONObject securityPolicyViolationsForArElement =  (JSONObject) topElement.get(Elements.SECURITY_POLICY_VIOLATIONS_FOR_AR);
        this.securityPolicyViolationsForAr = new SecurityPolicyViolationForArDTO(securityPolicyViolationsForArElement);
    }

    public SecurityPolicyViolationForArDTO getSecurityPolicyViolationsForAr() {
        return securityPolicyViolationsForAr;
    }
}
