package com.tzachi.lib.datatypes.securitypolicyviolation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.datatypes.generic.Elements;
import org.json.simple.JSONObject;

import static com.tzachi.lib.datatypes.generic.Elements.VIOLATION;


public class SecurityPolicyViolationForAr {
    private int access_request_order;
    private Violation violations;

    public SecurityPolicyViolationForAr(JSONObject json) {
        System.out.println("Parsing security policy violation for AR");
        this.access_request_order = Integer.parseInt(json.get(Elements.ACCESS_REQUEST_ORDER).toString());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode violations = mapper.convertValue(json.get(Elements.VIOLATIONS), JsonNode.class);
        if (violations.size() == 0) {
            this.violations = null;
        } else {
            this.violations = mapper.convertValue(violations.get(VIOLATION), Violation.class);
        }
    }

    public Violation getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}
