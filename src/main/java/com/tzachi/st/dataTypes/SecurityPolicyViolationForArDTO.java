package com.tzachi.st.dataTypes;

import org.json.simple.JSONObject;


public class SecurityPolicyViolationForArDTO {
    private int access_request_order;
    private ViolationDTO violations;

    public SecurityPolicyViolationForArDTO(JSONObject json) {
        System.out.println("Parsing security policy violation for AR");
        this.access_request_order = Integer.parseInt(json.get(Elements.ACCESS_REQUEST_ORDER).toString());
        Object violations = json.get(Elements.VIOLATIONS);
        if (violations instanceof String) {
            this.violations = null;
        } else {
            this.violations = new ViolationDTO((JSONObject) json.get(Elements.VIOLATIONS));
        }
    }

    public ViolationDTO getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return  (violations != null);
    }
}
