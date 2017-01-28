package com.tzachi.lib.dataTypes.securitypolicyviolation;

import org.json.simple.JSONObject;


public class ViolationDTO {
    private String severities = null;

    public ViolationDTO(JSONObject json) {
        JSONObject violation = new JSONObject();
//        violation = json.get(Elements.VIOLATION);
    }
}
