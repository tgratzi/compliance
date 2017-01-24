package com.tzachi.st.dataTypes;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;


public class ViolationDTO {
    private String severities = null;

    public ViolationDTO(JSONObject json) {
        System.out.println("Parsing single violation");
        JSONArray violation = new JSONArray();
        violation = (JSONArray) json.get(Elements.VIOLATION);
    }
}
