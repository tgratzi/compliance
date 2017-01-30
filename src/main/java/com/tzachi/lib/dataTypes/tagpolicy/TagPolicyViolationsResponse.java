package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.List;


public class TagPolicyViolationsResponse {
    private List<TagPolicyViolation> violations;
    private String errorMessage;
    private String status;

    public TagPolicyViolationsResponse(JsonNode tagPolicyViolationResponse) {
        System.out.println(tagPolicyViolationResponse);
        this.status = tagPolicyViolationResponse.get(Elements.STATUS).toString();
        JsonNode violationsNode = (JsonNode) tagPolicyViolationResponse.get(Elements.VIOLATIONS);
        System.out.println(violationsNode);
        this.violations = violationsNode == null ? new ArrayList<TagPolicyViolation>() : getTagPolicyViolations(violationsNode);
        try {
            this.errorMessage = tagPolicyViolationResponse.get(Elements.ERROR_MESSAGE).toString();
        } catch (NullPointerException ex) {
            this.errorMessage = null;
        }
    }

    private List<TagPolicyViolation> getTagPolicyViolations(JsonNode violations) {
        System.out.println("tzachi");
        List<TagPolicyViolation> tagPolicyViolationList = new ArrayList<TagPolicyViolation>();
        for (int i=0; i<violations.size(); i++) {
            System.out.println(violations.get(i));
            tagPolicyViolationList.add(new TagPolicyViolation(violations.get(i)));
        }
        return tagPolicyViolationList;
    }

    public List<TagPolicyViolation> getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return ! violations.isEmpty();
    }
}
