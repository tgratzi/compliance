package com.tzachi.st.dataTypes;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.List;


public class TagPolicyViolationsResponseDTO {
    private List<TagPolicyViolationDTO> violations;
    private String errorMessage;
    private String status;

    public TagPolicyViolationsResponseDTO(JSONObject tagPolicyViolationResponse) {
        System.out.println(tagPolicyViolationResponse);
        this.status = tagPolicyViolationResponse.get(Elements.STATUS).toString();
        JSONArray violationsNode = (JSONArray) tagPolicyViolationResponse.get(Elements.VIOLATIONS);
        this.violations = violationsNode.isEmpty() ? new ArrayList<TagPolicyViolationDTO>() : getTagPolicyViolations(violationsNode);
        try {
            this.errorMessage = tagPolicyViolationResponse.get(Elements.ERROR_MESSAGE).toString();
        } catch (NullPointerException ex) {
            this.errorMessage = null;
        }
    }

    private List<TagPolicyViolationDTO> getTagPolicyViolations(JSONArray violations) {
        List<TagPolicyViolationDTO> tagPolicyViolationList = new ArrayList<TagPolicyViolationDTO>();
        for (int i=0; i<violations.size(); i++) {
            tagPolicyViolationList.add(new TagPolicyViolationDTO((JSONObject)violations.get(i)));
        }
        return tagPolicyViolationList;
    }

    public List<TagPolicyViolationDTO> getViolations() {
        return violations;
    }

    public Boolean isViolated() {
        return ! violations.isEmpty();
    }
}
