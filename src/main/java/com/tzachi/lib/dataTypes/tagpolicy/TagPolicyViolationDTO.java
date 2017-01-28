package com.tzachi.lib.dataTypes.tagpolicy;

import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

/**
 * Created by tzachi.gratziani on 26/01/2017.
 */
public class TagPolicyViolationDTO {
    private String policy_id;
    private String requirement_name;
    private String policy_name;
    private String violation_message;
    private TagPolicyViolationAttributesDTO violation_attributes;

    public TagPolicyViolationDTO(JSONObject tagPolicyViolation) {
        this.policy_id = tagPolicyViolation.get(Elements.POLICY_ID).toString();
        this.requirement_name = tagPolicyViolation.get(Elements.POLICY_ID).toString();
        this.policy_name = tagPolicyViolation.get(Elements.POLICY_NAME).toString();
        this.violation_message = tagPolicyViolation.get(Elements.VIOLATION_MESSAGE).toString();
    }
}
