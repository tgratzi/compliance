package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tzachi.lib.dataTypes.generic.Attributes;
import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

import java.util.List;

import static com.tzachi.lib.dataTypes.generic.Attributes.VALID_VALUES_REQUIREMENT_TYPE;

/**
 * Created by tzachi.gratziani on 26/01/2017.
 */
public class TagPolicyViolation {
    private String policyId;
    private String requirementType;
    private String requirementName;
    private String policyName;
    private String violationMessage;
    private Object violationAttributes;

    public TagPolicyViolation(JsonNode node) {
        this.policyId = node.get(Elements.POLICY_ID).toString();
        this.requirementType = node.get(Elements.REQUIREMENT_TYPE).toString();
        this.requirementName = node.get(Elements.POLICY_ID).toString();
        this.policyName = node.get(Elements.POLICY_NAME).toString();
        this.violationMessage = node.get(Elements.VIOLATION_MESSAGE).toString();
        if (requirementType.equalsIgnoreCase(VALID_VALUES_REQUIREMENT_TYPE)) {
            this.violationAttributes = new InvalidTagValueViolationAttributes(node.get(Elements.VIOLATION_ATTRIBUTES));
        } else {
            this.violationAttributes = new MandatoryTagMissingViolationAttributes(node.get(Elements.VIOLATION_ATTRIBUTES));
        }
        System.out.println(violationAttributes);
    }

    private class InvalidTagValueViolationAttributes extends TagPolicyViolation {
        private String tag;
        private String invalidValue;
        private List<String> validValues;

        public InvalidTagValueViolationAttributes(JsonNode node) {
            super(node);
            this.tag = node.get(Elements.TAG).textValue();
            this.invalidValue = node.get(Elements.INVALID_VALUE).textValue();
            for (int i=0; i<node.get(Elements.VALID_VALUES).size(); i++) {
                this.validValues.add(node.get(Elements.VALID_VALUES).get(i).textValue());
            }
        }
    }

    private class MandatoryTagMissingViolationAttributes extends TagPolicyViolation {
        private String missingTag;

        public MandatoryTagMissingViolationAttributes(JsonNode node) {
            super(node);
            this.missingTag = node.get(Elements.MISSING_TAG).textValue();
        }
    }
}
