package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tzachi.lib.dataTypes.generic.Attributes;
import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.List;

import static com.tzachi.lib.dataTypes.generic.Attributes.VALID_VALUES_REQUIREMENT_TYPE;

/**
 * Created by tzachi.gratziani on 26/01/2017.
 */
public class TagPolicyViolation {
    private String policyId;
    private String requirementSeverity;
    private String requirementType;
    private String requirementName;
    private String policyName;
    private String violationMessage;
    private Object violationAttributes;

    public TagPolicyViolation(JsonNode node) {
        this.policyId = node.get(Elements.POLICY_ID).textValue();
        this.requirementSeverity = node.get(Elements.REQUIREMENT_SEVERITY).textValue();
        this.requirementType = node.get(Elements.REQUIREMENT_TYPE).textValue();
        this.requirementName = node.get(Elements.POLICY_ID).textValue();
        this.policyName = node.get(Elements.POLICY_NAME).textValue();
        this.violationMessage = node.get(Elements.VIOLATION_MESSAGE).textValue();
        if (requirementType.equalsIgnoreCase(VALID_VALUES_REQUIREMENT_TYPE)) {
            this.violationAttributes = new InvalidTagValueViolationAttributes(node.get(Elements.VIOLATION_ATTRIBUTES));
        } else {
            this.violationAttributes = new MandatoryTagMissingViolationAttributes(node.get(Elements.VIOLATION_ATTRIBUTES));
        }
    }

    public String toString() {
        StringBuffer violationStr = new StringBuffer();
        violationStr.append("Severity: " + requirementSeverity).append(", ");
        violationStr.append("Policy name: " + policyName).append(", ");
        violationStr.append(violationAttributes.toString());
        return violationStr.toString();
    }

    private class InvalidTagValueViolationAttributes {
        private String tag;
        private String invalidValue;
        private List<String> validValues = new ArrayList<String>();

        public InvalidTagValueViolationAttributes(JsonNode node) {
            this.tag = node.get(Elements.TAG).textValue();
            this.invalidValue = node.get(Elements.INVALID_VALUE).textValue();
            JsonNode valList= node.get(Elements.VALID_VALUES);
            for (int i=0; i<valList.size(); i++)
                this.validValues.add(valList.get(i).textValue());
        }

        public String toString() {
            StringBuffer violationStr = new StringBuffer();
            violationStr.append("Valid values: " + validValues.toString()).append(", ");
            violationStr.append("Invalid values: " + invalidValue).append(", ");
            violationStr.append("Tag: " + tag);
            return violationStr.toString();
        }
    }

    private class MandatoryTagMissingViolationAttributes {
        private String missingTag;

        public MandatoryTagMissingViolationAttributes(JsonNode node) {
            this.missingTag = node.get(Elements.MISSING_TAG).textValue();
        }

        public String toString() {
            StringBuffer violationStr = new StringBuffer();
            violationStr.append("Missing Tag: " + missingTag);
            return violationStr.toString();
        }
    }
}
