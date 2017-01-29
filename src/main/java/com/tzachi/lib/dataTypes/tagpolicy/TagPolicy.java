package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.tzachi.lib.dataTypes.generic.Elements;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by tzachi.gratziani on 28/01/2017.
 */
public class TagPolicy {
    private static final String MANDATORY_REQUIREMENT_TYPE = "mandatory_tags";
    private static final String VALID_VALUES_REQUIREMENT_TYPE = "valid_values";

    private String policy_description;
    private String policyId;
    private String policyName;
    private List requirements = new ArrayList();

    public TagPolicy(JsonNode node) {
        System.out.println("tag policy");
        this.policyId = node.get(Elements.POLICY_ID).textValue();
        this.policyName = node.get(Elements.POLICY_NAME).textValue();
        this.policy_description = node.get(Elements.POLICY_DESCRIPTION).textValue();

        JsonNode requirementArray = node.get(Elements.REQUIREMENTS);
        for(int i=0; i<requirementArray.size(); i++) {
            String reqType = requirementArray.get(i).get(Elements.REQUIREMENT_TYPE).textValue();
            TagPolicyRequirement t = new TagPolicyRequirement();
            if (reqType.equalsIgnoreCase(MANDATORY_REQUIREMENT_TYPE)) {
                TagPolicyRequirement.MandatoryTagPolicyRequirement obj = t.new MandatoryTagPolicyRequirement(requirementArray.get(i));
                this.requirements.add(obj);
            } else {
                TagPolicyRequirement.ValidValuesTagPolicyRequirement obj = t.new ValidValuesTagPolicyRequirement(requirementArray.get(i));
                this.requirements.add(obj);
            }
        }
    }

    public String getPolicyId() {
        return policyId;
    }

    public String getPolicyName() {
        return policyName;
    }

    public List<String> getTags() {
        for (int i=0; i<requirements.size(); i++) {
            if (((TagPolicyRequirement) requirements.get(i)).getRequirementType().equalsIgnoreCase(MANDATORY_REQUIREMENT_TYPE)) {
                System.out.println(((TagPolicyRequirement.MandatoryTagPolicyRequirement) requirements.get(i)).getTags());
            }
        }
        return null;
    }

    public List<Map<String,List<String>>> getTagsValues() {
        List<Map<String,List<String>>> l = new ArrayList<Map<String, List<String>>>();
        for (int i=0; i<requirements.size(); i++) {
            if (((TagPolicyRequirement) requirements.get(i)).getRequirementType().equalsIgnoreCase(VALID_VALUES_REQUIREMENT_TYPE)) {
                l.add(((TagPolicyRequirement.ValidValuesTagPolicyRequirement) requirements.get(i)).getTagsValues());
            }
        }
        System.out.println(l);
        return l;
    }
}
