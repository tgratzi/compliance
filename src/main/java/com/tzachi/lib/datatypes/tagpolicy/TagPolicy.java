package com.tzachi.lib.datatypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tzachi.lib.datatypes.generic.Elements;

import java.util.*;

import static com.tzachi.lib.datatypes.generic.Attributes.MANDATORY_REQUIREMENT_TYPE;
import static com.tzachi.lib.datatypes.generic.Attributes.VALID_VALUES_REQUIREMENT_TYPE;

/**
 * Created by tzachi.gratziani on 28/01/2017.
 */
public class TagPolicy {
    private String policy_description;
    private String policyId;
    private String policyName;
    private List requirements = new ArrayList();

    public TagPolicy(JsonNode node) {
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

    public Set<String> getTags() {
        Set<String> tags = new HashSet<String>();
        for (int i=0; i<requirements.size(); i++) {
            if (((TagPolicyRequirement) requirements.get(i)).getRequirementType().equalsIgnoreCase(MANDATORY_REQUIREMENT_TYPE)) {
                List<String> tagList = ((TagPolicyRequirement.MandatoryTagPolicyRequirement) requirements.get(i)).getTags();
                for (String tag: tagList)
                    tags.add(tag);
            }
        }
        return tags;
    }

    public Map<String,List<String>> getAllTagsValues() {
        Map<String,List<String>> m = new HashMap<String, List<String>>();
        for (int i=0; i<requirements.size(); i++) {
            if (((TagPolicyRequirement) requirements.get(i)).getRequirementType().equalsIgnoreCase(VALID_VALUES_REQUIREMENT_TYPE)) {
                String tag = ((TagPolicyRequirement.ValidValuesTagPolicyRequirement) requirements.get(i)).getTag();
                List<String> values = ((TagPolicyRequirement.ValidValuesTagPolicyRequirement) requirements.get(i)).getValues();
                m.put(tag, values);
            }
        }
        return m;
    }
}
