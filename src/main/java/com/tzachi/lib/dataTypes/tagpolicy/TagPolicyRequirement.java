package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.tzachi.lib.dataTypes.generic.Elements;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class TagPolicyRequirement {
    private String requirementName;
    private String requirementDescription;
    private String requirementType;

    public TagPolicyRequirement() {}

    public TagPolicyRequirement(JsonNode node) {
        this.requirementName = node.get(Elements.REQUIREMENT_NAME).textValue();
        this.requirementType = node.get(Elements.REQUIREMENT_TYPE).textValue();
        this.requirementDescription = node.get(Elements.REQUIREMENT_DESCRIPTION).textValue();
    }

    public String getRequirementType() {
        return requirementType;
    }

    public class MandatoryTagPolicyRequirement extends TagPolicyRequirement {
        private List<String> tags = new ArrayList<String>();

        public MandatoryTagPolicyRequirement(JsonNode node) {
            super(node);
            try {
                JsonNode tagNode = node.get(Elements.TAGS);
                for (int i = 0; i < tagNode.size(); i++)
                    this.tags.add(tagNode.get(i).textValue());
            } catch (Exception ex) {
                System.out.println("tags");
            }
        }

        public List<String> getTags() {
            return tags;
        }
    }

    public class ValidValuesTagPolicyRequirement extends TagPolicyRequirement {
        private String tag;
        private List<String> values = new ArrayList<String>();

        public ValidValuesTagPolicyRequirement(JsonNode node) {
            super(node);
            this.tag = node.get(Elements.TAG).textValue();
            try {
                JsonNode listOfVal = node.get(Elements.VALUES);
                for (int i = 0; i < listOfVal.size(); i++)
                    this.values.add(listOfVal.get(i).textValue());
            } catch (Exception ex) {
                System.out.println("value");
            }
        }

        public Map<String,List<String>> getTagsValues() {
            Map<String,List<String>> m = new HashMap<String, List<String>>();
            m.put(tag, values);
            return m;
        }
    }
}
