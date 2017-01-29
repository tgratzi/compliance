package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by tzachi.gratziani on 28/01/2017.
 */
public class TagPolicyDetailedResponse {
    private List<TagPolicy> results = new ArrayList<TagPolicy>();
    private String errorMessage = null;
    private String status;

    public TagPolicyDetailedResponse(JSONObject node) {
        ObjectMapper mapper = new ObjectMapper();
        this.status = node.get(Elements.STATUS).toString();
        JsonNode items = mapper.convertValue(node.get(Elements.RESULT), JsonNode.class);
        for(JsonNode item: items) {
            this.results.add(new TagPolicy(item));
        }
    }

    public Map<String, String> getAllPolicyId() {
        Map<String, String> policyNameId = new HashMap<String, String>();
        for (TagPolicy result: results) {
            policyNameId.put(result.getPolicyName(), result.getPolicyId());
        }
        return policyNameId;
    }

    public List<List<String>> getTags() {
        List<List<String>> allPoliciesTags = new ArrayList<List<String>>();
        for (TagPolicy result: results) {
            allPoliciesTags.add(result.getTags());
        }
        return allPoliciesTags;
    }

    public List<List<Map<String,List<String>>>> getAllTagsValues() {
        List<List<Map<String,List<String>>>> allTagsValues = new ArrayList<List<Map<String, List<String>>>>();
        for (TagPolicy result: results) {
            allTagsValues.add(result.getTagsValues());
        }
        return allTagsValues;
    }
}
