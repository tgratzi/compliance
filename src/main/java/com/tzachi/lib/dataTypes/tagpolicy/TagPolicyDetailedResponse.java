package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tzachi.lib.dataTypes.generic.Elements;
import org.json.simple.JSONObject;

import java.util.*;

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

    public Set<String> getTagsByPolicyId(String policyId) {
        Set<String> tags = new HashSet<String>();
        for (TagPolicy result: results) {
            if (result.getPolicyId().equalsIgnoreCase(policyId))
                tags = result.getTags();
        }
        return tags;
    }
}
