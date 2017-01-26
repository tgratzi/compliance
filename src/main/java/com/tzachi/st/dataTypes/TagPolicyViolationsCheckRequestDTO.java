package com.tzachi.st.dataTypes;


import com.fasterxml.jackson.databind.JsonNode;

public class TagPolicyViolationsCheckRequestDTO {
    private String type = "vm";
    private String name = null;
    private String os = null;
    private String image = null;
    private TagPolicyResource tagPolicyResource = new TagPolicyResource();

    public void setImage(String image) {
        this.image = image;
    }

    public void setTagPolicyResource(TagPolicyResource tagPolicyResource) {
        this.tagPolicyResource = tagPolicyResource;
    }
}
