package com.tzachi.lib.dataTypes.tagpolicy;


import com.fasterxml.jackson.annotation.JsonProperty;

public class TagPolicyViolationsCheckRequestDTO {
    private String type = "vm";
    private String name;
    private String os = "ubuntu14.4";
    private String image;

    @JsonProperty("tags")
    private TagPolicyResource tagPolicyResource = new TagPolicyResource();

    public void setType(String type) {this.type = type;}

    public String getType() {return type;}

    public void setImage(String image) {this.image = image;}

    public String getImage() {return image;}

    public void setOs(String os) {this.os = os;}

    public String getOs() {return os;}

    public void setName(String name) {this.name = name;}

    public String getName() {return name;}

    public void setTagPolicyResource(TagPolicyResource tagPolicyResource) {
        this.tagPolicyResource = tagPolicyResource;
    }

    public TagPolicyResource getTagPolicyResource() {
        return tagPolicyResource;
    }
}
