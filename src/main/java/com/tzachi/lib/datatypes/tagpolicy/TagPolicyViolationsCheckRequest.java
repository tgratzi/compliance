package com.tzachi.lib.datatypes.tagpolicy;


import java.util.HashMap;
import java.util.Map;

public class TagPolicyViolationsCheckRequest {
    private String type = "vm";
    private String name;
    private String os = "ubuntu14.4";
    private String image;
    private Map<String,String> tags = new HashMap<String, String>();

    public void setType(String type) {this.type = type;}

    public String getType() {return type;}

    public void setImage(String image) {this.image = image;}

    public String getImage() {return image;}

    public void setOs(String os) {this.os = os;}

    public String getOs() {return os;}

    public void setName(String name) {this.name = name;}

    public String getName() {return name;}

    public void setTags(Map<String,String> tags) {
        this.tags = tags;
    }

    public Map<String,String> getTags() {
        return tags;
    }
}
