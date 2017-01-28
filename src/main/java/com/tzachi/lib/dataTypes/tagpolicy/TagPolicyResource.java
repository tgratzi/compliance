package com.tzachi.lib.dataTypes.tagpolicy;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Created by tzachi.gratziani on 26/01/2017.
 */
public class TagPolicyResource {
    @JsonProperty("Role")
    private String role = "webserver";

    @JsonProperty("Budget")
    private String budget = "corporate";

    @JsonProperty("Owner")
    private String owner = "Steve.Smith";

    public String getRole() {return role;}

    public String getBudget() {return budget;}

    public String getOwner() {return owner;}
}
