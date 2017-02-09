package com.tzachi.lib.datatypes.securitygroup;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;


public class SecurityGroup {
    public static final String INGRESS = "SecurityGroupIngress";
    public static final String EGRESS = "SecurityGroupEgress";

    @JsonProperty("IpProtocol")
    String protocol;

    @JsonProperty("FromPort")
    Integer fromPort;

    @JsonProperty("ToPort")
    Integer toPort;

    @JsonProperty("CidrIp")
    String cidrIP;

    @JsonIgnore
    String direction;

    public void setDirection(String direction) {
        this.direction = direction;
    }

    public String getDirection() {
        return direction;
    }

    public String getCidrIP() {
        return cidrIP;
    }

    public Integer getFromPort() {
        return fromPort;
    }

    public Integer getToPort() {
        return toPort;
    }

    public String getProtocol() {
        return protocol;
    }
}
