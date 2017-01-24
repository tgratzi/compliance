package com.tzachi.common;

import org.apache.commons.net.util.SubnetUtils;

import java.util.HashMap;
import java.util.Map;


public class SecurityGroupToSubnet {
    private static Map<String, String> sg2Ip = new HashMap<String, String>();

    static {
        sg2Ip.put("InstanceSecurityGroup", "10.0.0.10/24");
        sg2Ip.put("InstanceSecurityGroup2", "10.0.0.20/24");
        sg2Ip.put("InstanceSecurityGroup3", "10.0.0.30/24");
        sg2Ip.put("InstanceSecurityGroup4", "10.0.0.9/32");
        sg2Ip.put("InstanceSecurityGroup5", "11.0.0.0/24");
        sg2Ip.put("default", "0.0.0.0/0");
    }

    public static SubnetUtils getIP(String sgName) {
        System.out.println("Converting security group to IP " + sgName);
        String sgIP = sg2Ip.get(sgName);
        if (sgIP == null )
            return new SubnetUtils(sg2Ip.get("default"));
        return new SubnetUtils(sgIP);
    }
}
