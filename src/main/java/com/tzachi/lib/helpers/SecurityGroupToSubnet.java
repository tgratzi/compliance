package com.tzachi.lib.helpers;

import org.apache.commons.net.util.SubnetUtils;

import java.util.HashMap;
import java.util.Map;


public class SecurityGroupToSubnet {
    private static Map<String, String> sg2Ip = new HashMap<String, String>();

    static {
        sg2Ip.put("InstanceSecurityGroup", "10.0.0.10/24");
        sg2Ip.put("KibanaSecurityGroup", "10.0.0.10/24");
        sg2Ip.put("SshInnerSecurityGroup", "10.0.0.10/24");
        sg2Ip.put("SshSecurityGroup", "10.0.0.10/24");
        sg2Ip.put("CiSecurityGroup", "10.0.0.20/24");
        sg2Ip.put("LogstashInnerSecurityGroup", "10.0.0.30/24");
        sg2Ip.put("WebSecurityGroup", "10.0.0.9/32");
        sg2Ip.put("LbSecurityGroup", "11.0.0.0/24");
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
