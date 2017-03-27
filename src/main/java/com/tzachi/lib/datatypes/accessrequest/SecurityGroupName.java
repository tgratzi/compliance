package com.tzachi.lib.datatypes.accessrequest;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


@XmlType(name = "security_group_name")
public class SecurityGroupName extends AccessRequestAbstract {
    @XmlElement(name = "security_group_name")
    public String securityGroupName;

    public SecurityGroupName(String securityGroupName) {
        this.setSecurityGroupName(securityGroupName);
    }

    public void setSecurityGroupName(String securityGroupName) {
        this.securityGroupName = securityGroupName;
    }

    public String prettyPrint() {
        return securityGroupName;
    }
}
