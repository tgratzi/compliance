package com.tzachi.cf.dataTypes.xml;


import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "access_requests")
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessRequests {
    @XmlElement(name = "access_request")
    private List<AccessRequest> accessRequests = new ArrayList<AccessRequest>();

    public List<AccessRequest> getAccessRequests() {
        return accessRequests;
    }

    public void setAccessRequests(List<AccessRequest> accessRequests) {
        this.accessRequests = accessRequests;
    }
}
