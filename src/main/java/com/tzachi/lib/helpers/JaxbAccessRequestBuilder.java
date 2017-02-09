package com.tzachi.lib.helpers;

import com.tzachi.lib.datatypes.generic.PreDefinedService;
import com.tzachi.lib.datatypes.generic.Protocol;
import com.tzachi.lib.datatypes.securitygroup.SecurityGroup;
import com.tzachi.lib.datatypes.accessrequest.*;
import org.apache.commons.net.util.SubnetUtils;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class JaxbAccessRequestBuilder {
    private List<AccessRequest> accessRequestList = new ArrayList<AccessRequest>();

    public JaxbAccessRequestBuilder() {}

    public JaxbAccessRequestBuilder(Map.Entry<String, List<SecurityGroup>> securityGroupMap) throws IOException {
        SubnetUtils sgNet = SecurityGroupToSubnet.getIP(securityGroupMap.getKey());
        for (SecurityGroup rule: securityGroupMap.getValue()) {
            AccessRequest accessRequest = new AccessRequest();
            accessRequest.useTopology = "false";
            accessRequest.order = "AR1";
            try {
                SubnetUtils network = new SubnetUtils(rule.getCidrIP());
                if (SecurityGroup.INGRESS.equalsIgnoreCase(rule.getDirection())) {
                    accessRequest.setSource(network.getInfo().getAddress(), network.getInfo().getNetmask());
                    accessRequest.setDestination(sgNet.getInfo().getAddress(), sgNet.getInfo().getNetmask());
                } else {
                    accessRequest.setSource(sgNet.getInfo().getAddress(), sgNet.getInfo().getNetmask());
                    accessRequest.setDestination(network.getInfo().getAddress(), network.getInfo().getNetmask());
                }
            } catch (IllegalArgumentException ex) {
                throw new IOException("CIDR/IP parameter is invalid, Error " + ex.getMessage());
            }
            int protocol = Protocol.getProtocolNumByValue(rule.getProtocol());
            int toPort = rule.getToPort();
            int fromPort = rule.getFromPort();
            String serviceName = PreDefinedService.getServiceNameByPort(fromPort);
            accessRequest.setService(serviceName, protocol, toPort, fromPort);
            this.accessRequestList.add(accessRequest);
        }
    }

    public List<AccessRequest> getAccessRequestList() {
        return accessRequestList;
    }

    public String accessRequestBuilder(AccessRequest accessRequest) throws IOException {
        StringWriter accessRequestStr;
        accessRequestStr = new StringWriter();
        AccessRequests accessRequests = new AccessRequests();
        List<AccessRequest> accessRequestsTmp = new ArrayList<AccessRequest>();
        accessRequestsTmp.add(accessRequest);
        accessRequests.setAccessRequests(accessRequestsTmp);
        try {
            JAXBContext context = JAXBContext.newInstance(
                    AccessRequests.class,
                    AccessRequest.class,
                    IPNetwork.class,
                    RawNetworkSubnet.class,
                    ImplicitService.class);
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            m.marshal(accessRequests, accessRequestStr);
        } catch (JAXBException e) {
            throw new IOException(e.getMessage());
        }
        return accessRequestStr.toString();
    }
}
