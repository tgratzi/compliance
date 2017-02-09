package com.tzachi.lib.datatypes.accessrequest;


import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "implicit_service")
public class ImplicitService extends AccessRequestAbstract {
    @XmlElement(name = "name")
    private String name;

    @XmlElement(name = "service")
    private Service service;

    public void setName(String name) {
        this.name = name;
    }

    public void setService(int protocol, int toPort, int fromPort) {
        Service srv = new Service();
        srv.minProtocol = protocol;
        srv.maxProtocol = protocol;
        srv.minPort = toPort;
        srv.maxPort = fromPort;
        this.service = srv;
    }

    public String prettyPrint() {
        String portProtocolStr = service.getService();
        return name + ", " + portProtocolStr;
    }
}
