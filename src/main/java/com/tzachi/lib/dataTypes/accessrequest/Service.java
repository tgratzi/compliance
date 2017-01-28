package com.tzachi.lib.dataTypes.accessrequest;


import javax.xml.bind.annotation.XmlElement;

public class Service {
    @XmlElement(name = "predefined")
    public String predefined = "true";

    @XmlElement(name = "min_protocol")
    public int minProtocol;

    @XmlElement(name = "max_protocol")
    public int maxProtocol;

    @XmlElement(name = "min_port")
    public int minPort;

    @XmlElement(name = "max_port")
    public int maxPort;

    public String getService() {
        return "Protocol: " + minProtocol + ", Port: " + minPort;
    }
}
