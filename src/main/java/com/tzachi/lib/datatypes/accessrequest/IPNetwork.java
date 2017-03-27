package com.tzachi.lib.datatypes.accessrequest;

import javax.xml.bind.annotation.*;

@XmlType(name = "ip_network")
public class IPNetwork extends AccessRequestAbstract {
    @XmlElement(name = "network")
    public NetworkAbstract network;

    public IPNetwork(String ip, String mask) {
        this.setNetwork(ip, mask);
    }

    public void setNetwork(String ip, String mask) {
        RawNetworkSubnet net = new RawNetworkSubnet();
        net.setIP(ip);
        net.setMask(mask);
        this.network = net;
    }

    public String prettyPrint() {
        return network.prettyPrint();
    }
}
