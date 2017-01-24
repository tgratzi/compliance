package com.tzachi.cf.dataTypes;


public enum Protocol {
    TCP("tcp", 6),
    UDP("udp", 17),
    ICMP("icmp", 1);

    private final String name;
    private final int protocolNum;

    Protocol(String name, int portocolNum) {
        this.name = name;
        this.protocolNum = portocolNum;
    }

    public static int getProtocolNumByValue(String value) {
        for (Protocol protocol : Protocol.values()) {
            if (protocol.getName().equalsIgnoreCase(value)) {
                return protocol.getProtocolNum();
            }
        }
        throw new IllegalStateException("Unsupported protocol " + value);
    }

    public String getName() {
        return name;
    }

    public int getProtocolNum() {
        return protocolNum;
    }
}
