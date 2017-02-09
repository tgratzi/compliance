package com.tzachi.lib.datatypes.generic;


public enum PreDefinedService {
    SSH("ssh", 22),
    TELNET("telnet", 23),
    FTP("ftp", 21),
    DNS("dns", 53),
    HTTP("http", 80),
    HTTPS("https", 443);

    private final String name;
    private final int port;

    PreDefinedService(String name, int port) {
        this.name = name;
        this.port = port;
    }

    public static String getServiceNameByPort(int port) {
        for (PreDefinedService serviceName : PreDefinedService.values()) {
            if (serviceName.getPort()==port) {
                return serviceName.getName();
            }
        }
        return String.valueOf(port);
    }

    public String getName() {
        return name;
    }

    public int getPort() {
        return port;
    }
}
