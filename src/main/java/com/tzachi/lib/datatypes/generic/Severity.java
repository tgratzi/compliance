package com.tzachi.lib.datatypes.generic;


public enum Severity {
    CRITICAL("critical", 3),
    HIGH("high", 3),
    MEDIUM("medium", 2),
    LOW("low", 1);

    private final String sName;
    private final int num;

    Severity(String sName, int num) {
        this.sName = sName;
        this.num = num;
    }

    public static int getSeverityValueByName(String key) {
        for (Severity severity : Severity.values()) {
            if (severity.getSeverity().equalsIgnoreCase(key)) {
                return severity.getNum();
            }
        }
        throw new IllegalStateException("Unsupported protocol " + key);
    }

    public String getSeverity() {
        return sName;
    }

    public int getNum() {
        return num;
    }
}
