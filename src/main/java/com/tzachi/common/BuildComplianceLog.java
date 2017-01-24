package com.tzachi.common;

import java.io.OutputStream;
import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;


/**
 * Created by tzachi.gratziani on 20/01/2017.
 */
public class BuildComplianceLog {
    private static final String TUFIN_DOMAIN = "com.tufin";
    private final Logger logger;
    private final String className;

    public BuildComplianceLog(String cls, Level level, OutputStream out) {
        this.className = cls;
        this.logger = Logger.getLogger(TUFIN_DOMAIN + cls);
        this.logger.setLevel(level);

        StreamHandler handler = new StreamHandler(out, new SimpleFormatter());
        this.logger.addHandler(handler);
        this.logger.setUseParentHandlers(false);
        handler.flush();
    }

    public Logger getLogger() {
        return logger;
    }

    public static <T> BuildComplianceLog forClass(Class<T> sourceClass, Level level, OutputStream outputStream) {
        return new BuildComplianceLog(sourceClass.getName(), level, outputStream);
    }
}
