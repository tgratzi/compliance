package com.tzachi;


import com.tzachi.lib.datatypes.generic.Severity;
import com.tzachi.lib.helpers.CloudFormationTemplateProcessor;
import com.tzachi.lib.helpers.BuildComplianceLog;
import com.tzachi.lib.helpers.HttpHelper;
import com.tzachi.lib.helpers.ViolationHelper;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.tzachi.lib.datatypes.generic.Attributes.PROD_ENVIRONMENT;
import static com.tzachi.lib.datatypes.generic.Attributes.TEST_ENVIRONMENT;

public class App {
    private static final transient Logger LOGGER = Logger.getLogger(App.class.getName());
    private static transient Logger instanceLogger = LOGGER;
    private static final Level LOG_LEVEL = Level.INFO;

    private static void getLog() {
        BuildComplianceLog complianceLog = new BuildComplianceLog(App.class.getName(), Level.INFO, System.out);
        instanceLogger = complianceLog.getLogger();
    }

    public static void main( String[] args ) throws IOException {
        ViolationHelper violation = new ViolationHelper();
        String severity = "critical";
        String environment = "production";
        String policyid = "";
        int severityLevel = 0;
        boolean is_processed = false;
        try {
            HttpHelper stHelper = new HttpHelper("192.168.204.161", "tzachi", "tzachi");
//            HttpHelper stHelper = new HttpHelper("192.168.1.66", "adam", "adam");
//            HttpHelper stHelper = new HttpHelper("hydra", "adam", "adam");
            Map<String, String> policyIDs = new ViolationHelper().getTagPolicies(stHelper).getPolicies();
            if (! policyIDs.isEmpty()) {
                String policyId = policyIDs.entrySet().iterator().next().getValue();
            }
            String jsonPath = ".";
//            String jsonPath = "/json-templates/another-folder";
//            String dirPath = "C:/Program Files (x86)/Jenkins/workspace/test";
            String dirPath = "C:/Program Files (x86)/Jenkins/workspace/test/json-templates/another-folder";
            if (! jsonPath.equalsIgnoreCase(".") && ! jsonPath.isEmpty()) {
                dirPath += jsonPath;
                if (! Files.isDirectory(Paths.get(dirPath))) {
                    System.out.println("Not a directory " + dirPath);
                    System.exit(1);
                }
            }
            System.out.println(dirPath);
            DirectoryStream<Path> files = Files.newDirectoryStream(Paths.get(dirPath), "*.json");
            for(Path filePath: files) {
                System.out.println("---------------------------------------------------------------------------");
                System.out.println(String.format("Running compliance check for the Cloudformation template '%s'", filePath.getFileName()));
                try {
                    CloudFormationTemplateProcessor cf = new CloudFormationTemplateProcessor(filePath.toString());
                    try {
                        cf.processCF();
                    } catch (IOException ex) {
                        System.out.println(ex.getMessage());
                        if (severity.equalsIgnoreCase("critical")) {
                            System.exit(1);
                        }
                        continue;
                    }
                    if (cf.getIsCloudformation()) {
                        is_processed = true;
                        severityLevel = violation.checkUspViolation(cf, stHelper);
                        if (environment.equalsIgnoreCase(PROD_ENVIRONMENT) && severityLevel >= Severity.getSeverityValueByName(severity.toUpperCase())) {
                            System.out.println("Exit");
                            System.exit(1);
                        }
                        if (! policyid.isEmpty()) {
                            severityLevel = violation.checkTagPolicyViolation(cf, stHelper, policyid);
                            if (environment.equalsIgnoreCase(PROD_ENVIRONMENT) && severityLevel >= Severity.getSeverityValueByName(severity.toUpperCase())) {
                                System.out.println("Exit");
                                System.exit(1);
                            }
                        } else {
                            System.out.println("Policy check TAG did not run due to missing policy ID");
                        }
                    } else {
                        System.out.println("Not a Cloudformation template");
                    }
                } catch (IOException ex) {
                    System.out.println(ex.getMessage());
                    if (severity.equalsIgnoreCase("critical")) {
                        System.out.println("Exit");
                        System.exit(1);
                    }
                }
            }
            if (is_processed) {
                System.out.println("No violations were found, GOOD TO GO");
            } else {
                System.out.println(String.format("No files were found under the directory '%s'", dirPath));
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
