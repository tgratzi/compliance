package com.tzachi.st;

import com.tzachi.common.BuildComplianceLog;
import com.tzachi.common.HttpHelper;
import com.tzachi.st.dataTypes.SecurityPolicyViolationsForMultiArDTO;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ViolationHelper {
    private Logger logger;

    public ViolationHelper() {
        logger = Logger.getLogger(ViolationHelper.class.getName());
    }

    public ViolationHelper(Level level, OutputStream outputStream) {
        BuildComplianceLog complianceLog = new BuildComplianceLog(getClass().getName(), level, outputStream);
        this.logger = complianceLog.getLogger();
    }

    public SecurityPolicyViolationsForMultiArDTO checkUSPAccessRequestViolation(HttpHelper stHelper, String str) throws IOException{
        final String uspURL = "https://{0}/securetrack/api/violations/access_requests/sync.json?use_topology=false&ar_domain_mode=false";
        System.out.println("Checking USP access request violation");
        JSONObject response = new JSONObject();
        SecurityPolicyViolationsForMultiArDTO violationMultiAr = null;
        response = stHelper.post(uspURL, str, "application/xml");
        violationMultiAr = new SecurityPolicyViolationsForMultiArDTO(response);
        return violationMultiAr;
    }

    public void checkTagViolation(HttpHelper stHelper, String body, String policyId) throws IOException {
        final String tagURL = "https://{0}/securetrack/api/tagpolicy/violation_check?policy_external_id=" + policyId;
        logger.info("Tag Violation");
        System.out.println(body);
        JSONObject response = new JSONObject();
        response = stHelper.post(tagURL, body, "application/json");
        System.out.println(response);
    }
}
