package com.tzachi.lib.helpers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.mifmif.common.regex.Generex;
import com.tzachi.lib.dataTypes.securitygroup.SecurityGroup;
import com.tzachi.lib.dataTypes.tagpolicy.TagPolicyViolationsCheckRequest;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class CloudFormationTemplateProcessor {
    private final static String SECURITY_GROUP_TYPE = "AWS::EC2::SecurityGroup";
    private final static String INSTANCE_TYPE = "AWS::EC2::Instance";
    private final static String SECURITY_GROUP_INGRESS = "SecurityGroupIngress";
    private final static String SECURITY_GROUP_EGRESS = "SecurityGroupEgress";
    private final static String CIDR_IP = "CidrIp";
    private final static String REF = "Ref";
    private final static String DEFAULT = "Default";

    private ObjectMapper objectMapper = new ObjectMapper();
    private final JsonNode jsonRoot;
    private Map<String, List<SecurityGroup>> securityGroupRules = new HashMap<String, List<SecurityGroup>>();
    private List<TagPolicyViolationsCheckRequest> instancesTags = new ArrayList<TagPolicyViolationsCheckRequest>();

    public Map<String, List<SecurityGroup>> getSecurityGroupRules() {
        return securityGroupRules;
    }

    public List<TagPolicyViolationsCheckRequest> getInstancesTags() {
        return instancesTags;
    }

    public CloudFormationTemplateProcessor(String file) throws IOException {
        JSONParser parser = new JSONParser();
        try {
            this.jsonRoot = objectMapper.readTree(parser.parse(new FileReader(file)).toString());
            JsonNode resourcesRoot = this.jsonRoot.get("Resources");
            processCF(resourcesRoot);
        } catch (ParseException ex) {
            throw new IOException("Failed to parse file name " + file);
        }

    }

    private void processCF(JsonNode resourcesRoot) throws IOException {
        System.out.println("Processing Cloudformation security group");
        Iterator<Map.Entry<String, JsonNode>> fields = resourcesRoot.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> resourceNode = fields.next();
            JsonNode typeNode = resourceNode.getValue().get("Type");
            if (typeNode != null && SECURITY_GROUP_TYPE.equals(typeNode.textValue())) {
                JsonNode securityIngressNode = resourceNode.getValue().findPath(SECURITY_GROUP_INGRESS);
                JsonNode securityEgressNode = resourceNode.getValue().findPath(SECURITY_GROUP_EGRESS);
                if (securityEgressNode.isNull() && securityIngressNode.isNull())
                    break;

                Map<String, JsonNode> securityGroupNodeTypes = new HashMap<String, JsonNode>();
                securityGroupNodeTypes.put(SECURITY_GROUP_INGRESS, securityIngressNode);
                securityGroupNodeTypes.put(SECURITY_GROUP_EGRESS, securityEgressNode);
                for (Map.Entry<String, JsonNode> securityType: securityGroupNodeTypes.entrySet()) {
                    if (! securityType.getValue().isNull()) {
                        List<SecurityGroup> rules = extractRule(securityIngressNode, securityType.getKey());
                        if (rules.isEmpty()) {
//                            this.securityGroupRules = new HashMap<String, List<SecurityGroup>>();
                            this.securityGroupRules.put(resourceNode.getKey(), rules);
                            continue;
                        }
                        this.securityGroupRules.put(resourceNode.getKey(), rules);
                    }
                }
            } else if (typeNode != null && INSTANCE_TYPE.equals(typeNode.textValue())) {
                this.instancesTags.add(getTagFromInstance(resourceNode));
            }
        }
    }

    private List<SecurityGroup> extractRule(JsonNode securityGroupNodes, String securityGroupRuleType) throws IOException {
        List<SecurityGroup> rules = new ArrayList<SecurityGroup>();
        if (! securityGroupNodes.isNull()) {
            for (JsonNode securityGroupNode: securityGroupNodes){
                JsonNode securityGroupValues = getSecurityGroupValues(securityGroupNode);
                if (securityGroupValues.size() == 0) {
                    System.out.println("Failed to process security group");
                    return (new ArrayList<SecurityGroup>());
                }
                try {
                    SecurityGroup rule = objectMapper.treeToValue(securityGroupValues, SecurityGroup.class);
                    rule.setDirection(securityGroupRuleType);
                    rules.add(rule);
                } catch(JsonProcessingException ex) {
                    throw new IOException ("Failed to parse security group, " + ex.getMessage());
                }
            }
        }
        return rules;
    }

    private JsonNode getSecurityGroupValues(JsonNode securityGroupNode) throws IOException {
        //Iterate on every value in security group to get the value
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        Iterator<Map.Entry<String, JsonNode>> items = securityGroupNode.fields();
        while (items.hasNext()) {
            Map.Entry<String, JsonNode> item = items.next();
            String key = item.getKey();
            if (key.equalsIgnoreCase("SourceSecurityGroupId"))
                key = CIDR_IP;
            JsonNode value = item.getValue();
            if (value instanceof ObjectNode) {
                value = mapper.convertValue(getValueFromObject(value, key), JsonNode.class);
                if (value.isNull()) {
                    return value;
                }
            } else if (key.equalsIgnoreCase("FromPort") || key.equalsIgnoreCase("ToPort")) {
                int intVal = Integer.parseInt(value.textValue());
                if (intVal < 0) {
                    value = mapper.convertValue(Math.abs(intVal), JsonNode.class);
                }
            }
            root.set(key, mapper.convertValue(value, JsonNode.class));
        }
        return root;
    }

    private String getValueFromObject(JsonNode node, String key) throws IOException {
        // looking first in security group type and next in parameter to find the real value
        String refValue = node.get("Ref").textValue();
        JsonNode refObject = jsonRoot.findValue(refValue);
        JsonNode nodeType = refObject.get("Type");
        if (nodeType.textValue().equalsIgnoreCase(SECURITY_GROUP_TYPE)) {
            try {
                return refObject.findValue(key).textValue();
            } catch (Exception ex) {
                if (key.equalsIgnoreCase(CIDR_IP)) {
                    return getValueFromObject(refObject.findValue("SourceSecurityGroupId"), CIDR_IP);
                }
            }
        }
        System.out.println(String.format("The key '%s' was not found in security group", key));
        // If not found in security group type try find in parameters
        String value = "";
        if (key.equalsIgnoreCase(CIDR_IP)) {
            try {
                value = getCidrIpFromParam(refObject);
            } catch (NullPointerException ex) {
                return "";
            }
        }
        return value;
    }

    private String getCidrIpFromParam(JsonNode cidrIpRefData) throws IOException{
        if (cidrIpRefData.has(DEFAULT)) {
            return cidrIpRefData.get(DEFAULT).textValue();
        }
        String regex = cidrIpRefData.get("AllowedPattern").textValue();
        regex = regex.replaceAll("\\^| $|\\n |\\$", "");
        Generex generex = new Generex(regex);
//        String secondString = generex.getMatchedString(1);
//        System.out.println(secondString);
//        Xeger generator = new Xeger(regex);
//        String result = generator.generate();
//        System.out.println(result);
        return generex.random();
    }

    private TagPolicyViolationsCheckRequest getTagFromInstance(Map.Entry<String, JsonNode> instanceNode) {
        TagPolicyViolationsCheckRequest tagPolicyViolation = new TagPolicyViolationsCheckRequest();
        tagPolicyViolation.setImage(getImageId(instanceNode.getValue()));
        tagPolicyViolation.setTags(getTags(instanceNode.getValue()));
        tagPolicyViolation.setName(instanceNode.getKey());
//        JsonNode instanceProperties = instanceNode.getValue().findPath("Properties");
//        Iterator<Map.Entry<String, JsonNode>> items = instanceProperties.fields();
//        while (items.hasNext()) {
//            Map.Entry<String, JsonNode> item = items.next();
//            String key = item.getKey();
//            JsonNode val = item.getValue();
//            if (val instanceof ObjectNode) {
//                System.out.println(val);
//                String refValue = val.get("Ref").textValue();
//                System.out.println(refValue);
//                JsonNode refObject = jsonRoot.findValue(refValue);
//                try {
//                    System.out.println(refObject.findValue("Default").textValue());
//                } catch (Exception ex) {
//                    continue;
//                }
//
//            }
//        }
        return tagPolicyViolation;
    }

    private String getImageId(JsonNode node) {
        JsonNode imageId = node.findPath("ImageId");
        if (imageId instanceof ObjectNode) {
            String refValue = imageId.get(REF).textValue();
            JsonNode refObject = jsonRoot.findValue(refValue);
            return refObject.findValue(DEFAULT).textValue();
        }
        return node.textValue();
    }

    private Map<String,String> getTags(JsonNode node) {
        Map<String, String> tagsMap = new HashMap<String, String>();
        for (JsonNode tag: node.findValue("Tags"))
            tagsMap.put(tag.get("Key").textValue(), tag.get("Value").textValue());
        return tagsMap;
    }

}
