package com.tzachi.cf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.mifmif.common.regex.Generex;
import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
import com.tzachi.cf.dataTypes.json.SecurityGroup;
import com.tzachi.st.dataTypes.TagPolicyResource;
import com.tzachi.st.dataTypes.TagPolicyViolationsCheckRequestDTO;
import nl.flotsam.xeger.Xeger;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class CloudFormationTemplateProcessor {
    private final static String SECURITY_GROUP_TYPE = "AWS::EC2::SecurityGroup";
    private final static String INSTANCE_TYPE = "AWS::EC2::Instance";
    private final static String[] SECURITY_GROUP_RULE_TYPES = {"SecurityGroupIngress", "SecurityGroupEgress"};
    private final static Set<String> MANDATORY_SG_KEYS = new HashSet<String>(Arrays.asList(new String[] {"IpProtocol", "FromPort", "ToPort", "CidrIp"}));
    private final static Set<String> MANDATORY_TAG_KEYS = new HashSet<String>(Arrays.asList(new String[] {"ImageId", "Tags"}));
    private ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, List<SecurityGroup>> securityGroupRules;
    private final JsonNode jsonRoot;
    private List<TagPolicyViolationsCheckRequestDTO> tagPolicyViolationsCheckRequestList;

    public Map<String, List<SecurityGroup>> getSecurityGroupRules() {
        return securityGroupRules;
    }

    public CloudFormationTemplateProcessor(String file) throws IOException {
        JSONParser parser = new JSONParser();
        try {
            this.jsonRoot = objectMapper.readTree(parser.parse(new FileReader(file)).toString());
            JsonNode resourcesRoot = this.jsonRoot.get("Resources");
            this.securityGroupRules = processSecurityGroup(resourcesRoot);
            this.tagPolicyViolationsCheckRequestList = processTags(resourcesRoot);
        } catch (ParseException ex) {
            throw new IOException("Failed to parse file name " + file);
        }

    }

    private Map<String, List<SecurityGroup>> processSecurityGroup(JsonNode resourcesRoot) throws IOException {
        System.out.println("Processing cloudformation security group");
        Map<String, List<SecurityGroup>> securityGroups = new HashMap();
        Iterator<Map.Entry<String, JsonNode>> fields = resourcesRoot.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> resourceNode = fields.next();
            JsonNode typeNode = resourceNode.getValue().get("Type");
            if (typeNode != null && SECURITY_GROUP_TYPE.equals(typeNode.textValue())) {
                for (String securityGroupRuleType: SECURITY_GROUP_RULE_TYPES) {
                    List<SecurityGroup> securityGroupRules = extractRule(resourceNode, securityGroupRuleType);
                    if (securityGroupRules.isEmpty()) {
                        continue;
                    }
                    securityGroups.put(resourceNode.getKey(), securityGroupRules);
                }
            }
        }
        return securityGroups;
    }

    private List<SecurityGroup> extractRule(Map.Entry<String, JsonNode> resourceNode, String securityGroupRuleType) throws IOException {
//        System.out.println("Getting rule for security group type " + securityGroupRuleType);
        JsonNode securityGroupNodes = resourceNode.getValue().findPath(securityGroupRuleType);
        List<SecurityGroup> securityGroups = new ArrayList<SecurityGroup>();
        if (! securityGroupNodes.isNull()) {
            for (JsonNode securityGroupNode: securityGroupNodes){
                JsonNode processedSecurityGroupNode = validateNode(securityGroupNode);
                if (processedSecurityGroupNode.size() == 0) {
                    System.out.println("Failed to process security group");
                    continue;
                }
                try {
                    SecurityGroup securityGroup = objectMapper.treeToValue(processedSecurityGroupNode, SecurityGroup.class);
                    securityGroup.setDirection(securityGroupRuleType);
                    securityGroups.add(securityGroup);
                } catch(JsonProcessingException ex) {
                    throw new IOException ("Failed to parse security group, " + ex.getMessage());
                }
            }
        }
        return securityGroups;
    }

    private JsonNode validateNode(JsonNode securityGroupNode) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        Iterator<Map.Entry<String, JsonNode>> items = securityGroupNode.fields();
        while (items.hasNext()) {
            Map.Entry<String, JsonNode> item = items.next();
            String key = item.getKey();
            if (key.equalsIgnoreCase("SourceSecurityGroupId"))
                key = "CidrIp";
            JsonNode value = item.getValue();
            if (value instanceof ObjectNode) {
                value = mapper.convertValue(getValueFromObject(value, key), JsonNode.class);
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
                if (key.equalsIgnoreCase("CidrIp")) {
                    return getValueFromObject(refObject.findValue("SourceSecurityGroupId"), "CidrIp");
                }
            }
        }
        System.out.println("Not found in security group");
        // If not found in security group type try find in parameters
        String value = "";
        if (key.equalsIgnoreCase("CidrIp")) {
            value = getCidrIp(refObject);
        }
        return value;
    }

    private String getCidrIp(JsonNode cidrIpRefData) throws IOException{
        if (cidrIpRefData.has("Default")) {
            return cidrIpRefData.get("Default").textValue();
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

    private List<TagPolicyViolationsCheckRequestDTO> processTags(JsonNode resourcesRoot) throws IOException {
        System.out.println("Processing cloudformation security group");
        List<TagPolicyViolationsCheckRequestDTO> tagPolicyList = new ArrayList<TagPolicyViolationsCheckRequestDTO>();
        Iterator<Map.Entry<String, JsonNode>> fields = resourcesRoot.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> resourceNode = fields.next();
            JsonNode typeNode = resourceNode.getValue().get("Type");
            if (typeNode != null && INSTANCE_TYPE.equals(typeNode.textValue())) {
                extractTag(resourceNode);
            }
        }
        return tagPolicyList;
    }

    private List<TagPolicyViolationsCheckRequestDTO> extractTag(Map.Entry<String, JsonNode> instanceNode) {
        List<TagPolicyViolationsCheckRequestDTO> tagPolicyViolations = new ArrayList<TagPolicyViolationsCheckRequestDTO>();
        TagPolicyViolationsCheckRequestDTO tagPolicyViolation = new TagPolicyViolationsCheckRequestDTO();
        tagPolicyViolation.setImage(getImageId(instanceNode.getValue()));
        tagPolicyViolation.setTagPolicyResource(getTag(instanceNode.getValue()));
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
        return tagPolicyViolations;
    }

    private String getImageId(JsonNode node) {
        JsonNode imageId = node.findPath("ImageId");
        if (imageId instanceof ObjectNode) {
            String refValue = imageId.get("Ref").textValue();
            JsonNode refObject = jsonRoot.findValue(refValue);
            return refObject.findValue("Default").textValue();
        }
        return node.textValue();
    }

    private TagPolicyResource getTag(JsonNode node) {
        TagPolicyResource tagPolicyViolation = new TagPolicyResource();
        JsonNode tagArray = node.findValue("Tags");
        for (JsonNode tag: tagArray) {
            System.out.println(tag);
        }

        return tagPolicyViolation;
    }

}
