package com.tzachi.cf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.tzachi.cf.dataTypes.json.SecurityGroup;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class CloudFormationTemplateProcessor {
    private final static String SECURITY_GROUP_TYPE = "AWS::EC2::SecurityGroup";
    private final static String[] SECURITY_GROUP_RULE_TYPES = {"SecurityGroupIngress", "SecurityGroupEgress"};
    private final static Set<String> MANDATORY_SG_KEYS = new HashSet<String>(Arrays.asList(new String[] {"IpProtocol", "FromPort", "ToPort", "CidrIp"}));
    private ObjectMapper objectMapper = new ObjectMapper();
    public Map<String, List<SecurityGroup>> securityGroupRules;

    public CloudFormationTemplateProcessor(String file) throws IOException {
        JSONParser parser = new JSONParser();
        try {
            String jsonString = parser.parse(new FileReader(file)).toString();
            JsonNode resourcesRoot = objectMapper.readTree(jsonString).get("Resources");
            this.securityGroupRules = processSecurityGroup(resourcesRoot);
        } catch (ParseException ex) {
            throw new IOException("Failed to parse file name " + file);
        }
    }

    public Map<String, List<SecurityGroup>> processSecurityGroup(JsonNode resourcesRoot) throws IOException {
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

    public List<SecurityGroup> extractRule(Map.Entry<String, JsonNode> resourceNode, String securityGroupRuleType) throws IOException {
        System.out.println("Getting rule for security group type " + securityGroupRuleType);
        JsonNode securityGroupNodes = resourceNode.getValue().findPath(securityGroupRuleType);
        List<SecurityGroup> securityGroups = new ArrayList<SecurityGroup>();
        if (! securityGroupNodes.isNull()) {
            for (JsonNode securityGroupNode: securityGroupNodes){
                JsonNode processedSecurityGroupNode = validateMandatoryFields(securityGroupNode);
                System.out.println(processedSecurityGroupNode.size());
                if (processedSecurityGroupNode.size() == 0) {
                    System.out.println("Failed to find mandatory field");
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

    private JsonNode validateMandatoryFields(JsonNode securityGroupNode) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        for (String key: MANDATORY_SG_KEYS) {
            if (securityGroupNode.has(key) && ! securityGroupNode.get(key).isNull()) {
                if (securityGroupNode.get(key) instanceof ObjectNode) {
                    String value = getObjectValue(securityGroupNode.get(key));
                }
                root.set(key, mapper.convertValue(securityGroupNode.get(key), JsonNode.class));
                continue;
            }
            return mapper.createObjectNode();
        }
        System.out.println(root.toString());
        return root;
    }

    private String getObjectValue(JsonNode node) {
        System.out.println(node.toString());
        String refValue = node.get("Ref").textValue();
        System.out.println(refValue);
        return "";
    }
}
