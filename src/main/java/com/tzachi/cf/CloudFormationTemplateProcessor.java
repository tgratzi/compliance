package com.tzachi.cf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.mifmif.common.regex.Generex;
import com.tzachi.cf.dataTypes.json.SecurityGroup;
import nl.flotsam.xeger.Xeger;
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
    private final String jsonString;

    public CloudFormationTemplateProcessor(String file) throws IOException {
        JSONParser parser = new JSONParser();
        try {
            this.jsonString = parser.parse(new FileReader(file)).toString();
            JsonNode resourcesRoot = objectMapper.readTree(this.jsonString).get("Resources");
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

    private JsonNode validateMandatoryFields(JsonNode securityGroupNode) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        for (String key: MANDATORY_SG_KEYS) {
            if (securityGroupNode.has(key) && ! securityGroupNode.get(key).isNull()) {
                String protocol = securityGroupNode.get(key).textValue();
                JsonNode value = securityGroupNode.get(key);
//                if ((key.equalsIgnoreCase("IpProtocol") && protocol.equalsIgnoreCase("icmp"))) {
//                    return mapper.createObjectNode();
//                }
                if (securityGroupNode.get(key) instanceof ObjectNode) {
                    value = mapper.convertValue(getObjectValue(value), JsonNode.class);
                }
                root.set(key, mapper.convertValue(value, JsonNode.class));
                continue;
            }
            return mapper.createObjectNode();
        }
        System.out.println(root.toString());
        return root;
    }

    private String getObjectValue(JsonNode node) throws IOException {
        System.out.println("Get object value");
        String refValue = node.get("Ref").textValue();
        JsonNode cidrIpRefData = objectMapper.readTree(this.jsonString).findValue(refValue);
        String regex = cidrIpRefData.get("AllowedPattern").textValue();
        regex = regex.replaceAll("\\^| $|\\n |\\$", "");
        Generex generex = new Generex(regex);
        String secondString = generex.getMatchedString(1);
        System.out.println(secondString);
        Xeger generator = new Xeger(regex);
        String result = generator.generate();
        System.out.println(result);
        return generex.random();
    }
}
