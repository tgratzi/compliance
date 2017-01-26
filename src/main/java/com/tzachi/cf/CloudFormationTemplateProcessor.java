package com.tzachi.cf;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.mifmif.common.regex.Generex;
import com.sun.xml.internal.ws.policy.privateutil.PolicyUtils;
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
    private Map<String, List<SecurityGroup>> securityGroupRules;
    private final JsonNode jsonRoot;

    public Map<String, List<SecurityGroup>> getSecurityGroupRules() {
        return securityGroupRules;
    }

    public CloudFormationTemplateProcessor(String file) throws IOException {
        JSONParser parser = new JSONParser();
        try {
            this.jsonRoot = objectMapper.readTree(parser.parse(new FileReader(file)).toString());
            JsonNode resourcesRoot = this.jsonRoot.get("Resources");
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
                JsonNode processedSecurityGroupNode = validateNode(securityGroupNode);
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

    private JsonNode validateNode(JsonNode securityGroupNode) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode root = mapper.createObjectNode();
        Iterator<Map.Entry<String, JsonNode>> items = securityGroupNode.fields();
        while (items.hasNext()) {
            Map.Entry<String, JsonNode> item = items.next();
            String key = item.getKey();
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
            return refObject.findValue(key).textValue();
        }
        // If not found the security group type find in parameters
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
}
