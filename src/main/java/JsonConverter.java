import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;

public class JsonConverter {

    public static void main(String[] args) throws IOException {
        ObjectMapper mapper = new ObjectMapper();

        // Read the input JSON file
        JsonNode inputJson = mapper.readTree(new File("bb-fortify-report.json"));

        // Create the root node for the output JSON
        ObjectNode outputJson = mapper.createObjectNode();
        outputJson.put("title", "Fortify Scan Results");
        outputJson.put("details", "Detailed report of vulnerabilities found during the Fortify scan.");
        outputJson.put("report_type", "SECURITY");
        outputJson.put("result", "FAIL");

        // Create the data array node
        ArrayNode dataArray = mapper.createArrayNode();

        // Calculate and add total issues
        int totalIssues = 0;
        for (JsonNode dataNode : inputJson.get("data")) {
            if (dataNode.get("type").asText().equals("NUMBER")) {
                totalIssues += dataNode.get("value").asInt();
            }
        }
        totalIssues = totalIssues/2;
        dataArray.add(createDataNode(mapper, "Total Issues", totalIssues));

        // Add critical, high, medium, and low issues
        dataArray.add(createDataNode(mapper, "Critical Issues", getIssueCount(inputJson, "Critical (SAST)")));
        dataArray.add(createDataNode(mapper, "High Issues", getIssueCount(inputJson, "High (SAST)")));
        dataArray.add(createDataNode(mapper, "Medium Issues", getIssueCount(inputJson, "Medium (SAST)")));
        dataArray.add(createDataNode(mapper, "Low Issues", getIssueCount(inputJson, "Low (SAST)")));

        // Add the data array to the output JSON
        outputJson.set("data", dataArray);

        // Write the output JSON to a file
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File("bb-fortify-report2.json"), outputJson);

        System.out.println("report JSON transformation complete. Check output.json for results.");
    }

    private static ObjectNode createDataNode(ObjectMapper mapper, String title, int value) {
        ObjectNode dataNode = mapper.createObjectNode();
        dataNode.put("title", title);
        dataNode.put("value", value);
        return dataNode;
    }

    private static int getIssueCount(JsonNode inputJson, String issueType) {
        for (JsonNode dataNode : inputJson.get("data")) {
            if (dataNode.get("title").asText().equals(issueType)) {
                return dataNode.get("value").asInt();
            }
        }
        return 0;
    }
}
