// Emits defined strings as JSON for the MCP server.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import java.io.PrintWriter;

public class CodexGetStrings extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args[0];
        int minLength = Integer.parseInt(args[1]);

        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            out.println("{\"strings\":[");
            DataIterator dataItems = currentProgram.getListing().getDefinedData(true);
            boolean first = true;
            for (Data data : dataItems) {
                StringDataInstance stringInstance = StringDataInstance.getStringDataInstance(data);
                if (stringInstance == null || stringInstance.getStringValue() == null) {
                    continue;
                }
                String value = stringInstance.getStringValue();
                if (value.length() < minLength) {
                    continue;
                }
                if (!first) {
                    out.println(",");
                }
                first = false;
                out.print("{\"address\":\"" + data.getAddress().toString() + "\"");
                out.print(",\"value\":\"" + escape(value) + "\"}");
            }
            out.println("]}");
        }
    }

    // Escapes strings before passing them back through JSON to Codex.
    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
