// Emits discovered functions as JSON for the MCP server.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;

public class CodexListFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs()[0];
        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            out.println("{\"functions\":[");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            boolean first = true;
            for (Function function : functions) {
                if (!first) {
                    out.println(",");
                }
                first = false;
                out.print("{\"name\":\"" + escape(function.getName()) + "\"");
                out.print(",\"entry\":\"" + function.getEntryPoint().toString() + "\"");
                out.print(",\"signature\":\"" + escape(function.getSignature().toString()) + "\"}");
            }
            out.println("]}");
        }
    }

    // Escapes strings before passing them back through JSON to Codex.
    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
