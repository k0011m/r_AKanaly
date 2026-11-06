// Decompiles a requested function and emits the result as JSON for the MCP server.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.PrintWriter;

public class CodexDecompileFunction extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args[0];
        String target = args[1];
        Function function = findFunction(target);

        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            if (function == null) {
                out.println("{\"error\":\"function not found\",\"query\":\"" + escape(target) + "\"}");
                return;
            }

            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            String c = results.decompileCompleted() ? results.getDecompiledFunction().getC() : "";

            out.println("{");
            out.println("\"name\":\"" + escape(function.getName()) + "\",");
            out.println("\"entry\":\"" + function.getEntryPoint().toString() + "\",");
            out.println("\"signature\":\"" + escape(function.getSignature().toString()) + "\",");
            out.println("\"decompiled\":\"" + escape(c) + "\"");
            out.println("}");
            decompiler.dispose();
        }
    }

    // Accepts either a function name or an address string from the MCP call.
    private Function findFunction(String target) {
        try {
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
            Function byAddress = currentProgram.getFunctionManager().getFunctionAt(address);
            if (byAddress != null) {
                return byAddress;
            }
        } catch (Exception ignored) {
            // Fall back to a name scan when the query is not an address.
        }

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        for (Function function : functions) {
            if (function.getName().equals(target)) {
                return function;
            }
        }
        return null;
    }

    // Escapes strings before passing them back through JSON to Codex.
    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
