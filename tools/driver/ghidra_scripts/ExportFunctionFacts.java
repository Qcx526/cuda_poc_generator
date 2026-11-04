// Export one function's facts as JSON, covering every block Ghidra knows about.
//
// An earlier version walked instructions linearly and stopped at the first `ret`,
// which silently truncated functions with several return paths. This one walks
// the function body (all address ranges) and reports what it could not decode,
// so an incomplete export says so instead of looking complete.
//
// Arguments: <rva-hex> <output-json> [expected-size-hex]
//@category cpg
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportFunctionFacts extends GhidraScript {

    private static String esc(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public void run() throws Exception {
        println("SCRIPT_START");
        String[] args = getScriptArgs();
        long rva = Long.decode(args[0]);
        String output = args[1];
        long expectedSize = (args.length > 2) ? Long.decode(args[2]) : -1;
        println("PROGRAM_OPENED " + currentProgram.getName());

        long imageBase = currentProgram.getImageBase().getOffset();
        Address address = currentProgram.getImageBase().add(rva);
        println("FUNCTION_LOOKUP " + address);

        // Containing first: across builds the same RVA can land inside a function
        // rather than on its entry.
        Function function = getFunctionContaining(address);
        if (function == null) {
            function = getFunctionAt(address);
        }
        println("FUNCTION_FOUND " + (function != null));

        if (function == null) {
            // Never fabricate a function just to have something to report.
            write(output, "{\"error\":\"not a function in this build\",\"rva\":\""
                    + Long.toHexString(rva) + "\",\"provenance\":\"ghidra_decompiler\"}");
            println("FUNCTION_ABSENT rva=" + Long.toHexString(rva));
            println("SCRIPT_END");
            return;
        }

        // Decode the entry if the import left those bytes undefined. This is a
        // bounded disassembly of one function, not a whole-binary analysis.
        if (getInstructionAt(function.getEntryPoint()) == null) {
            new DisassembleCommand(function.getEntryPoint(), null, true)
                    .applyTo(currentProgram, monitor);
            println("FUNCTION_DECODED entry=" + function.getEntryPoint());
        }

        List<String> callers = new ArrayList<>();
        ReferenceIterator refs = currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint());
        for (Reference ref : refs) {
            Function caller = getFunctionContaining(ref.getFromAddress());
            callers.add((caller == null ? "?" : caller.getName())
                    + "@" + ref.getFromAddress());
        }

        List<String> callees = new ArrayList<>();
        List<String> strings = new ArrayList<>();
        long instructions = 0;
        long coveredBytes = 0;
        int ranges = 0;
        int returns = 0;

        InstructionIterator iterator = currentProgram.getListing()
                .getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            Instruction instruction = iterator.next();
            instructions++;
            coveredBytes += instruction.getLength();
            for (Reference ref : instruction.getReferencesFrom()) {
                if (ref.getReferenceType().isCall()) {
                    Function target = getFunctionAt(ref.getToAddress());
                    callees.add((target == null ? "?" : target.getName())
                            + "@" + ref.getToAddress());
                }
                Data data = getDataAt(ref.getToAddress());
                if (data != null && data.hasStringValue()) {
                    strings.add(ref.getFromAddress() + " -> " + data.getValue());
                }
            }
            String mnemonic = instruction.getMnemonicString();
            if (mnemonic != null && mnemonic.toLowerCase().startsWith("ret")) {
                returns++;
            }
        }

        // Bytes the body covers but no instruction owns: jump tables, padding and
        // genuinely undecoded regions all land here.
        long undefinedBytes = 0;
        for (AddressRange range : function.getBody().getAddressRanges()) {
            ranges++;
            for (Address cursor = range.getMinAddress();
                    cursor.compareTo(range.getMaxAddress()) <= 0;
                    cursor = cursor.add(1)) {
                if (getInstructionContaining(cursor) == null) {
                    undefinedBytes++;
                }
            }
        }

        long bodySize = function.getBody().getNumAddresses();
        // Complete only when the body decoded cleanly and lines up with the .pdata
        // span. Anything else is reported as partial rather than rounded up.
        boolean sizeMatchesPdata = expectedSize < 0 || bodySize == expectedSize
                || coveredBytes == expectedSize;
        boolean complete = instructions > 0 && undefinedBytes == 0 && sizeMatchesPdata;
        println("WALK instructions=" + instructions + " covered=" + coveredBytes
                + " body=" + bodySize + " undefined=" + undefinedBytes
                + " ranges=" + ranges + " returns=" + returns
                + " complete=" + complete);

        String decompiled = "";
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
        if (results != null && results.decompileCompleted()) {
            decompiled = results.getDecompiledFunction().getC();
        }

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"rva\":\"").append(Long.toHexString(
                function.getEntryPoint().getOffset() - imageBase)).append("\",");
        json.append("\"name\":\"").append(esc(function.getName())).append("\",");
        json.append("\"size\":").append(coveredBytes).append(",");
        json.append("\"body_size\":").append(bodySize).append(",");
        json.append("\"pdata_size\":").append(expectedSize).append(",");
        json.append("\"instructions\":").append(instructions).append(",");
        json.append("\"basic_block_ranges\":").append(ranges).append(",");
        json.append("\"returns\":").append(returns).append(",");
        json.append("\"undefined_bytes\":").append(undefinedBytes).append(",");
        json.append("\"complete\":").append(complete).append(",");
        json.append("\"callers\":[");
        for (int i = 0; i < callers.size(); i++) {
            if (i > 0) json.append(",");
            json.append("\"").append(esc(callers.get(i))).append("\"");
        }
        json.append("],\"callees\":[");
        for (int i = 0; i < callees.size(); i++) {
            if (i > 0) json.append(",");
            json.append("\"").append(esc(callees.get(i))).append("\"");
        }
        json.append("],\"string_refs\":[");
        for (int i = 0; i < strings.size(); i++) {
            if (i > 0) json.append(",");
            json.append("\"").append(esc(strings.get(i))).append("\"");
        }
        json.append("],\"decompiled\":\"").append(esc(decompiled)).append("\",");
        json.append("\"analysis_mode\":\"headless\",");
        json.append("\"provenance\":\"ghidra_decompiler\"}");
        write(output, json.toString());
        println("SCRIPT_END");
    }

    private void write(String path, String content) throws Exception {
        try (FileWriter writer = new FileWriter(path)) {
            writer.write(content);
        }
        println("JSON_WRITTEN " + path);
    }
}
