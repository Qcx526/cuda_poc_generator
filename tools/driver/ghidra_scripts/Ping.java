// Minimal probe: does headless reach a script, and can the script see the
// program and a given address? Nothing else. Used to separate "the launcher is
// stuck" from "my analysis code is slow".
//
// Arguments: <rva-hex> <output-json>
//@category cpg
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import java.io.FileWriter;

public class Ping extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("SCRIPT_START");
        String rva = (getScriptArgs().length > 0) ? getScriptArgs()[0] : "0x0";
        String output = (getScriptArgs().length > 1) ? getScriptArgs()[1] : "";
        println("PROGRAM_OPENED " + (currentProgram == null ? "null" : currentProgram.getName()));
        Address address = currentProgram.getImageBase().add(Long.decode(rva));
        println("FUNCTION_LOOKUP " + address);
        boolean hasFunction = getFunctionAt(address) != null;
        println("FUNCTION_FOUND " + hasFunction);
        String json = "{\"program\":\"" + currentProgram.getName()
                + "\",\"image_base\":\"" + currentProgram.getImageBase()
                + "\",\"address\":\"" + address
                + "\",\"function_present\":" + hasFunction + "}";
        if (!output.isEmpty()) {
            try (FileWriter writer = new FileWriter(output)) {
                writer.write(json);
            }
            println("JSON_WRITTEN " + output);
        }
        println("SCRIPT_END");
    }
}
