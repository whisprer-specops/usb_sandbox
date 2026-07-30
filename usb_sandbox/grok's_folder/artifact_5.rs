import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;

public class NixieFirmwareAnalyzer extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("🔍 Analyzing nixie_flash.bin for husklyfren!");
        Program program = getCurrentProgram();
        Memory memory = program.getMemory();
        Listing listing = program.getListing();
        File reportFile = new File(getScriptArgs()[0]);
        PrintWriter writer = new PrintWriter(reportFile);

        // Set AVR architecture
        program.setLanguage(new LanguageID("AVR8:LE:32:default"), null, true);
        writer.println("Nixie Firmware Analysis Report");
        writer.println("Architecture: AVR8");

        // Find protocol headers (0xAA55)
        byte[] pattern = new byte[] {(byte) 0xAA, 0x55};
        Address found = memory.findBytes(memory.getMinAddress(), pattern, null, true, monitor);
        while (found != null) {
            println("Found protocol header 0xAA55 at: " + found);
            writer.println("Protocol Header 0xAA55 at: " + found);
            listing.createFunction("command_parser_" + found, found, null, SourceType.ANALYSIS);
            found = memory.findBytes(found.add(1), pattern, null, true, monitor);
        }

        // Find interrupt vectors
        Address resetVector = program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        listing.createFunction("reset_handler", resetVector, null, SourceType.ANALYSIS);
        writer.println("Reset Handler at: " + resetVector);

        // Find GPIO reads (button logic)
        byte[] gpio_pattern = new byte[] {(byte) 0xB3}; // IN instruction (e.g., for PINB)
        found = memory.findBytes(memory.getMinAddress(), gpio_pattern, null, true, monitor);
        while (found != null) {
            println("Found GPIO read (possible button logic) at: " + found);
            writer.println("GPIO Read at: " + found);
            listing.createFunction("gpio_handler_" + found, found, null, SourceType.ANALYSIS);
            found = memory.findBytes(found.add(1), gpio_pattern, null, true, monitor);
        }

        // Extract strings
        for (Data data : listing.getDefinedData(true)) {
            if (data.isString()) {
                String value = data.getValue().toString();
                println("Found string: " + value);
                writer.println("String: " + value);
            }
        }

        // Save report
        writer.close();
        println("✅ Analysis complete. Report saved to: " + reportFile);
    }
}