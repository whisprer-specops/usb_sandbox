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

        // Set AVR8 architecture
        program.setLanguage(new LanguageID("AVR8:LE:32:default"), null, true);
        writer.println("Nixie Firmware Analysis Report");
        writer.println("Architecture: AVR8");

        // Find protocol headers (0xAA55)
        byte[] protocolHeader = new byte[] {(byte) 0xAA, (byte) 0x55};
        Address found = memory.findBytes(memory.getMinAddress(), protocolHeader, null, true, monitor);
        while (found != null) {
            println("Found USB protocol header 0xAA55 at: " + found);
            writer.println("USB Protocol Header 0xAA55 at: " + found);
            listing.createFunction("command_parser_" + found, found, null, SourceType.ANALYSIS);
            found = memory.findBytes(found.add(1), protocolHeader, null, true, monitor);
        }

        // Find GPIO reads (e.g., IN rXX, PINB for buttons)
        byte[] inInstruction = new byte[] {(byte) 0xB3}; // AVR8 IN instruction opcode
        found = memory.findBytes(memory.getMinAddress(), inInstruction, null, true, monitor);
        while (found != null) {
            println("Found GPIO read (possible button logic) at: " + found);
            writer.println("GPIO Read (IN instruction) at: " + found);
            listing.createFunction("gpio_handler_" + found, found, null, SourceType.ANALYSIS);
            found = memory.findBytes(found.add(1), inInstruction, null, true, monitor);
        }

        // Find USB interrupt handlers
        Address interruptVector = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x0000);
        listing.createFunction("reset_handler", interruptVector, null, SourceType.ANALYSIS);
        writer.println("Reset Handler at: " + interruptVector);
        // USB interrupt vector (e.g., 0x001A for ATmega32U4)
        Address usbInterrupt = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x001A);
        if (memory.contains(usbInterrupt)) {
            println("Found USB interrupt handler at: " + usbInterrupt);
            writer.println("USB Interrupt Handler at: " + usbInterrupt);
            listing.createFunction("usb_interrupt_handler", usbInterrupt, null, SourceType.ANALYSIS);
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