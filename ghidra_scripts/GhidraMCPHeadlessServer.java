// Ghidra script: start a long-lived HTTP API in analyzeHeadless.
//
// Usage (example):
//   analyzeHeadless <project_dir> <project_name> -import <binary> \
//     -scriptPath <path-to-this-dir> \
//     -postScript GhidraMCPHeadlessServer.java --bind 127.0.0.1 --port 18080
//
// This intentionally implements a "core subset" of endpoints used by the Python MCP bridge.
// The GUI plugin remains the full-featured path; this script is for process-level concurrency.

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.OriginalFileExporter;
import ghidra.app.util.exporter.IntelHexExporter;
import ghidra.app.util.exporter.AsciiExporter;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.GlobalNamespace;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class GhidraMCPHeadlessServer extends GhidraScript {
    private HttpServer server;

    @Override
    protected void run() throws Exception {
        Args args = Args.parse(getScriptArgs());
        Program program = currentProgram;
        if (program == null) {
            println("GhidraMCPHeadlessServer: currentProgram is null (did you -import a binary?)");
            return;
        }

        startServer(program, args.bindHost, args.port);
        println("GhidraMCPHeadlessServer: serving " + program.getName() + " on http://" + args.bindHost + ":" + args.port + "/");

        // Keep analyzeHeadless alive until cancelled or interrupted.
        TaskMonitor mon = monitor != null ? monitor : new ConsoleTaskMonitor();
        while (!mon.isCancelled()) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ie) {
                break;
            }
        }
    }

    private void startServer(Program program, String bindHost, int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress(bindHost, port), 0);

        // Basic health check
        server.createContext("/health", exchange -> sendResponse(exchange, "ok"));

        // Listing endpoints used by bridge_mcp_ghidra.py
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllFunctionNames(program, offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getAllClassNames(program, offset, limit));
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listSegments(program, offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listImports(program, offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listExports(program, offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listNamespaces(program, offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDefinedData(program, offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(program, searchTerm, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(program, offset, limit, filter));
        });

        // Program identification
        server.createContext("/get_program_name", exchange -> sendResponse(exchange, program.getName()));
        server.createContext("/get_program_info", exchange -> sendResponse(exchange, getProgramInfo(program)));

        // Decompile by function name (legacy)
        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(program, name));
        });

        // Rename endpoints (subset)
        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean ok = renameFunction(program, params.get("oldName"), params.get("newName"));
            sendResponse(exchange, ok ? "Renamed successfully" : "Rename failed");
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(program, params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            sendResponse(exchange, renameVariableInFunction(program, functionName, oldName, newName));
        });

        // Decompile/disassemble by address (newer bridge tools)
        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, decompileFunctionByAddress(program, qparams.get("address")));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            sendResponse(exchange, disassembleFunction(program, qparams.get("address")));
        });

        // Patch / bytes / export
        server.createContext("/patch_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String bytes = params.get("bytes");
            sendResponse(exchange, patchBytes(program, address, bytes));
        });
        server.createContext("/patch_instruction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String assembly = params.get("assembly");
            sendResponse(exchange, patchInstruction(program, address, assembly));
        });
        server.createContext("/nop_region", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String start = params.get("start_address");
            String end = params.get("end_address");
            sendResponse(exchange, nopRegion(program, start, end));
        });

        server.createContext("/get_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, getBytes(program, address, length));
        });

        server.createContext("/export_binary", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String outputPath = params.get("output_path");
            String format = params.get("format");
            sendResponse(exchange, exportBinary(program, outputPath, format));
        });

        server.createContext("/save_program", exchange -> {
            sendResponse(exchange, saveProgram(program));
        });

        server.createContext("/list_exporters", exchange -> sendResponse(exchange, listExporters()));

        server.createContext("/run_auto_analysis", exchange -> sendResponse(exchange, runAutoAnalysis(program)));

        // A couple of endpoints exist in the MCP bridge but are UI-oriented; return explicit messages.
        server.createContext("/get_current_address", exchange -> sendResponse(exchange, "Headless server: no UI selection"));
        server.createContext("/get_current_function", exchange -> sendResponse(exchange, "Headless server: no UI selection"));
        server.createContext("/goto_address", exchange -> sendResponse(exchange, "Headless server: goto_address not supported"));

        server.setExecutor(null);
        server.start();
    }

    // ----------------------------------------------------------------------------------
    // Core implementations (copied/simplified from the GUI plugin)
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(Program program, int offset, int limit) {
        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(Program program, int offset, int limit) {
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(Program program, int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(Program program, int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(Program program, int offset, int limit) {
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(Program program, int offset, int limit) {
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(Program program, int offset, int limit) {
        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s", data.getAddress(), escapeNonAscii(label), escapeNonAscii(valRepr)));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(Program program, String searchTerm, int offset, int limit) {
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
        Collections.sort(matches);
        if (matches.isEmpty()) return "No functions matching '" + searchTerm + "'";
        return paginateList(matches, offset, limit);
    }

    private String decompileFunctionByName(Program program, String name) {
        if (name == null || name.isEmpty()) return "Function name is required";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                return (result != null && result.decompileCompleted())
                        ? result.getDecompiledFunction().getC()
                        : "Decompilation failed";
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(Program program, String oldName, String newName) {
        if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) return false;
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(oldName)) {
                int tx = program.startTransaction("Rename function " + oldName);
                boolean success = false;
                try {
                    func.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                } catch (Exception e) {
                    Msg.error(this, "Rename failed", e);
                } finally {
                    program.endTransaction(tx, success);
                }
                return success;
            }
        }
        return false;
    }

    private void renameDataAtAddress(Program program, String addressStr, String newName) {
        if (addressStr == null || addressStr.isEmpty() || newName == null || newName.isEmpty()) return;
        int tx = program.startTransaction("Rename data " + addressStr);
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(addr);
            if (data != null) {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Rename data error", e);
        } finally {
            program.endTransaction(tx, true);
        }
    }

    private String renameVariableInFunction(Program program, String functionName, String oldVarName, String newVarName) {
        if (functionName == null || functionName.isEmpty()) return "Function name is required";
        if (oldVarName == null || oldVarName.isEmpty()) return "Old variable name is required";
        if (newVarName == null || newVarName.isEmpty()) return "New variable name is required";

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);

            Function func = null;
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }
            if (func == null) return "Function not found";

            DecompileResults decResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (decResult == null || !decResult.decompileCompleted()) {
                return "Decompilation failed";
            }

            HighFunction highFunction = decResult.getHighFunction();
            if (highFunction == null) return "Decompilation failed (no high function)";

            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            if (localSymbolMap == null) return "Decompilation failed (no local symbol map)";

            HighSymbol target = null;
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                HighSymbol sym = symbols.next();
                String symName = sym.getName();
                if (symName.equals(oldVarName)) {
                    target = sym;
                }
                if (symName.equals(newVarName)) {
                    return "Error: A variable with name '" + newVarName + "' already exists in this function";
                }
            }
            if (target == null) return "Variable not found";

            boolean commitRequired = checkFullCommit(target, highFunction);

            int tx = program.startTransaction("Rename variable");
            boolean success = false;
            try {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(
                            highFunction,
                            false,
                            ReturnCommitOption.NO_COMMIT,
                            func.getSignatureSource()
                    );
                }

                HighFunctionDBUtil.updateDBVariable(
                        target,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                );
                success = true;
            } finally {
                program.endTransaction(tx, success);
            }

            return success ? "Variable renamed" : "Failed to rename variable";
        } catch (Exception e) {
            Msg.error(this, "Headless renameVariable failed", e);
            return "Failed to rename variable: " + e.getMessage();
        } finally {
            try {
                decomp.dispose();
            } catch (Exception ignored) {
                // best-effort cleanup
            }
        }
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     */
    protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }

        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }

            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
        return func;
    }

    private String decompileFunctionByAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            return (result != null && result.decompileCompleted())
                    ? result.getDecompiledFunction().getC()
                    : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    private String disassembleFunction(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                result.append(String.format("%s: %s\n", instr.getAddress(), instr.toString()));
            }
            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }

    private String getBytes(Program program, String addressStr, int length) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (length <= 0 || length > 4096) return "Invalid length (1-4096)";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] bytes = new byte[length];
            program.getMemory().getBytes(addr, bytes);

            StringBuilder result = new StringBuilder();
            result.append(String.format("Bytes at %s (%d bytes):\n", addr, length));
            result.append(bytesToHex(bytes));
            return result.toString();
        } catch (Exception e) {
            return "Error getting bytes: " + e.getMessage();
        }
    }

    private String exportBinary(Program program, String outputPath, String format) {
        if (outputPath == null || outputPath.isEmpty()) return "Output path is required";
        try {
            File outputFile = new File(outputPath);
            Exporter exporter;
            String fmt = (format == null) ? "" : format.trim().toLowerCase();
            if (fmt.isEmpty() || fmt.equals("binary") || fmt.equals("bin") || fmt.equals("raw")) {
                exporter = new BinaryExporter();
            } else if (fmt.equals("original") || fmt.equals("elf") || fmt.equals("pe") || fmt.equals("native")) {
                // This preserves the original container format (ELF/PE/Mach-O) where possible.
                exporter = new OriginalFileExporter();
            } else if (fmt.equals("hex") || fmt.equals("ihex") || fmt.equals("intelhex")) {
                exporter = new IntelHexExporter();
            } else if (fmt.equals("ascii") || fmt.equals("txt") || fmt.equals("text")) {
                exporter = new AsciiExporter();
            } else {
                return "Unknown export format: " + format + ". Use /list_exporters to see available formats.";
            }

            AddressSet addrSet = new AddressSet(program.getMemory());
            TaskMonitor mon = new ConsoleTaskMonitor();
            boolean success = exporter.export(outputFile, program, addrSet, mon);
            if (success) {
                return String.format(
                        "Exported to %s using %s exporter\nFile size: %d bytes",
                        outputFile.getAbsolutePath(),
                        exporter.getName(),
                        outputFile.length()
                );
            }
            return "Export failed: " + exporter.getMessageLog().toString();
        } catch (Exception e) {
            return "Export error: " + e.getMessage();
        }
    }

    private String saveProgram(Program program) {
        try {
            program.save("Saved via GhidraMCPHeadlessServer", new ConsoleTaskMonitor());
            return "Program saved to Ghidra project: " + program.getName();
        } catch (Exception e) {
            return "Failed to save: " + e.getMessage();
        }
    }

    private String listExporters() {
        return String.join("\n",
                "Available export formats:",
                "- original / elf / pe (RECOMMENDED: preserves original file format with patches)",
                "- binary / raw (raw memory dump - may not be executable)",
                "- hex / intelhex (Intel HEX format)",
                "- ascii / txt (ASCII listing)",
                "",
                "For patched binaries, use 'original' format when possible."
        );
    }

    private String getProgramInfo(Program program) {
        StringBuilder sb = new StringBuilder();
        sb.append("Program: ").append(program.getName()).append("\n");
        sb.append("Language: ").append(program.getLanguageID()).append("\n");
        sb.append("CompilerSpec: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("ImageBase: ").append(program.getImageBase()).append("\n");
        sb.append("MinAddress: ").append(program.getMinAddress()).append("\n");
        sb.append("MaxAddress: ").append(program.getMaxAddress()).append("\n");
        return sb.toString();
    }

    private String listDefinedStrings(Program program, int offset, int limit, String filter) {
        // Simple implementation: walk defined data, pick items that look like strings.
        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = listing.getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (!block.contains(data.getAddress())) continue;
                String repr = data.getDefaultValueRepresentation();
                if (repr == null) continue;
                if (!repr.startsWith("\"")) continue;
                String line = String.format("%s: %s", data.getAddress(), escapeNonAscii(repr));
                if (filter != null && !filter.isEmpty() && !line.toLowerCase().contains(filter.toLowerCase())) {
                    continue;
                }
                lines.add(line);
            }
        }
        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    private String runAutoAnalysis(Program program) {
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            if (mgr == null) return "Could not get analysis manager";
            AddressSet addrSet = new AddressSet(program.getMemory());
            mgr.reAnalyzeAll(addrSet);
            return "Auto-analysis triggered for entire program. Analysis is running in background.";
        } catch (Exception e) {
            return "Error triggering auto-analysis: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // Patching methods (ported from GUI plugin; no Swing dependency)
    // ----------------------------------------------------------------------------------

    private String patchBytes(Program program, String addressStr, String hexBytes) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (hexBytes == null || hexBytes.isEmpty()) return "Bytes are required";

        String cleaned = hexBytes.replaceAll("\\s+", "");
        if (cleaned.length() % 2 != 0) return "Invalid hex string (odd length)";

        byte[] bytes = new byte[cleaned.length() / 2];
        try {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(cleaned.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return "Invalid hex string: " + e.getMessage();
        }

        int tx = program.startTransaction("Patch bytes at " + addressStr);
        boolean success = false;
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Memory memory = program.getMemory();

            byte[] original = new byte[bytes.length];
            memory.getBytes(addr, original);

            Listing listing = program.getListing();
            listing.clearCodeUnits(addr, addr.add(bytes.length - 1), false);
            memory.setBytes(addr, bytes);

            DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
            disCmd.applyTo(program, new ConsoleTaskMonitor());

            success = true;
            return String.format(
                    "Patched %d bytes at %s\nOriginal: %s\nNew: %s",
                    bytes.length, addr, bytesToHex(original), bytesToHex(bytes)
            );
        } catch (Exception e) {
            return "Error patching bytes: " + e.getMessage();
        } finally {
            program.endTransaction(tx, success);
        }
    }

    private String patchInstruction(Program program, String addressStr, String assembly) {
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (assembly == null || assembly.isEmpty()) return "Assembly instruction is required";

        int tx = program.startTransaction("Patch instruction at " + addressStr);
        boolean success = false;
        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Assembler assembler = Assemblers.getAssembler(program);

            Instruction originalInstr = program.getListing().getInstructionAt(addr);
            String originalStr = (originalInstr != null) ? originalInstr.toString() : "N/A";
            int originalLen = (originalInstr != null) ? originalInstr.getLength() : 0;

            byte[] assembled = assembler.assembleLine(addr, assembly);

            Listing listing = program.getListing();
            if (originalLen > 0) {
                listing.clearCodeUnits(addr, addr.add(originalLen - 1), false);
            }

            program.getMemory().setBytes(addr, assembled);

            DisassembleCommand disCmd = new DisassembleCommand(addr, null, true);
            disCmd.applyTo(program, new ConsoleTaskMonitor());

            success = true;
            StringBuilder sb = new StringBuilder();
            sb.append(String.format("Patched instruction at %s\n", addr));
            sb.append(String.format("Original: %s (%d bytes)\n", originalStr, originalLen));
            sb.append(String.format("New: %s (%d bytes)\n", assembly, assembled.length));
            sb.append(String.format("Bytes: %s", bytesToHex(assembled)));
            if (assembled.length < originalLen) {
                sb.append(String.format("\nWarning: New instruction is shorter. Consider NOPing %d remaining bytes.", originalLen - assembled.length));
            }
            return sb.toString();
        } catch (AssemblySyntaxException e) {
            return "Assembly syntax error: " + e.getMessage();
        } catch (AssemblySemanticException e) {
            return "Assembly semantic error: " + e.getMessage();
        } catch (Exception e) {
            return "Error patching instruction: " + e.getMessage();
        } finally {
            program.endTransaction(tx, success);
        }
    }

    private String nopRegion(Program program, String startAddrStr, String endAddrStr) {
        if (startAddrStr == null || startAddrStr.isEmpty()) return "Start address is required";
        if (endAddrStr == null || endAddrStr.isEmpty()) return "End address is required";

        int tx = program.startTransaction("NOP region " + startAddrStr + " to " + endAddrStr);
        boolean success = false;
        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddrStr);
            Address endAddr = program.getAddressFactory().getAddress(endAddrStr);
            long length = endAddr.subtract(startAddr) + 1;
            if (length <= 0 || length > 1024) return "Invalid range or too large (max 1024 bytes)";

            // Architecture-specific NOP is complex; default to 0x90 (x86/x64).
            byte[] nops = new byte[(int) length];
            Arrays.fill(nops, (byte) 0x90);

            Listing listing = program.getListing();
            listing.clearCodeUnits(startAddr, endAddr, false);
            program.getMemory().setBytes(startAddr, nops);

            DisassembleCommand disCmd = new DisassembleCommand(startAddr, null, true);
            disCmd.applyTo(program, new ConsoleTaskMonitor());

            success = true;
            return String.format("NOPed %d bytes from %s to %s", length, startAddr, endAddr);
        } catch (Exception e) {
            return "Error NOPing region: " + e.getMessage();
        } finally {
            program.endTransaction(tx, success);
        }
    }

    // ----------------------------------------------------------------------------------
    // HTTP helpers
    // ----------------------------------------------------------------------------------

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        if (response == null) response = "";
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query == null || query.isEmpty()) return result;

        for (String p : query.split("&")) {
            String[] kv = p.split("=");
            if (kv.length != 2) continue;
            try {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                result.put(key, value);
            } catch (Exception e) {
                Msg.error(this, "Error decoding query param", e);
            }
        }
        return result;
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        if (bodyStr.isEmpty()) return params;

        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length != 2) continue;
            try {
                String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                params.put(key, value);
            } catch (Exception e) {
                Msg.error(this, "Error decoding post param", e);
            }
        }
        return params;
    }

    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), offset + limit);
        if (start >= items.size()) return "";
        return String.join("\n", items.subList(start, end));
    }

    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) sb.append(c);
            else sb.append(String.format("\\x%02x", (int) c & 0xFF));
        }
        return sb.toString();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
            if (i < bytes.length - 1) sb.append(" ");
        }
        return sb.toString();
    }

    private static final class Args {
        final String bindHost;
        final int port;

        private Args(String bindHost, int port) {
            this.bindHost = bindHost;
            this.port = port;
        }

        static Args parse(String[] argv) {
            String bind = "127.0.0.1";
            int port = 8080;
            for (int i = 0; i < argv.length; i++) {
                String a = argv[i];
                if ("--bind".equals(a) && i + 1 < argv.length) {
                    bind = argv[++i];
                } else if ("--port".equals(a) && i + 1 < argv.length) {
                    port = Integer.parseInt(argv[++i]);
                }
            }
            return new Args(bind, port);
        }
    }
}

