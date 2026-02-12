package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.exporter.BinaryExporter;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Bookmark;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.GoToService;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.symbol.FlowType;

import java.io.File;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/get_program_name", exchange -> {
            sendResponse(exchange, getProgramName());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // ==================== PATCHING ENDPOINTS ====================

        // Patch bytes at an address
        server.createContext("/patch_bytes", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String hexBytes = params.get("bytes");  // e.g., "90 90 90" or "909090"
            String result = patchBytes(address, hexBytes);
            sendResponse(exchange, result);
        });

        // Patch with assembly instruction
        server.createContext("/patch_instruction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String assembly = params.get("assembly");  // e.g., "NOP" or "MOV EAX, 0x1"
            String result = patchInstruction(address, assembly);
            sendResponse(exchange, result);
        });

        // NOP out an address range or instruction
        server.createContext("/nop_region", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String startAddr = params.get("start_address");
            String endAddr = params.get("end_address");
            String result = nopRegion(startAddr, endAddr);
            sendResponse(exchange, result);
        });

        // Get bytes at address
        server.createContext("/get_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            sendResponse(exchange, getBytes(address, length));
        });

        // ==================== EXPORT ENDPOINTS ====================

        // Export patched binary
        server.createContext("/export_binary", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String outputPath = params.get("output_path");
            String format = params.get("format");  // "binary", "elf", "pe", or null for original
            String result = exportBinary(outputPath, format);
            sendResponse(exchange, result);
        });

        // Save the current program (to Ghidra project)
        server.createContext("/save_program", exchange -> {
            String result = saveProgram();
            sendResponse(exchange, result);
        });

        // List available exporters
        server.createContext("/list_exporters", exchange -> {
            sendResponse(exchange, listExporters());
        });

        // ==================== ENHANCED ANALYSIS ENDPOINTS ====================

        // Get all functions that call a given function (callers)
        server.createContext("/callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getCallers(name, offset, limit));
        });

        // Get all functions called by a given function (callees)
        server.createContext("/callees", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getCallees(name, offset, limit));
        });

        // Get function variables and parameters
        server.createContext("/get_function_variables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionVariables(address));
        });

        // Create a function at an address
        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            sendResponse(exchange, createFunction(address, name));
        });

        // Delete a function
        server.createContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, deleteFunction(address));
        });

        // List defined data types
        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String category = qparams.get("category");
            sendResponse(exchange, listDataTypes(offset, limit, category));
        });

        // Get structure fields
        server.createContext("/get_struct_fields", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            sendResponse(exchange, getStructFields(name));
        });

        // Create a new structure
        server.createContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 0);
            String category = params.get("category");
            sendResponse(exchange, createStruct(name, size, category));
        });

        // Add a field to a structure
        server.createContext("/add_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldName = params.get("field_name");
            String fieldType = params.get("field_type");
            int fieldOffset = parseIntOrDefault(params.get("offset"), -1);
            int fieldSize = parseIntOrDefault(params.get("size"), 0);
            sendResponse(exchange, addStructField(structName, fieldName, fieldType, fieldOffset, fieldSize));
        });

        // Create a new enum
        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            int size = parseIntOrDefault(params.get("size"), 4);
            String category = params.get("category");
            sendResponse(exchange, createEnum(name, size, category));
        });

        // Add a member to an enum
        server.createContext("/add_enum_member", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String enumName = params.get("enum_name");
            String memberName = params.get("member_name");
            long memberValue = Long.parseLong(params.getOrDefault("value", "0"));
            sendResponse(exchange, addEnumMember(enumName, memberName, memberValue));
        });

        // Set a bookmark at an address
        server.createContext("/set_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String bookmarkCategory = params.get("category");
            String comment = params.get("comment");
            sendResponse(exchange, setBookmark(address, bookmarkCategory, comment));
        });

        // List all bookmarks
        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String category = qparams.get("category");
            sendResponse(exchange, listBookmarks(offset, limit, category));
        });

        // Delete a bookmark
        server.createContext("/delete_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String bookmarkCategory = params.get("category");
            sendResponse(exchange, deleteBookmark(address, bookmarkCategory));
        });

        // Search memory for byte patterns
        server.createContext("/search_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String hexPattern = qparams.get("pattern");
            int maxResults = parseIntOrDefault(qparams.get("max_results"), 100);
            sendResponse(exchange, searchMemory(hexPattern, maxResults));
        });

        // Get comprehensive info about an address
        server.createContext("/get_address_info", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getAddressInfo(address));
        });

        // Navigate Ghidra UI to an address
        server.createContext("/goto_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, gotoAddress(address));
        });

        // Get comprehensive program info / binary metadata
        server.createContext("/get_program_info", exchange -> {
            sendResponse(exchange, getProgramInfo());
        });

        // List all comments in the program
        server.createContext("/list_comments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String commentType = qparams.get("type");
            sendResponse(exchange, listComments(offset, limit, commentType));
        });

        // Trigger auto-analysis
        server.createContext("/run_auto_analysis", exchange -> {
            sendResponse(exchange, runAutoAnalysis());
        });

        // Ghidra help reference for scripting concepts
        server.createContext("/ghidra_help", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String topic = qparams.get("topic");
            sendResponse(exchange, getGhidraHelp(topic));
        });

        // ==================== ENHANCED RENAME & RE ENDPOINTS ====================

        // Rename a variable within a function identified by address
        server.createContext("/rename_variable_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            sendResponse(exchange, renameVariableByAddress(functionAddress, oldName, newName));
        });

        // Batch rename multiple symbols in one request
        server.createContext("/batch_rename", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, batchRename(body));
        });

        // Get complete call graph (both callers and callees) for a function
        server.createContext("/get_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int depth = parseIntOrDefault(qparams.get("depth"), 1);
            sendResponse(exchange, getCallGraph(name, depth));
        });

        // List functions with auto-generated names (not yet analyzed/renamed)
        server.createContext("/list_undefined_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listUndefinedFunctions(offset, limit));
        });

        // Get control flow and complexity info for a function
        server.createContext("/get_function_cfg_info", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionCfgInfo(address));
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

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

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
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
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
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

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * Get the name of the currently loaded program
     */
    private String getProgramName() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return program.getName();
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
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

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
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
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // ENHANCED ANALYSIS METHODS
    // ----------------------------------------------------------------------------------

    /**
     * Get all functions that call a given function (callers / incoming references)
     */
    private String getCallers(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        Function targetFunc = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                targetFunc = f;
                break;
            }
        }
        if (targetFunc == null) return "Function not found: " + functionName;

        Set<String> callers = new LinkedHashSet<>();
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesTo(targetFunc.getEntryPoint());

        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    callers.add(String.format("%s @ %s -> %s [%s]",
                        caller.getName(), ref.getFromAddress(),
                        functionName, ref.getReferenceType().getName()));
                }
            }
        }

        if (callers.isEmpty()) return "No callers found for function: " + functionName;
        return paginateList(new ArrayList<>(callers), offset, limit);
    }

    /**
     * Get all functions called by a given function (callees / outgoing calls)
     */
    private String getCallees(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        Function targetFunc = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                targetFunc = f;
                break;
            }
        }
        if (targetFunc == null) return "Function not found: " + functionName;

        Set<String> callees = new LinkedHashSet<>();
        ReferenceManager refManager = program.getReferenceManager();
        AddressRangeIterator bodyRanges = targetFunc.getBody().getAddressRanges();

        while (bodyRanges.hasNext()) {
            AddressRange range = bodyRanges.next();
            Address addr = range.getMinAddress();
            while (addr != null && addr.compareTo(range.getMaxAddress()) <= 0) {
                Reference[] refsFrom = refManager.getReferencesFrom(addr);
                for (Reference ref : refsFrom) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (callee == null) {
                            callee = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
                        }
                        String calleeName = (callee != null) ? callee.getName() : "unknown@" + ref.getToAddress();
                        callees.add(String.format("%s calls %s @ %s [%s]",
                            functionName, calleeName, ref.getToAddress(),
                            ref.getReferenceType().getName()));
                    }
                }
                addr = addr.next();
            }
        }

        if (callees.isEmpty()) return "No callees found for function: " + functionName;
        return paginateList(new ArrayList<>(callees), offset, limit);
    }

    /**
     * Get all variables and parameters for a function at the given address
     */
    private String getFunctionVariables(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            StringBuilder result = new StringBuilder();
            result.append("Function: ").append(func.getName()).append(" @ ").append(func.getEntryPoint()).append("\n");
            result.append("Signature: ").append(func.getSignature()).append("\n\n");

            // Return type
            result.append("Return type: ").append(func.getReturnType().getName()).append("\n\n");

            // Parameters
            Parameter[] params = func.getParameters();
            result.append("Parameters (").append(params.length).append("):\n");
            for (Parameter p : params) {
                result.append(String.format("  %s %s [%s] (ordinal=%d)\n",
                    p.getDataType().getName(), p.getName(),
                    p.getVariableStorage(), p.getOrdinal()));
            }

            // Local variables
            Variable[] locals = func.getLocalVariables();
            result.append("\nLocal variables (").append(locals.length).append("):\n");
            for (Variable v : locals) {
                result.append(String.format("  %s %s [%s]\n",
                    v.getDataType().getName(), v.getName(),
                    v.getVariableStorage()));
            }

            // Stack frame info
            result.append("\nStack frame size: ").append(func.getStackFrame().getFrameSize());
            result.append("\nStack parameter offset: ").append(func.getStackFrame().getParameterOffset());

            return result.toString();
        } catch (Exception e) {
            return "Error getting function variables: " + e.getMessage();
        }
    }

    /**
     * Create a new function at the specified address
     */
    private String createFunction(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create function");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function at " + addressStr);
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);

                    // Check if function already exists
                    Function existing = program.getFunctionManager().getFunctionAt(addr);
                    if (existing != null) {
                        result.set("Function already exists at " + addressStr + ": " + existing.getName());
                        return;
                    }

                    CreateFunctionCmd cmd = new CreateFunctionCmd(addr);
                    boolean created = cmd.applyTo(program, new ConsoleTaskMonitor());

                    if (created) {
                        Function newFunc = program.getFunctionManager().getFunctionAt(addr);
                        if (newFunc != null && name != null && !name.isEmpty()) {
                            newFunc.setName(name, SourceType.USER_DEFINED);
                        }
                        String funcName = (newFunc != null) ? newFunc.getName() : "unknown";
                        result.set("Created function " + funcName + " at " + addr);
                        success = true;
                    } else {
                        result.set("Failed to create function at " + addressStr + ": " + cmd.getStatusMsg());
                    }
                } catch (Exception e) {
                    result.set("Error creating function: " + e.getMessage());
                    Msg.error(this, "Error creating function", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create function on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Delete a function at the specified address
     */
    private String deleteFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to delete function");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete function at " + addressStr);
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Function func = program.getFunctionManager().getFunctionAt(addr);

                    if (func == null) {
                        result.set("No function found at " + addressStr);
                        return;
                    }

                    String funcName = func.getName();
                    program.getFunctionManager().removeFunction(addr);
                    result.set("Deleted function " + funcName + " at " + addr);
                    success = true;
                } catch (Exception e) {
                    result.set("Error deleting function: " + e.getMessage());
                    Msg.error(this, "Error deleting function", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to delete function on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * List all defined data types in the program
     */
    private String listDataTypes(int offset, int limit, String categoryFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> lines = new ArrayList<>();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String catPath = dt.getCategoryPath().getPath();

            if (categoryFilter != null && !categoryFilter.isEmpty()) {
                if (!catPath.toLowerCase().contains(categoryFilter.toLowerCase())) {
                    continue;
                }
            }

            String typeKind;
            if (dt instanceof Structure) {
                typeKind = "struct";
            } else if (dt instanceof Enum) {
                typeKind = "enum";
            } else if (dt instanceof ghidra.program.model.data.TypeDef) {
                typeKind = "typedef";
            } else if (dt instanceof ghidra.program.model.data.FunctionDefinition) {
                typeKind = "funcdef";
            } else {
                typeKind = "other";
            }

            lines.add(String.format("[%s] %s (size=%d, category=%s)",
                typeKind, dt.getPathName(), dt.getLength(), catPath));
        }

        Collections.sort(lines);
        if (lines.isEmpty()) return "No data types found";
        return paginateList(lines, offset, limit);
    }

    /**
     * Get the fields of a structure by name
     */
    private String getStructFields(String structName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType found = findDataTypeByNameInAllCategories(dtm, structName);

        if (found == null) return "Structure not found: " + structName;
        if (!(found instanceof Structure)) return structName + " is not a structure (it is " + found.getClass().getSimpleName() + ")";

        Structure struct = (Structure) found;
        StringBuilder result = new StringBuilder();
        result.append("Structure: ").append(struct.getPathName()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n\n");
        result.append("Fields:\n");

        DataTypeComponent[] components = struct.getComponents();
        for (DataTypeComponent comp : components) {
            String fieldName = comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)";
            String comment = comp.getComment() != null ? " // " + comp.getComment() : "";
            result.append(String.format("  offset=0x%x size=%d %s %s%s\n",
                comp.getOffset(), comp.getLength(),
                comp.getDataType().getName(), fieldName, comment));
        }

        return result.toString();
    }

    /**
     * Create a new structure data type
     */
    private String createStruct(String name, int size, String categoryStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Structure name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create structure");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure " + name);
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    CategoryPath catPath = (categoryStr != null && !categoryStr.isEmpty())
                        ? new CategoryPath(categoryStr)
                        : CategoryPath.ROOT;

                    StructureDataType struct = new StructureDataType(catPath, name, size, dtm);
                    DataType resolved = dtm.addDataType(struct, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Created structure: " + resolved.getPathName() + " (size=" + resolved.getLength() + ")");
                    success = true;
                } catch (Exception e) {
                    result.set("Error creating structure: " + e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create structure on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Add a field to a structure
     */
    private String addStructField(String structName, String fieldName, String fieldType, int fieldOffset, int fieldSize) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldType == null || fieldType.isEmpty()) return "Field type is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to add field");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add field to " + structName);
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType found = findDataTypeByNameInAllCategories(dtm, structName);
                    if (found == null || !(found instanceof Structure)) {
                        result.set("Structure not found: " + structName);
                        return;
                    }

                    Structure struct = (Structure) found;
                    DataType fType = resolveDataType(dtm, fieldType);
                    if (fType == null) {
                        result.set("Could not resolve field type: " + fieldType);
                        return;
                    }

                    String fName = (fieldName != null && !fieldName.isEmpty()) ? fieldName : null;

                    if (fieldOffset >= 0) {
                        // Insert at specific offset
                        int actualSize = (fieldSize > 0) ? fieldSize : fType.getLength();
                        struct.replaceAtOffset(fieldOffset, fType, actualSize, fName, null);
                        result.set(String.format("Added field %s (%s) at offset 0x%x in %s",
                            fName != null ? fName : "(auto)", fType.getName(), fieldOffset, structName));
                    } else {
                        // Append to end
                        struct.add(fType, (fieldSize > 0) ? fieldSize : fType.getLength(), fName, null);
                        result.set(String.format("Appended field %s (%s) to %s",
                            fName != null ? fName : "(auto)", fType.getName(), structName));
                    }
                    success = true;
                } catch (Exception e) {
                    result.set("Error adding field: " + e.getMessage());
                    Msg.error(this, "Error adding struct field", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add struct field on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Create a new enum data type
     */
    private String createEnum(String name, int size, String categoryStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Enum name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to create enum");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum " + name);
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    CategoryPath catPath = (categoryStr != null && !categoryStr.isEmpty())
                        ? new CategoryPath(categoryStr)
                        : CategoryPath.ROOT;

                    EnumDataType enumType = new EnumDataType(catPath, name, size, dtm);
                    DataType resolved = dtm.addDataType(enumType, ghidra.program.model.data.DataTypeConflictHandler.REPLACE_HANDLER);

                    result.set("Created enum: " + resolved.getPathName() + " (size=" + resolved.getLength() + ")");
                    success = true;
                } catch (Exception e) {
                    result.set("Error creating enum: " + e.getMessage());
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to create enum on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Add a member to an enum
     */
    private String addEnumMember(String enumName, String memberName, long memberValue) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";
        if (memberName == null || memberName.isEmpty()) return "Member name is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to add enum member");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add enum member to " + enumName);
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType found = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (found == null || !(found instanceof Enum)) {
                        result.set("Enum not found: " + enumName);
                        return;
                    }

                    Enum enumType = (Enum) found;
                    enumType.add(memberName, memberValue);
                    result.set(String.format("Added %s = %d (0x%x) to enum %s",
                        memberName, memberValue, memberValue, enumName));
                    success = true;
                } catch (Exception e) {
                    result.set("Error adding enum member: " + e.getMessage());
                    Msg.error(this, "Error adding enum member", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to add enum member on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Set a bookmark at the specified address
     */
    private String setBookmark(String addressStr, String category, String comment) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        String bookmarkCategory = (category != null && !category.isEmpty()) ? category : "Analysis";
        String bookmarkComment = (comment != null && !comment.isEmpty()) ? comment : "";

        AtomicReference<String> result = new AtomicReference<>("Failed to set bookmark");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set bookmark at " + addressStr);
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    BookmarkManager bm = program.getBookmarkManager();
                    bm.setBookmark(addr, "Note", bookmarkCategory, bookmarkComment);
                    result.set(String.format("Bookmark set at %s [%s]: %s", addr, bookmarkCategory, bookmarkComment));
                    success = true;
                } catch (Exception e) {
                    result.set("Error setting bookmark: " + e.getMessage());
                    Msg.error(this, "Error setting bookmark", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to set bookmark on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * List all bookmarks in the program
     */
    private String listBookmarks(int offset, int limit, String categoryFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        BookmarkManager bm = program.getBookmarkManager();
        List<String> lines = new ArrayList<>();

        Iterator<Bookmark> bookmarks = bm.getBookmarksIterator();
        while (bookmarks.hasNext()) {
            Bookmark b = bookmarks.next();
            if (categoryFilter != null && !categoryFilter.isEmpty()) {
                if (!b.getCategory().equalsIgnoreCase(categoryFilter)) {
                    continue;
                }
            }
            Function func = program.getFunctionManager().getFunctionContaining(b.getAddress());
            String funcInfo = (func != null) ? " in " + func.getName() : "";
            lines.add(String.format("%s [%s/%s]%s: %s",
                b.getAddress(), b.getTypeString(), b.getCategory(),
                funcInfo, b.getComment()));
        }

        if (lines.isEmpty()) return "No bookmarks found";
        return paginateList(lines, offset, limit);
    }

    /**
     * Delete a bookmark at the specified address
     */
    private String deleteBookmark(String addressStr, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to delete bookmark");

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete bookmark at " + addressStr);
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    BookmarkManager bm = program.getBookmarkManager();
                    Bookmark[] bookmarks = bm.getBookmarks(addr);

                    int removed = 0;
                    for (Bookmark b : bookmarks) {
                        if (category == null || category.isEmpty() || b.getCategory().equalsIgnoreCase(category)) {
                            bm.removeBookmark(b);
                            removed++;
                        }
                    }

                    if (removed > 0) {
                        result.set("Removed " + removed + " bookmark(s) at " + addr);
                        success = true;
                    } else {
                        result.set("No bookmarks found at " + addr);
                    }
                } catch (Exception e) {
                    result.set("Error deleting bookmark: " + e.getMessage());
                    Msg.error(this, "Error deleting bookmark", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to delete bookmark on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Search memory for a byte pattern
     */
    private String searchMemory(String hexPattern, int maxResults) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (hexPattern == null || hexPattern.isEmpty()) return "Hex pattern is required";

        // Parse hex pattern (supports "90 90" and "9090" and "90 ?? 90" for wildcards)
        hexPattern = hexPattern.trim();
        String[] parts = hexPattern.split("\\s+");

        // Build byte array and mask for wildcard support
        List<Byte> patternBytes = new ArrayList<>();
        List<Byte> maskBytes = new ArrayList<>();

        for (String part : parts) {
            if (part.length() == 2) {
                if (part.equals("??")) {
                    patternBytes.add((byte) 0);
                    maskBytes.add((byte) 0);
                } else {
                    patternBytes.add((byte) Integer.parseInt(part, 16));
                    maskBytes.add((byte) 0xFF);
                }
            } else {
                // Consecutive hex without spaces
                for (int i = 0; i < part.length(); i += 2) {
                    String byteStr = part.substring(i, Math.min(i + 2, part.length()));
                    if (byteStr.equals("??")) {
                        patternBytes.add((byte) 0);
                        maskBytes.add((byte) 0);
                    } else {
                        patternBytes.add((byte) Integer.parseInt(byteStr, 16));
                        maskBytes.add((byte) 0xFF);
                    }
                }
            }
        }

        byte[] pattern = new byte[patternBytes.size()];
        byte[] mask = new byte[maskBytes.size()];
        for (int i = 0; i < pattern.length; i++) {
            pattern[i] = patternBytes.get(i);
            mask[i] = maskBytes.get(i);
        }

        Memory memory = program.getMemory();
        List<String> results = new ArrayList<>();
        Address searchAddr = program.getMinAddress();

        try {
            while (searchAddr != null && results.size() < maxResults) {
                Address found = memory.findBytes(searchAddr, pattern, mask, true, new ConsoleTaskMonitor());
                if (found == null) break;

                Function func = program.getFunctionManager().getFunctionContaining(found);
                String funcInfo = (func != null) ? " in " + func.getName() : "";
                MemoryBlock block = memory.getBlock(found);
                String blockInfo = (block != null) ? " [" + block.getName() + "]" : "";

                results.add(String.format("%s%s%s", found, blockInfo, funcInfo));

                // Move to next byte after the found location
                searchAddr = found.add(1);
            }
        } catch (Exception e) {
            return "Error searching memory: " + e.getMessage();
        }

        if (results.isEmpty()) return "Pattern not found: " + hexPattern;

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Found %d match(es) for pattern %s:\n", results.size(), hexPattern));
        for (String r : results) {
            sb.append(r).append("\n");
        }
        return sb.toString();
    }

    /**
     * Get comprehensive information about what's at a given address
     */
    private String getAddressInfo(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            StringBuilder result = new StringBuilder();
            result.append("Address: ").append(addr).append("\n\n");

            // Memory block info
            MemoryBlock block = program.getMemory().getBlock(addr);
            if (block != null) {
                result.append("Memory Block: ").append(block.getName()).append("\n");
                result.append("  Range: ").append(block.getStart()).append(" - ").append(block.getEnd()).append("\n");
                result.append("  Permissions: ");
                if (block.isRead()) result.append("R");
                if (block.isWrite()) result.append("W");
                if (block.isExecute()) result.append("X");
                result.append("\n  Type: ").append(block.getType()).append("\n\n");
            }

            // Function info
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                result.append("Function entry: ").append(func.getName()).append("\n");
                result.append("  Signature: ").append(func.getSignature()).append("\n");
                result.append("  Body: ").append(func.getBody().getMinAddress()).append(" - ")
                    .append(func.getBody().getMaxAddress()).append("\n\n");
            } else {
                Function containing = program.getFunctionManager().getFunctionContaining(addr);
                if (containing != null) {
                    result.append("Inside function: ").append(containing.getName())
                        .append(" @ ").append(containing.getEntryPoint()).append("\n\n");
                }
            }

            // Instruction info
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr != null) {
                result.append("Instruction: ").append(instr.toString()).append("\n");
                result.append("  Length: ").append(instr.getLength()).append(" bytes\n");
                result.append("  Bytes: ").append(bytesToHex(instr.getBytes())).append("\n");
                result.append("  Mnemonic: ").append(instr.getMnemonicString()).append("\n");
                int numOps = instr.getNumOperands();
                for (int i = 0; i < numOps; i++) {
                    result.append("  Operand ").append(i).append(": ")
                        .append(instr.getDefaultOperandRepresentation(i)).append("\n");
                }
                result.append("\n");
            }

            // Data info
            Data data = program.getListing().getDataAt(addr);
            if (data != null && data.isDefined()) {
                result.append("Data: ").append(data.getDataType().getName()).append("\n");
                result.append("  Label: ").append(data.getLabel() != null ? data.getLabel() : "(none)").append("\n");
                result.append("  Value: ").append(escapeNonAscii(data.getDefaultValueRepresentation())).append("\n");
                result.append("  Size: ").append(data.getLength()).append(" bytes\n\n");
            }

            // Symbol info
            Symbol[] symbols = program.getSymbolTable().getSymbols(addr);
            if (symbols.length > 0) {
                result.append("Symbols:\n");
                for (Symbol s : symbols) {
                    result.append(String.format("  %s (type=%s, source=%s, primary=%s)\n",
                        s.getName(), s.getSymbolType(), s.getSource(), s.isPrimary()));
                }
                result.append("\n");
            }

            // Comments
            Listing listing = program.getListing();
            String[] commentTypes = {"EOL", "Pre", "Post", "Plate", "Repeatable"};
            int[] commentTypeConstants = {
                CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT,
                CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT
            };
            boolean hasComments = false;
            for (int i = 0; i < commentTypes.length; i++) {
                String comment = listing.getComment(commentTypeConstants[i], addr);
                if (comment != null) {
                    if (!hasComments) {
                        result.append("Comments:\n");
                        hasComments = true;
                    }
                    result.append(String.format("  %s: %s\n", commentTypes[i], comment));
                }
            }
            if (hasComments) result.append("\n");

            // References to this address
            java.util.List<Reference> refsToList = new java.util.ArrayList<>();
            for (Reference ref : program.getReferenceManager().getReferencesTo(addr)) {
                refsToList.add(ref);
            }
            Reference[] refsTo = refsToList.toArray(new Reference[0]);
            if (refsTo.length > 0) {
                result.append("References TO this address (").append(refsTo.length).append("):\n");
                int shown = Math.min(refsTo.length, 10);
                for (int i = 0; i < shown; i++) {
                    result.append(String.format("  from %s [%s]\n",
                        refsTo[i].getFromAddress(), refsTo[i].getReferenceType().getName()));
                }
                if (refsTo.length > 10) result.append("  ... and ").append(refsTo.length - 10).append(" more\n");
                result.append("\n");
            }

            // References from this address
            Reference[] refsFrom = program.getReferenceManager().getReferencesFrom(addr);
            if (refsFrom.length > 0) {
                result.append("References FROM this address (").append(refsFrom.length).append("):\n");
                for (Reference ref : refsFrom) {
                    result.append(String.format("  to %s [%s]\n",
                        ref.getToAddress(), ref.getReferenceType().getName()));
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error getting address info: " + e.getMessage();
        }
    }

    /**
     * Navigate the Ghidra UI to a specific address
     */
    private String gotoAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        AtomicReference<String> result = new AtomicReference<>("Failed to navigate");

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    GoToService goToService = tool.getService(GoToService.class);
                    if (goToService != null) {
                        boolean success = goToService.goTo(addr);
                        if (success) {
                            Function func = program.getFunctionManager().getFunctionContaining(addr);
                            String funcInfo = (func != null) ? " (in " + func.getName() + ")" : "";
                            result.set("Navigated to " + addr + funcInfo);
                        } else {
                            result.set("Could not navigate to " + addr);
                        }
                    } else {
                        result.set("GoTo service not available");
                    }
                } catch (Exception e) {
                    result.set("Error navigating: " + e.getMessage());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to navigate on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Get comprehensive program/binary metadata
     */
    private String getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        result.append("=== Program Information ===\n\n");
        result.append("Name: ").append(program.getName()).append("\n");
        result.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        result.append("Compiler Spec: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        result.append("Processor: ").append(program.getLanguage().getProcessor()).append("\n");
        result.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        result.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");
        result.append("Executable Format: ").append(program.getExecutableFormat()).append("\n");
        result.append("Executable Path: ").append(program.getExecutablePath()).append("\n");

        String md5 = program.getExecutableMD5();
        if (md5 != null && !md5.isEmpty()) {
            result.append("MD5: ").append(md5).append("\n");
        }
        String sha256 = program.getExecutableSHA256();
        if (sha256 != null && !sha256.isEmpty()) {
            result.append("SHA256: ").append(sha256).append("\n");
        }

        result.append("\nImage Base: ").append(program.getImageBase()).append("\n");
        result.append("Min Address: ").append(program.getMinAddress()).append("\n");
        result.append("Max Address: ").append(program.getMaxAddress()).append("\n");

        // Count functions
        int funcCount = 0;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            funcCount++;
        }
        result.append("\nFunction Count: ").append(funcCount).append("\n");

        // Memory blocks summary
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        result.append("Memory Blocks: ").append(blocks.length).append("\n");
        long totalSize = 0;
        for (MemoryBlock b : blocks) {
            totalSize += b.getSize();
        }
        result.append("Total Memory: ").append(totalSize).append(" bytes\n");

        // Symbol counts
        SymbolTable symTable = program.getSymbolTable();
        result.append("Symbol Count: ").append(symTable.getNumSymbols()).append("\n");

        // Bookmark counts
        BookmarkManager bm = program.getBookmarkManager();
        result.append("Bookmark Count: ").append(bm.getBookmarkCount()).append("\n");

        // Data type counts
        DataTypeManager dtm = program.getDataTypeManager();
        int dtCount = 0;
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) { dtIter.next(); dtCount++; }
        result.append("Data Type Count: ").append(dtCount).append("\n");

        return result.toString();
    }

    /**
     * List all comments in the program
     */
    private String listComments(int offset, int limit, String commentTypeFilter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();

        // Define which comment types to search
        int[] commentTypes;
        String[] commentTypeNames;

        if (commentTypeFilter != null && !commentTypeFilter.isEmpty()) {
            switch (commentTypeFilter.toLowerCase()) {
                case "eol":
                    commentTypes = new int[]{CodeUnit.EOL_COMMENT};
                    commentTypeNames = new String[]{"EOL"};
                    break;
                case "pre":
                    commentTypes = new int[]{CodeUnit.PRE_COMMENT};
                    commentTypeNames = new String[]{"Pre"};
                    break;
                case "post":
                    commentTypes = new int[]{CodeUnit.POST_COMMENT};
                    commentTypeNames = new String[]{"Post"};
                    break;
                case "plate":
                    commentTypes = new int[]{CodeUnit.PLATE_COMMENT};
                    commentTypeNames = new String[]{"Plate"};
                    break;
                case "repeatable":
                    commentTypes = new int[]{CodeUnit.REPEATABLE_COMMENT};
                    commentTypeNames = new String[]{"Repeatable"};
                    break;
                default:
                    commentTypes = new int[]{CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT,
                        CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT};
                    commentTypeNames = new String[]{"EOL", "Pre", "Post", "Plate", "Repeatable"};
                    break;
            }
        } else {
            commentTypes = new int[]{CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT,
                CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT, CodeUnit.REPEATABLE_COMMENT};
            commentTypeNames = new String[]{"EOL", "Pre", "Post", "Plate", "Repeatable"};
        }

        // Iterate through all code units looking for comments
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            CodeUnitIterator cuIter = listing.getCodeUnits(block.getStart(), true);
            while (cuIter.hasNext()) {
                CodeUnit cu = cuIter.next();
                if (!block.contains(cu.getAddress())) break;

                for (int i = 0; i < commentTypes.length; i++) {
                    String comment = cu.getComment(commentTypes[i]);
                    if (comment != null && !comment.isEmpty()) {
                        Function func = program.getFunctionManager().getFunctionContaining(cu.getAddress());
                        String funcInfo = (func != null) ? " in " + func.getName() : "";
                        lines.add(String.format("%s [%s]%s: %s",
                            cu.getAddress(), commentTypeNames[i], funcInfo, escapeString(comment)));
                    }
                }
            }
        }

        if (lines.isEmpty()) return "No comments found";
        return paginateList(lines, offset, limit);
    }

    /**
     * Trigger auto-analysis on the current program
     */
    private String runAutoAnalysis() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        AtomicReference<String> result = new AtomicReference<>("Auto-analysis failed");

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Use AutoAnalysisManager as fallback
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                        ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);

                    if (mgr != null) {
                        AddressSet addrSet = new AddressSet(program.getMemory());
                        mgr.reAnalyzeAll(addrSet);
                        result.set("Auto-analysis triggered for entire program. Analysis is running in background.");
                    } else {
                        result.set("Could not get analysis manager");
                    }
                } catch (Exception e) {
                    result.set("Error triggering auto-analysis: " + e.getMessage());
                    Msg.error(this, "Error running auto-analysis", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to trigger auto-analysis on Swing thread: " + e.getMessage();
        }

        return result.get();
    }

    /**
     * Provide Ghidra scripting/analysis help reference
     * Returns guidance on how to accomplish common RE tasks in Ghidra
     */
    private String getGhidraHelp(String topic) {
        if (topic == null || topic.isEmpty()) {
            return getGhidraHelpTopics();
        }

        switch (topic.toLowerCase()) {
            case "xrefs":
            case "cross-references":
            case "references":
                return "=== Cross-References (XRefs) ===\n\n"
                    + "Cross-references show where code or data references other locations.\n\n"
                    + "Available MCP tools:\n"
                    + "- get_xrefs_to(address): Find all locations that reference a given address\n"
                    + "- get_xrefs_from(address): Find all locations referenced from a given address\n"
                    + "- get_function_xrefs(name): Find all callers of a function by name\n"
                    + "- get_callers(name): Get functions that call a given function\n"
                    + "- get_callees(name): Get functions called by a given function\n\n"
                    + "In Ghidra UI:\n"
                    + "- Right-click an address -> References -> Show References To\n"
                    + "- Window -> Function Call Graph for visual call graph\n"
                    + "- Right-click function -> References -> Find References To\n";

            case "functions":
            case "function":
                return "=== Functions ===\n\n"
                    + "Available MCP tools:\n"
                    + "- list_methods(): List all function names (paginated)\n"
                    + "- list_functions(): List all functions with addresses\n"
                    + "- search_functions_by_name(query): Search by substring\n"
                    + "- decompile_function(name): Get C pseudocode by name\n"
                    + "- decompile_function_by_address(addr): Get C pseudocode by address\n"
                    + "- disassemble_function(addr): Get assembly listing\n"
                    + "- get_function_by_address(addr): Get function info at address\n"
                    + "- get_function_variables(addr): Get all params and local vars\n"
                    + "- create_function(addr, name): Create function at address\n"
                    + "- delete_function(addr): Remove function definition\n"
                    + "- rename_function(old, new): Rename by name\n"
                    + "- rename_function_by_address(addr, name): Rename by address\n"
                    + "- set_function_prototype(addr, proto): Set full signature\n\n"
                    + "Tips:\n"
                    + "- Use decompile to understand function logic\n"
                    + "- Rename functions and variables for clarity\n"
                    + "- Set prototypes to fix calling conventions\n";

            case "types":
            case "datatypes":
            case "data types":
            case "structures":
            case "structs":
                return "=== Data Types & Structures ===\n\n"
                    + "Available MCP tools:\n"
                    + "- list_data_types(category): List all defined types\n"
                    + "- get_struct_fields(name): View structure layout\n"
                    + "- create_struct(name, size): Create a new structure\n"
                    + "- add_struct_field(struct, field, type, offset): Add field to struct\n"
                    + "- create_enum(name, size): Create a new enum\n"
                    + "- add_enum_member(enum, member, value): Add enum member\n"
                    + "- set_local_variable_type(func_addr, var, type): Change variable type\n\n"
                    + "Tips:\n"
                    + "- Create structs to model data layouts (network packets, file headers, etc.)\n"
                    + "- Use enums to label magic constants (flags, error codes, etc.)\n"
                    + "- After creating types, apply them to variables for cleaner decompilation\n";

            case "patching":
            case "patch":
                return "=== Binary Patching ===\n\n"
                    + "Available MCP tools:\n"
                    + "- patch_bytes(addr, hex): Write raw bytes\n"
                    + "- patch_instruction(addr, asm): Assemble and write instruction\n"
                    + "- nop_region(start, end): Fill with NOP instructions\n"
                    + "- get_bytes(addr, len): Read bytes at address\n"
                    + "- export_binary(path, format): Export patched binary\n"
                    + "- save_program(): Save changes to Ghidra project\n\n"
                    + "Tips:\n"
                    + "- Always read bytes before patching to save originals\n"
                    + "- Use 'original' format when exporting to preserve file structure\n"
                    + "- NOP out unwanted checks (e.g., license validation)\n"
                    + "- Patch conditional jumps to change control flow\n";

            case "navigation":
            case "nav":
                return "=== Navigation ===\n\n"
                    + "Available MCP tools:\n"
                    + "- get_current_address(): Get selected address in UI\n"
                    + "- get_current_function(): Get selected function in UI\n"
                    + "- goto_address(addr): Navigate UI to address\n"
                    + "- get_address_info(addr): Get detailed info about an address\n"
                    + "- set_bookmark(addr, category, comment): Mark interesting locations\n"
                    + "- list_bookmarks(): List all bookmarks\n\n"
                    + "Tips:\n"
                    + "- Use bookmarks to track analysis progress\n"
                    + "- Use goto_address to follow references\n"
                    + "- get_address_info gives a complete picture of any location\n";

            case "analysis":
            case "auto-analysis":
                return "=== Analysis ===\n\n"
                    + "Available MCP tools:\n"
                    + "- run_auto_analysis(): Re-run Ghidra's auto-analysis\n"
                    + "- get_program_info(): Get comprehensive binary metadata\n"
                    + "- search_memory(pattern): Find byte patterns\n"
                    + "- list_strings(filter): Find strings in the binary\n"
                    + "- list_imports(): View imported functions\n"
                    + "- list_exports(): View exported functions\n"
                    + "- list_segments(): View memory segments\n\n"
                    + "Tips:\n"
                    + "- Run auto-analysis after making significant changes\n"
                    + "- Start analysis by examining imports/exports and strings\n"
                    + "- Use memory search to find specific patterns or signatures\n";

            case "comments":
            case "annotations":
                return "=== Comments & Annotations ===\n\n"
                    + "Available MCP tools:\n"
                    + "- set_decompiler_comment(addr, comment): Add pre-comment (shown in decompiler)\n"
                    + "- set_disassembly_comment(addr, comment): Add EOL comment (shown in listing)\n"
                    + "- list_comments(type): List all comments, optionally filtered by type\n"
                    + "- rename_function(old, new): Annotate by renaming functions\n"
                    + "- rename_variable(func, old, new): Annotate by renaming variables\n"
                    + "- rename_data(addr, name): Rename data labels\n\n"
                    + "Comment types: eol, pre, post, plate, repeatable\n";

            case "search":
                return "=== Search ===\n\n"
                    + "Available MCP tools:\n"
                    + "- search_functions_by_name(query): Search function names\n"
                    + "- search_memory(pattern): Search for byte patterns (supports ?? wildcards)\n"
                    + "- list_strings(filter): Search string content\n\n"
                    + "Memory search pattern examples:\n"
                    + "- \"48 89 5C 24 08\" - Exact byte sequence\n"
                    + "- \"FF 15 ?? ?? ?? ??\" - Call [rip+??] pattern with wildcards\n"
                    + "- \"E8\" - Find all relative CALL instructions (x86)\n\n"
                    + "Tips:\n"
                    + "- Search for known patterns to find similar code\n"
                    + "- Use wildcards for instruction patterns with varying operands\n";

            default:
                return "Unknown help topic: " + topic + "\n\n" + getGhidraHelpTopics();
        }
    }

    /**
     * List all available help topics
     */
    private String getGhidraHelpTopics() {
        return "=== GhidraMCP Help ===\n\n"
            + "Available help topics:\n"
            + "- xrefs: Cross-references and call graph analysis\n"
            + "- functions: Function analysis and manipulation\n"
            + "- types: Data types, structures, and enums\n"
            + "- patching: Binary patching and export\n"
            + "- navigation: UI navigation and bookmarks\n"
            + "- analysis: Auto-analysis and program info\n"
            + "- comments: Comments and annotations\n"
            + "- search: Memory and function search\n\n"
            + "Usage: ghidra_help(topic='xrefs')\n\n"
            + "Typical RE workflow:\n"
            + "1. get_program_info() - Understand the binary\n"
            + "2. list_imports/exports/strings - Survey the attack surface\n"
            + "3. search_functions_by_name - Find interesting functions\n"
            + "4. decompile_function - Read pseudocode\n"
            + "5. get_callers/callees - Trace execution flow\n"
            + "6. rename_function/set_function_prototype - Annotate findings\n"
            + "7. set_bookmark - Mark important locations\n"
            + "8. create_struct - Model data structures\n"
            + "9. patch_bytes/patch_instruction - Modify behavior\n"
            + "10. export_binary - Save patched binary\n";
    }

    // ----------------------------------------------------------------------------------
    // ENHANCED RENAME & SEMI-AUTONOMOUS RE METHODS
    // ----------------------------------------------------------------------------------

    /**
     * Rename a variable within a function identified by address.
     * This is more reliable than by name when functions have auto-generated names.
     */
    private String renameVariableByAddress(String functionAddrStr, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionAddrStr == null || functionAddrStr.isEmpty()) return "Function address is required";
        if (oldVarName == null || oldVarName.isEmpty()) return "Old variable name is required";
        if (newVarName == null || newVarName.isEmpty()) return "New variable name is required";

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + functionAddrStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
            if (result == null || !result.decompileCompleted()) return "Decompilation failed";

            HighFunction highFunction = result.getHighFunction();
            if (highFunction == null) return "No high function available";

            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            if (localSymbolMap == null) return "No local symbol map";

            HighSymbol highSymbol = null;
            Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                if (symbol.getName().equals(oldVarName)) {
                    highSymbol = symbol;
                }
                if (symbol.getName().equals(newVarName)) {
                    return "Error: A variable with name '" + newVarName + "' already exists in this function";
                }
            }

            if (highSymbol == null) return "Variable '" + oldVarName + "' not found in function at " + functionAddrStr;

            boolean commitRequired = checkFullCommit(highSymbol, highFunction);
            final HighSymbol finalHighSymbol = highSymbol;
            AtomicBoolean successFlag = new AtomicBoolean(false);

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename variable by address");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol, newVarName, null, SourceType.USER_DEFINED);
                    successFlag.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Failed to rename variable by address", e);
                } finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });

            return successFlag.get()
                ? "Renamed '" + oldVarName + "' to '" + newVarName + "' in " + func.getName() + " @ " + functionAddrStr
                : "Failed to rename variable";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Batch rename multiple symbols. Accepts a JSON body with an array of rename operations.
     * Format: [{"type":"function","old_name":"FUN_001","new_name":"decrypt"},
     *          {"type":"variable","function_address":"0x401000","old_name":"local_8","new_name":"buffer"},
     *          {"type":"data","address":"0x402000","new_name":"g_key"}]
     */
    private String batchRename(String jsonBody) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (jsonBody == null || jsonBody.isEmpty()) return "JSON body is required";

        try {
            // Parse JSON array manually (avoid external deps)
            // Simple JSON array parser for the expected format
            List<Map<String, String>> operations = parseJsonArray(jsonBody);
            if (operations.isEmpty()) return "No operations found in JSON body";

            StringBuilder results = new StringBuilder();
            int successCount = 0;
            int failCount = 0;

            for (Map<String, String> op : operations) {
                String type = op.getOrDefault("type", "");
                String opResult;

                switch (type) {
                    case "function":
                        String oldName = op.get("old_name");
                        String newName = op.get("new_name");
                        boolean funcSuccess = renameFunction(oldName, newName);
                        opResult = funcSuccess
                            ? "OK: Renamed function '" + oldName + "' -> '" + newName + "'"
                            : "FAIL: Could not rename function '" + oldName + "'";
                        break;
                    case "function_by_address":
                        String funcAddr = op.get("address");
                        String funcNewName = op.get("new_name");
                        boolean addrSuccess = renameFunctionByAddress(funcAddr, funcNewName);
                        opResult = addrSuccess
                            ? "OK: Renamed function at " + funcAddr + " -> '" + funcNewName + "'"
                            : "FAIL: Could not rename function at " + funcAddr;
                        break;
                    case "variable":
                        String varFuncAddr = op.get("function_address");
                        String varOld = op.get("old_name");
                        String varNew = op.get("new_name");
                        opResult = renameVariableByAddress(varFuncAddr, varOld, varNew);
                        break;
                    case "data":
                        String dataAddr = op.get("address");
                        String dataName = op.get("new_name");
                        renameDataAtAddress(dataAddr, dataName);
                        opResult = "OK: Renamed data at " + dataAddr + " -> '" + dataName + "'";
                        break;
                    default:
                        opResult = "FAIL: Unknown operation type '" + type + "'";
                        break;
                }

                if (opResult.startsWith("OK") || opResult.startsWith("Renamed")) {
                    successCount++;
                } else {
                    failCount++;
                }
                results.append(opResult).append("\n");
            }

            results.append(String.format("\nBatch complete: %d succeeded, %d failed out of %d operations",
                successCount, failCount, operations.size()));
            return results.toString();
        } catch (Exception e) {
            return "Error processing batch rename: " + e.getMessage();
        }
    }

    /**
     * Simple JSON array parser for batch operations.
     * Parses an array of objects with string key-value pairs.
     */
    private List<Map<String, String>> parseJsonArray(String json) {
        List<Map<String, String>> result = new ArrayList<>();
        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) return result;

        // Remove outer brackets
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return result;

        // Split by }, { pattern to get individual objects
        int depth = 0;
        int start = 0;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') {
                depth--;
                if (depth == 0) {
                    String objStr = json.substring(start, i + 1).trim();
                    if (objStr.startsWith(",")) objStr = objStr.substring(1).trim();
                    Map<String, String> obj = parseJsonObject(objStr);
                    if (!obj.isEmpty()) result.add(obj);
                    start = i + 1;
                }
            }
        }
        return result;
    }

    /**
     * Simple JSON object parser for string key-value pairs.
     */
    private Map<String, String> parseJsonObject(String json) {
        Map<String, String> result = new HashMap<>();
        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) return result;

        json = json.substring(1, json.length() - 1).trim();

        // Match "key": "value" patterns
        int i = 0;
        while (i < json.length()) {
            // Find key
            int keyStart = json.indexOf('"', i);
            if (keyStart < 0) break;
            int keyEnd = json.indexOf('"', keyStart + 1);
            if (keyEnd < 0) break;
            String key = json.substring(keyStart + 1, keyEnd);

            // Find colon
            int colon = json.indexOf(':', keyEnd + 1);
            if (colon < 0) break;

            // Find value
            int valStart = json.indexOf('"', colon + 1);
            if (valStart < 0) break;
            int valEnd = valStart + 1;
            while (valEnd < json.length()) {
                if (json.charAt(valEnd) == '"' && json.charAt(valEnd - 1) != '\\') break;
                valEnd++;
            }
            if (valEnd >= json.length()) break;
            String value = json.substring(valStart + 1, valEnd);

            result.put(key, value);
            i = valEnd + 1;
        }
        return result;
    }

    /**
     * Get the complete call graph for a function - both callers and callees.
     * Supports multi-level depth for more comprehensive graphs.
     */
    private String getCallGraph(String functionName, int depth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";
        if (depth < 1) depth = 1;
        if (depth > 5) depth = 5; // Cap depth to prevent runaway

        Function targetFunc = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                targetFunc = f;
                break;
            }
        }
        if (targetFunc == null) return "Function not found: " + functionName;

        StringBuilder result = new StringBuilder();
        result.append("=== Call Graph for ").append(functionName)
              .append(" @ ").append(targetFunc.getEntryPoint()).append(" ===\n\n");

        // Callers (incoming)
        result.append("--- CALLERS (who calls ").append(functionName).append(") ---\n");
        Set<String> visited = new HashSet<>();
        collectCallers(program, targetFunc, result, visited, 0, depth);

        // Callees (outgoing)
        result.append("\n--- CALLEES (what ").append(functionName).append(" calls) ---\n");
        visited.clear();
        collectCallees(program, targetFunc, result, visited, 0, depth);

        return result.toString();
    }

    private void collectCallers(Program program, Function func, StringBuilder result,
                                Set<String> visited, int currentDepth, int maxDepth) {
        if (currentDepth >= maxDepth) return;
        String indent = "  ".repeat(currentDepth);

        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesTo(func.getEntryPoint());

        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    String key = caller.getName() + "@" + caller.getEntryPoint();
                    if (!visited.contains(key)) {
                        visited.add(key);
                        result.append(String.format("%s<- %s @ %s [%s]\n",
                            indent, caller.getName(), caller.getEntryPoint(),
                            ref.getReferenceType().getName()));
                        collectCallers(program, caller, result, visited, currentDepth + 1, maxDepth);
                    }
                }
            }
        }
    }

    private void collectCallees(Program program, Function func, StringBuilder result,
                                Set<String> visited, int currentDepth, int maxDepth) {
        if (currentDepth >= maxDepth) return;
        String indent = "  ".repeat(currentDepth);

        ReferenceManager refManager = program.getReferenceManager();
        AddressRangeIterator bodyRanges = func.getBody().getAddressRanges();

        while (bodyRanges.hasNext()) {
            AddressRange range = bodyRanges.next();
            Address addr = range.getMinAddress();
            while (addr != null && addr.compareTo(range.getMaxAddress()) <= 0) {
                Reference[] refsFrom = refManager.getReferencesFrom(addr);
                for (Reference ref : refsFrom) {
                    if (ref.getReferenceType().isCall()) {
                        Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (callee == null) {
                            callee = program.getFunctionManager().getFunctionContaining(ref.getToAddress());
                        }
                        if (callee != null) {
                            String key = callee.getName() + "@" + callee.getEntryPoint();
                            if (!visited.contains(key)) {
                                visited.add(key);
                                result.append(String.format("%s-> %s @ %s [%s]\n",
                                    indent, callee.getName(), callee.getEntryPoint(),
                                    ref.getReferenceType().getName()));
                                collectCallees(program, callee, result, visited, currentDepth + 1, maxDepth);
                            }
                        }
                    }
                }
                addr = addr.next();
            }
        }
    }

    /**
     * List functions with auto-generated names (FUN_, thunk_, entry, etc.)
     * that have not yet been meaningfully renamed by an analyst.
     */
    private String listUndefinedFunctions(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> undefinedFunctions = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // Check for auto-generated name patterns
            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_") ||
                name.startsWith("switchD_") || name.startsWith("caseD_") ||
                name.equals("entry") || name.startsWith("_") && name.contains("FUN_") ||
                func.getSymbol().getSource() == SourceType.DEFAULT ||
                func.getSymbol().getSource() == SourceType.ANALYSIS) {

                long bodySize = func.getBody().getNumAddresses();
                int paramCount = func.getParameterCount();
                String callerInfo = "";

                // Count callers
                ReferenceIterator refs = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
                int callerCount = 0;
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    if (ref.getReferenceType().isCall()) callerCount++;
                }

                undefinedFunctions.add(String.format("%s @ %s (size=%d, params=%d, callers=%d, source=%s)",
                    name, func.getEntryPoint(), bodySize, paramCount, callerCount,
                    func.getSymbol().getSource()));
            }
        }

        if (undefinedFunctions.isEmpty()) return "No undefined/auto-named functions found";

        String header = String.format("Found %d undefined/auto-named functions:\n", undefinedFunctions.size());
        return header + paginateList(undefinedFunctions, offset, limit);
    }

    /**
     * Get control flow graph information for a function including basic block count,
     * edges, and rough complexity metrics useful for triage.
     */
    private String getFunctionCfgInfo(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at address " + addressStr;

            // Decompile to get high-level info
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults decompResult = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            StringBuilder result = new StringBuilder();
            result.append("=== CFG Info for ").append(func.getName())
                  .append(" @ ").append(func.getEntryPoint()).append(" ===\n\n");

            // Basic function metrics
            long bodySize = func.getBody().getNumAddresses();
            result.append("Body size: ").append(bodySize).append(" bytes\n");

            // Count instructions and branches
            int instructionCount = 0;
            int branchCount = 0;
            int callCount = 0;
            Set<Address> branchTargets = new HashSet<>();

            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(func.getEntryPoint(), true);
            Address end = func.getBody().getMaxAddress();

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;
                instructionCount++;

                FlowType flowType = instr.getFlowType();
                if (flowType.isConditional()) {
                    branchCount++;
                    for (Address target : instr.getFlows()) {
                        branchTargets.add(target);
                    }
                }
                if (flowType.isCall()) {
                    callCount++;
                }
                if (flowType.isJump() && !flowType.isConditional()) {
                    for (Address target : instr.getFlows()) {
                        branchTargets.add(target);
                    }
                }
            }

            // Estimate basic blocks (branch targets + entry point = block leaders)
            branchTargets.add(func.getEntryPoint());
            int estimatedBlocks = branchTargets.size();

            result.append("Instructions: ").append(instructionCount).append("\n");
            result.append("Estimated basic blocks: ").append(estimatedBlocks).append("\n");
            result.append("Conditional branches: ").append(branchCount).append("\n");
            result.append("Function calls: ").append(callCount).append("\n");
            // Cyclomatic complexity approximation: E - N + 2P where P=1
            // Approximate as branches + 1
            int cyclomaticComplexity = branchCount + 1;
            result.append("Estimated cyclomatic complexity: ").append(cyclomaticComplexity).append("\n");

            // Parameters and locals
            result.append("Parameters: ").append(func.getParameterCount()).append("\n");
            result.append("Local variables: ").append(func.getLocalVariables().length).append("\n");
            result.append("Stack frame size: ").append(func.getStackFrame().getFrameSize()).append("\n");

            // Decompiled line count
            if (decompResult != null && decompResult.decompileCompleted() &&
                decompResult.getDecompiledFunction() != null) {
                String cCode = decompResult.getDecompiledFunction().getC();
                int lineCount = cCode.split("\n").length;
                result.append("Decompiled lines: ").append(lineCount).append("\n");
            }

            // Classify function complexity
            String complexity;
            if (cyclomaticComplexity <= 5) complexity = "Low";
            else if (cyclomaticComplexity <= 15) complexity = "Moderate";
            else if (cyclomaticComplexity <= 30) complexity = "High";
            else complexity = "Very High";
            result.append("Complexity class: ").append(complexity).append("\n");

            return result.toString();
        } catch (Exception e) {
            return "Error getting CFG info: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // PATCHING METHODS
    // ----------------------------------------------------------------------------------

    /**
     * Patch bytes at the specified address
     * @param addressStr The address to patch
     * @param hexBytes Hex string of bytes (e.g., "90 90 90" or "909090")
     */
    private String patchBytes(String addressStr, String hexBytes) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (hexBytes == null || hexBytes.isEmpty()) return "Bytes are required";

        // Parse hex string to byte array
        hexBytes = hexBytes.replaceAll("\\s+", ""); // Remove whitespace
        if (hexBytes.length() % 2 != 0) return "Invalid hex string (odd length)";
        
        byte[] bytes = new byte[hexBytes.length() / 2];
        try {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(hexBytes.substring(i * 2, i * 2 + 2), 16);
            }
        } catch (NumberFormatException e) {
            return "Invalid hex string: " + e.getMessage();
        }

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Patch bytes at " + addressStr);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Memory memory = program.getMemory();
                    
                    // Get original bytes for logging
                    byte[] original = new byte[bytes.length];
                    memory.getBytes(addr, original);
                    
                    // Clear existing code units at this location
                    Listing listing = program.getListing();
                    listing.clearCodeUnits(addr, addr.add(bytes.length - 1), false);
                    
                    // Write new bytes
                    memory.setBytes(addr, bytes);
                    
                    // Re-disassemble the patched area
                    ghidra.app.cmd.disassemble.DisassembleCommand disCmd = 
                        new ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true);
                    disCmd.applyTo(program, new ConsoleTaskMonitor());
                    
                    result.append(String.format("Patched %d bytes at %s\n", bytes.length, addr));
                    result.append(String.format("Original: %s\n", bytesToHex(original)));
                    result.append(String.format("New: %s", bytesToHex(bytes)));
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error patching bytes: ").append(e.getMessage());
                    Msg.error(this, "Error patching bytes", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute patch on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Patch with an assembly instruction
     * @param addressStr The address to patch
     * @param assembly The assembly instruction (e.g., "NOP" or "MOV EAX, 0x1")
     */
    private String patchInstruction(String addressStr, String assembly) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (assembly == null || assembly.isEmpty()) return "Assembly instruction is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Patch instruction at " + addressStr);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    
                    // Get the assembler for this program
                    Assembler assembler = Assemblers.getAssembler(program);
                    
                    // Get original instruction for logging
                    Instruction originalInstr = program.getListing().getInstructionAt(addr);
                    String originalStr = (originalInstr != null) ? originalInstr.toString() : "N/A";
                    int originalLen = (originalInstr != null) ? originalInstr.getLength() : 0;
                    
                    // Assemble the new instruction
                    byte[] assembled = assembler.assembleLine(addr, assembly);
                    
                    // Clear existing code units
                    Listing listing = program.getListing();
                    if (originalLen > 0) {
                        listing.clearCodeUnits(addr, addr.add(originalLen - 1), false);
                    }
                    
                    // Write assembled bytes
                    program.getMemory().setBytes(addr, assembled);
                    
                    // Re-disassemble
                    ghidra.app.cmd.disassemble.DisassembleCommand disCmd = 
                        new ghidra.app.cmd.disassemble.DisassembleCommand(addr, null, true);
                    disCmd.applyTo(program, new ConsoleTaskMonitor());
                    
                    result.append(String.format("Patched instruction at %s\n", addr));
                    result.append(String.format("Original: %s (%d bytes)\n", originalStr, originalLen));
                    result.append(String.format("New: %s (%d bytes)\n", assembly, assembled.length));
                    result.append(String.format("Bytes: %s", bytesToHex(assembled)));
                    
                    if (assembled.length < originalLen) {
                        result.append(String.format("\nWarning: New instruction is shorter. Consider NOPing %d remaining bytes.", 
                            originalLen - assembled.length));
                    }
                    
                    success.set(true);
                } catch (AssemblySyntaxException e) {
                    result.append("Assembly syntax error: ").append(e.getMessage());
                } catch (AssemblySemanticException e) {
                    result.append("Assembly semantic error: ").append(e.getMessage());
                } catch (Exception e) {
                    result.append("Error patching instruction: ").append(e.getMessage());
                    Msg.error(this, "Error patching instruction", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute patch on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * NOP out a region of code
     * @param startAddrStr Start address
     * @param endAddrStr End address (inclusive)
     */
    private String nopRegion(String startAddrStr, String endAddrStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startAddrStr == null || startAddrStr.isEmpty()) return "Start address is required";
        if (endAddrStr == null || endAddrStr.isEmpty()) return "End address is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("NOP region " + startAddrStr + " to " + endAddrStr);
                try {
                    Address startAddr = program.getAddressFactory().getAddress(startAddrStr);
                    Address endAddr = program.getAddressFactory().getAddress(endAddrStr);
                    
                    long length = endAddr.subtract(startAddr) + 1;
                    if (length <= 0 || length > 1024) {
                        result.append("Invalid range or too large (max 1024 bytes)");
                        return;
                    }
                    
                    // Create NOP bytes (0x90 for x86)
                    // TODO: Support other architectures' NOP instructions
                    byte nopByte = (byte) 0x90;
                    byte[] nops = new byte[(int) length];
                    java.util.Arrays.fill(nops, nopByte);
                    
                    // Clear existing code units
                    Listing listing = program.getListing();
                    listing.clearCodeUnits(startAddr, endAddr, false);
                    
                    // Write NOPs
                    program.getMemory().setBytes(startAddr, nops);
                    
                    // Re-disassemble
                    ghidra.app.cmd.disassemble.DisassembleCommand disCmd = 
                        new ghidra.app.cmd.disassemble.DisassembleCommand(startAddr, null, true);
                    disCmd.applyTo(program, new ConsoleTaskMonitor());
                    
                    result.append(String.format("NOPed %d bytes from %s to %s", length, startAddr, endAddr));
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error NOPing region: ").append(e.getMessage());
                    Msg.error(this, "Error NOPing region", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to execute NOP on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Get bytes at an address
     */
    private String getBytes(String addressStr, int length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (length <= 0 || length > 4096) return "Invalid length (1-4096)";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] bytes = new byte[length];
            program.getMemory().getBytes(addr, bytes);
            
            StringBuilder result = new StringBuilder();
            result.append(String.format("Bytes at %s (%d bytes):\n", addr, length));
            result.append(bytesToHex(bytes));
            result.append("\n\nASCII: ");
            for (byte b : bytes) {
                char c = (char) (b & 0xFF);
                result.append((c >= 32 && c < 127) ? c : '.');
            }
            return result.toString();
        } catch (Exception e) {
            return "Error getting bytes: " + e.getMessage();
        }
    }

    // ----------------------------------------------------------------------------------
    // EXPORT METHODS
    // ----------------------------------------------------------------------------------

    /**
     * Export the program to a binary file
     * @param outputPath Path to save the file
     * @param format Export format (null for original format)
     */
    private String exportBinary(String outputPath, String format) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (outputPath == null || outputPath.isEmpty()) return "Output path is required";

        try {
            File outputFile = new File(outputPath);
            
            // Get the appropriate exporter
            Exporter exporter;
            if (format == null || format.isEmpty() || format.equalsIgnoreCase("binary")) {
                exporter = new BinaryExporter();
            } else {
                // Try to find exporter by name
                exporter = findExporter(format);
                if (exporter == null) {
                    return "Unknown export format: " + format + ". Use /list_exporters to see available formats.";
                }
            }

            // Create address set for entire program
            AddressSet addrSet = new AddressSet(program.getMemory());
            
            // Export
            TaskMonitor monitor = new ConsoleTaskMonitor();
            boolean success = exporter.export(outputFile, program, addrSet, monitor);
            
            if (success) {
                return String.format("Exported to %s using %s exporter\nFile size: %d bytes", 
                    outputFile.getAbsolutePath(), 
                    exporter.getName(),
                    outputFile.length());
            } else {
                return "Export failed: " + exporter.getMessageLog().toString();
            }
        } catch (Exception e) {
            Msg.error(this, "Export error", e);
            return "Export error: " + e.getMessage();
        }
    }

    /**
     * Find an exporter by name
     */
    private Exporter findExporter(String format) {
        // Try common names
        String formatLower = format.toLowerCase();
        switch (formatLower) {
            case "original":
            case "elf":
            case "pe":
            case "native":
                return new ghidra.app.util.exporter.OriginalFileExporter();
            case "binary":
            case "bin":
            case "raw":
                return new BinaryExporter();
            case "hex":
            case "ihex":
            case "intelhex":
                return new ghidra.app.util.exporter.IntelHexExporter();
            case "ascii":
            case "txt":
            case "text":
                return new ghidra.app.util.exporter.AsciiExporter();
            default:
                return null;
        }
    }

    /**
     * List available exporters
     */
    private String listExporters() {
        StringBuilder result = new StringBuilder();
        result.append("Available export formats:\n");
        result.append("- original / elf / pe (RECOMMENDED: preserves original file format with patches)\n");
        result.append("- binary / raw (raw memory dump - may not be executable)\n");
        result.append("- hex / intelhex (Intel HEX format)\n");
        result.append("- ascii / txt (ASCII listing)\n");
        result.append("\nFor patched binaries, use 'original' format to preserve ELF/PE structure.");
        return result.toString();
    }

    /**
     * Save the current program to the Ghidra project
     */
    private String saveProgram() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        AtomicBoolean success = new AtomicBoolean(false);
        
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    program.save("Saved via GhidraMCP", new ConsoleTaskMonitor());
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error saving program", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Failed to save: " + e.getMessage();
        }

        return success.get() 
            ? "Program saved to Ghidra project: " + program.getName()
            : "Failed to save program";
    }

    /**
     * Convert bytes to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i] & 0xFF));
            if (i < bytes.length - 1) sb.append(" ");
        }
        return sb.toString();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
