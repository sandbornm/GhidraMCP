# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import argparse
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

import requests
from mcp.server.fastmcp import FastMCP

# Import trajectory recorder
from trajectory_recorder import TrajectoryRecorder, analyze_trajectory, export_trajectory_markdown

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"
DEFAULT_GDB_SERVER = "http://127.0.0.1:5000/"
DEFAULT_TRAJECTORY_DIR = os.path.expanduser("~/Github/GhidraMCP/trajectories")

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize server URLs with default values
ghidra_server_url = DEFAULT_GHIDRA_SERVER
gdb_server_url = DEFAULT_GDB_SERVER

# Global trajectory recorder
trajectory_recorder: TrajectoryRecorder | None = None

def _record_call(tool_name: str, params: dict, result, duration_ms: float, success: bool = True):
    """Record a tool call to the trajectory if recording is active."""
    global trajectory_recorder
    if trajectory_recorder:
        trajectory_recorder.record(tool_name, params, result, duration_ms, success)


def recorded_tool(func):
    """Decorator that records tool calls to the trajectory."""
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        global trajectory_recorder
        start = time.time()
        success = True
        result = None

        try:
            result = func(*args, **kwargs)
            return result
        except Exception as e:
            success = False
            result = str(e)
            raise
        finally:
            if trajectory_recorder:
                duration_ms = (time.time() - start) * 1000
                _record_call(func.__name__, kwargs, result, duration_ms, success)
    return wrapper


def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=30)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]


def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
@recorded_tool
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
@recorded_tool
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
@recorded_tool
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
@recorded_tool
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
@recorded_tool
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
@recorded_tool
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
@recorded_tool
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
@recorded_tool
def get_program_name() -> str:
    """
    Get the name of the currently loaded program in Ghidra.
    """
    return "\n".join(safe_get("get_program_name"))

@mcp.tool()
@recorded_tool
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
@recorded_tool
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
@recorded_tool
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
@recorded_tool
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
@recorded_tool
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
@recorded_tool
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
@recorded_tool
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
@recorded_tool
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
@recorded_tool
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).

    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.

    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)

    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
@recorded_tool
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params: dict[str, int | str] = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


# =============================================================================
# ENHANCED ANALYSIS TOOLS (Call Graph, Function Management, etc.)
# =============================================================================

@mcp.tool()
@recorded_tool
def get_callers(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions that call the specified function (incoming call references).
    Useful for understanding who uses a function and tracing execution flow backward.

    Args:
        name: Function name to find callers for
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of calling functions with addresses and reference types
    """
    return safe_get("callers", {"name": name, "offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def get_callees(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all functions called by the specified function (outgoing call references).
    Useful for understanding what a function does and tracing execution flow forward.

    Args:
        name: Function name to find callees for
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of called functions with addresses and reference types
    """
    return safe_get("callees", {"name": name, "offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def get_function_variables(address: str) -> str:
    """
    Get all parameters and local variables for a function at the given address.
    Shows variable names, types, storage locations, and stack frame info.

    Args:
        address: Function address (e.g. "0x401000")

    Returns:
        Detailed listing of function parameters, local variables, and stack frame
    """
    return "\n".join(safe_get("get_function_variables", {"address": address}))


@mcp.tool()
@recorded_tool
def create_function(address: str, name: str = None) -> str:
    """
    Create a new function at the specified address. Useful when Ghidra's
    auto-analysis missed a function or incorrectly merged code.

    Args:
        address: Address where the function starts (e.g. "0x401000")
        name: Optional name for the new function

    Returns:
        Success or failure message
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)


@mcp.tool()
@recorded_tool
def delete_function(address: str) -> str:
    """
    Delete/remove a function definition at the specified address.
    The underlying code/data is preserved, only the function boundary is removed.

    Args:
        address: Address of the function to delete (e.g. "0x401000")

    Returns:
        Success or failure message
    """
    return safe_post("delete_function", {"address": address})


@mcp.tool()
@recorded_tool
def list_data_types(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all defined data types in the program (structures, enums, typedefs, etc.).

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)
        category: Optional category filter (e.g. "windows" to find Windows types)

    Returns:
        List of data types with their kind, size, and category path
    """
    params: dict[str, int | str] = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_data_types", params)


@mcp.tool()
@recorded_tool
def get_struct_fields(name: str) -> str:
    """
    Get the field layout of a structure data type.
    Shows each field's offset, size, type, and name.

    Args:
        name: Name of the structure

    Returns:
        Detailed structure layout with all fields
    """
    return "\n".join(safe_get("get_struct_fields", {"name": name}))


@mcp.tool()
@recorded_tool
def create_struct(name: str, size: int = 0, category: str = None) -> str:
    """
    Create a new structure data type. Use size=0 for a growable struct
    that expands as fields are added.

    Args:
        name: Name for the new structure
        size: Initial size in bytes (0 for growable)
        category: Optional category path (e.g. "/MyTypes")

    Returns:
        Success message with the created structure path

    Example:
        create_struct("NetworkPacket", 64)
        create_struct("FileHeader", 0, "/CustomTypes")
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    return safe_post("create_struct", data)


@mcp.tool()
@recorded_tool
def add_struct_field(struct_name: str, field_type: str, field_name: str = None, offset: int = -1, size: int = 0) -> str:
    """
    Add a field to an existing structure. Can append to the end or insert at a specific offset.

    Args:
        struct_name: Name of the structure to modify
        field_type: Data type of the field (e.g. "int", "char", "pointer", struct name)
        field_name: Optional name for the field
        offset: Byte offset to insert at (-1 to append at end)
        size: Override field size in bytes (0 to use type's natural size)

    Returns:
        Success message with field details

    Example:
        add_struct_field("MyStruct", "int", "flags")
        add_struct_field("MyStruct", "char", "name", offset=8, size=32)
    """
    data = {"struct_name": struct_name, "field_type": field_type}
    if field_name:
        data["field_name"] = field_name
    if offset >= 0:
        data["offset"] = str(offset)
    if size > 0:
        data["size"] = str(size)
    return safe_post("add_struct_field", data)


@mcp.tool()
@recorded_tool
def create_enum(name: str, size: int = 4, category: str = None) -> str:
    """
    Create a new enum data type. Enums are useful for labeling magic constants,
    flags, error codes, and other numeric values.

    Args:
        name: Name for the new enum
        size: Size in bytes (1, 2, 4, or 8; default: 4)
        category: Optional category path (e.g. "/MyTypes")

    Returns:
        Success message with the created enum path

    Example:
        create_enum("ErrorCode", 4)
        create_enum("Flags", 4, "/CustomTypes")
    """
    data = {"name": name, "size": str(size)}
    if category:
        data["category"] = category
    return safe_post("create_enum", data)


@mcp.tool()
@recorded_tool
def add_enum_member(enum_name: str, member_name: str, value: int) -> str:
    """
    Add a named member to an existing enum type.

    Args:
        enum_name: Name of the enum to modify
        member_name: Name for the new member
        value: Integer value for the member

    Returns:
        Success message with member details

    Example:
        add_enum_member("ErrorCode", "SUCCESS", 0)
        add_enum_member("ErrorCode", "INVALID_PARAM", -1)
        add_enum_member("Flags", "FLAG_READ", 1)
    """
    return safe_post("add_enum_member", {
        "enum_name": enum_name,
        "member_name": member_name,
        "value": str(value)
    })


@mcp.tool()
@recorded_tool
def set_bookmark(address: str, category: str = "Analysis", comment: str = "") -> str:
    """
    Set a bookmark at the specified address to track interesting locations.
    Bookmarks are visible in Ghidra's Bookmark window and persist in the project.

    Args:
        address: Address to bookmark (e.g. "0x401000")
        category: Bookmark category for organization (default: "Analysis")
        comment: Descriptive comment for the bookmark

    Returns:
        Confirmation message

    Example:
        set_bookmark("0x401000", "Vulnerability", "Potential buffer overflow")
        set_bookmark("0x402000", "Crypto", "AES key derivation")
    """
    return safe_post("set_bookmark", {
        "address": address,
        "category": category,
        "comment": comment
    })


@mcp.tool()
@recorded_tool
def list_bookmarks(offset: int = 0, limit: int = 100, category: str = None) -> list:
    """
    List all bookmarks in the program, optionally filtered by category.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)
        category: Optional category filter

    Returns:
        List of bookmarks with addresses, categories, and comments
    """
    params: dict[str, int | str] = {"offset": offset, "limit": limit}
    if category:
        params["category"] = category
    return safe_get("list_bookmarks", params)


@mcp.tool()
@recorded_tool
def delete_bookmark(address: str, category: str = None) -> str:
    """
    Delete bookmark(s) at the specified address.

    Args:
        address: Address of the bookmark(s) to delete
        category: Optional category filter (delete only bookmarks in this category)

    Returns:
        Confirmation message with number of bookmarks removed
    """
    data = {"address": address}
    if category:
        data["category"] = category
    return safe_post("delete_bookmark", data)


@mcp.tool()
@recorded_tool
def search_memory(pattern: str, max_results: int = 100) -> str:
    """
    Search program memory for a byte pattern. Supports wildcards with '??'.
    Useful for finding specific instruction patterns, signatures, or data.

    Args:
        pattern: Hex byte pattern (e.g. "48 89 5C 24 08" or "FF 15 ?? ?? ?? ??")
        max_results: Maximum number of matches to return (default: 100)

    Returns:
        List of addresses where the pattern was found

    Example:
        search_memory("48 89 5C 24 08")         # Exact byte sequence
        search_memory("FF 15 ?? ?? ?? ??")       # CALL [rip+??] with wildcards
        search_memory("E8 ?? ?? ?? ?? 85 C0")    # CALL followed by TEST EAX, EAX
    """
    return "\n".join(safe_get("search_memory", {"pattern": pattern, "max_results": max_results}))


@mcp.tool()
@recorded_tool
def get_address_info(address: str) -> str:
    """
    Get comprehensive information about what exists at a given address.
    Returns details about the memory block, function, instruction, data,
    symbols, comments, and cross-references at the address.

    Args:
        address: Address to inspect (e.g. "0x401000")

    Returns:
        Detailed multi-section report about the address
    """
    return "\n".join(safe_get("get_address_info", {"address": address}))


@mcp.tool()
@recorded_tool
def goto_address(address: str) -> str:
    """
    Navigate the Ghidra UI to the specified address. The listing view,
    decompiler, and other views will update to show the target address.

    Args:
        address: Address to navigate to (e.g. "0x401000")

    Returns:
        Confirmation message
    """
    return safe_post("goto_address", {"address": address})


@mcp.tool()
@recorded_tool
def get_program_info() -> str:
    """
    Get comprehensive metadata about the currently loaded program/binary.
    Includes architecture, format, hashes, memory layout, and statistics.

    Returns:
        Detailed program information including language, compiler, format,
        hashes, address ranges, function count, symbol count, etc.
    """
    return "\n".join(safe_get("get_program_info"))


@mcp.tool()
@recorded_tool
def list_comments(offset: int = 0, limit: int = 100, type: str = None) -> list:
    """
    List all comments in the program with their addresses and types.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)
        type: Optional comment type filter: "eol", "pre", "post", "plate", "repeatable"

    Returns:
        List of comments with addresses, types, containing functions
    """
    params: dict[str, int | str] = {"offset": offset, "limit": limit}
    if type:
        params["type"] = type
    return safe_get("list_comments", params)


@mcp.tool()
@recorded_tool
def run_auto_analysis() -> str:
    """
    Trigger Ghidra's auto-analysis on the entire program.
    Useful after making changes (creating functions, patching bytes) that
    may require re-analysis to update references and type propagation.

    Returns:
        Status message about the analysis
    """
    return "\n".join(safe_get("run_auto_analysis"))


@mcp.tool()
@recorded_tool
def ghidra_help(topic: str = None) -> str:
    """
    Get help and guidance on how to accomplish reverse engineering tasks
    with GhidraMCP. Lists available tools, tips, and typical workflows.

    Args:
        topic: Help topic - one of: "xrefs", "functions", "types", "patching",
               "navigation", "analysis", "comments", "search".
               Omit to see all topics and a typical RE workflow.

    Returns:
        Help text with available tools, tips, and examples
    """
    params = {}
    if topic:
        params["topic"] = topic
    return "\n".join(safe_get("ghidra_help", params))


# =============================================================================
# ENHANCED RENAME & SEMI-AUTONOMOUS RE TOOLS
# =============================================================================

@mcp.tool()
@recorded_tool
def rename_variable_by_address(function_address: str, old_name: str, new_name: str) -> str:
    """
    Rename a variable within a function identified by its address.
    More reliable than rename_variable when functions have auto-generated names
    (e.g., FUN_00401000) since the address is unambiguous.

    Args:
        function_address: Address of the function containing the variable (e.g. "0x401000")
        old_name: Current name of the variable to rename
        new_name: New name for the variable

    Returns:
        Success or failure message with details
    """
    return safe_post("rename_variable_by_address", {
        "function_address": function_address,
        "old_name": old_name,
        "new_name": new_name
    })


@mcp.tool()
@recorded_tool
def batch_rename(operations: str) -> str:
    """
    Rename multiple functions, variables, and data labels in a single batch operation.
    Useful for efficiently annotating a binary after initial analysis.

    Args:
        operations: JSON string containing an array of rename operations. Each operation
                    is an object with a "type" field and relevant parameters:

                    Function rename by name:
                      {"type": "function", "old_name": "FUN_001", "new_name": "decrypt_data"}

                    Function rename by address:
                      {"type": "function_by_address", "address": "0x401000", "new_name": "main"}

                    Variable rename (by function address):
                      {"type": "variable", "function_address": "0x401000",
                       "old_name": "local_8", "new_name": "buffer"}

                    Data label rename:
                      {"type": "data", "address": "0x402000", "new_name": "g_encryption_key"}

    Returns:
        Summary of results for each operation

    Example:
        batch_rename('[{"type":"function","old_name":"FUN_001","new_name":"decrypt"},{"type":"variable","function_address":"0x401000","old_name":"local_8","new_name":"key"}]')
    """
    return safe_post("batch_rename", operations)


@mcp.tool()
@recorded_tool
def get_call_graph(name: str, depth: int = 1) -> str:
    """
    Get the complete call graph for a function, showing both callers and callees.
    This provides a comprehensive view of a function's relationships in the binary.

    Args:
        name: Function name to get the call graph for
        depth: How many levels deep to traverse (1-5, default: 1).
               Higher depth gives a more complete picture but may be large.

    Returns:
        Call graph showing incoming callers and outgoing callees with addresses

    Example:
        get_call_graph("main", depth=2)  # Show 2 levels of calls
    """
    return "\n".join(safe_get("get_call_graph", {"name": name, "depth": depth}))


@mcp.tool()
@recorded_tool
def list_undefined_functions(offset: int = 0, limit: int = 100) -> list:
    """
    List functions that still have auto-generated names (FUN_*, thunk_*, etc.)
    and have not been renamed by an analyst. Useful for identifying functions
    that need analysis and for prioritizing reverse engineering work.

    Each result includes the function's body size, parameter count, caller count,
    and symbol source to help prioritize which functions to analyze first.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of undefined/auto-named functions with metadata for triage
    """
    return safe_get("list_undefined_functions", {"offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def get_function_cfg_info(address: str) -> str:
    """
    Get control flow graph metrics for a function including basic block count,
    branch count, call count, cyclomatic complexity, and other structural info.
    Useful for triaging functions and identifying complex code that may warrant
    deeper analysis (e.g., encryption routines, parsers, state machines).

    Args:
        address: Function address (e.g. "0x401000")

    Returns:
        Detailed CFG metrics including:
        - Body size and instruction count
        - Estimated basic blocks and branch count
        - Cyclomatic complexity estimate
        - Decompiled line count
        - Complexity classification (Low/Moderate/High/Very High)
    """
    return "\n".join(safe_get("get_function_cfg_info", {"address": address}))


# =============================================================================
# PATCHING TOOLS (Ghidra)
# =============================================================================

@mcp.tool()
@recorded_tool
def patch_bytes(address: str, hex_bytes: str) -> str:
    """
    Patch bytes at a specific address in the binary.

    Args:
        address: The address to patch (e.g., "0x401000")
        hex_bytes: Hex string of bytes to write (e.g., "90 90 90" or "909090")

    Returns:
        Result message with original and new bytes

    Example:
        patch_bytes("0x401000", "90 90 90")  # Write 3 NOP bytes
        patch_bytes("0x401000", "EB05")      # Write a short jump
    """
    return safe_post("patch_bytes", {"address": address, "bytes": hex_bytes})


@mcp.tool()
@recorded_tool
def patch_instruction(address: str, assembly: str) -> str:
    """
    Patch with an assembly instruction at the specified address.
    Uses Ghidra's assembler to convert the instruction to bytes.

    Args:
        address: The address to patch (e.g., "0x401000")
        assembly: Assembly instruction (e.g., "NOP", "MOV EAX, 0x1", "JMP 0x401050")

    Returns:
        Result message with original and new instruction

    Example:
        patch_instruction("0x401000", "NOP")
        patch_instruction("0x401000", "XOR EAX, EAX")
        patch_instruction("0x401000", "RET")
    """
    return safe_post("patch_instruction", {"address": address, "assembly": assembly})


@mcp.tool()
@recorded_tool
def nop_region(start_address: str, end_address: str) -> str:
    """
    NOP out a region of code (fill with NOP instructions).

    Args:
        start_address: Start address of the region
        end_address: End address of the region (inclusive)

    Returns:
        Result message indicating how many bytes were NOPed

    Example:
        nop_region("0x401000", "0x401005")  # NOP 6 bytes
    """
    return safe_post("nop_region", {"start_address": start_address, "end_address": end_address})


@mcp.tool()
@recorded_tool
def get_bytes(address: str, length: int = 16) -> str:
    """
    Read bytes at an address.

    Args:
        address: The address to read from
        length: Number of bytes to read (default: 16, max: 4096)

    Returns:
        Hex dump and ASCII representation of the bytes
    """
    return "\n".join(safe_get("get_bytes", {"address": address, "length": length}))


@mcp.tool()
@recorded_tool
def export_binary(output_path: str, format: str = "original") -> str:
    """
    Export the current (patched) program to a file.

    Args:
        output_path: Full path where to save the exported file
        format: Export format:
            - "original" (RECOMMENDED): preserves ELF/PE format with patches
            - "binary": raw memory dump (may not be executable)
            - "hex": Intel HEX format
            - "ascii": text listing

    Returns:
        Success message with file path and size

    Example:
        export_binary("/tmp/patched_binary", "original")  # Keeps ELF structure
    """
    return safe_post("export_binary", {"output_path": output_path, "format": format})


@mcp.tool()
@recorded_tool
def save_program() -> str:
    """
    Save the current program to the Ghidra project database.
    This persists all changes (renames, comments, patches) to the project.

    Returns:
        Success or failure message
    """
    return safe_post("save_program", {})


@mcp.tool()
@recorded_tool
def list_exporters() -> str:
    """
    List available export formats for exporting patched binaries.

    Returns:
        List of supported export formats
    """
    return "\n".join(safe_get("list_exporters"))


# =============================================================================
# DYNAMIC ANALYSIS TOOLS (Docker/GDB)
# =============================================================================

def gdb_request(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Make a request to the GDB Docker container API."""
    url = urljoin(gdb_server_url, endpoint)
    try:
        response = requests.get(url, timeout=30) if method == "GET" else requests.post(url, json=data, timeout=60)
        response.encoding = 'utf-8'
        if response.ok:
            return cast(dict[str, Any], response.json())
        else:
            return {"error": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to GDB server at {gdb_server_url}. Is the Docker container running?"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
@recorded_tool
def gdb_health() -> dict:
    """
    Check if the GDB Docker container is running and healthy.

    Returns:
        Status dict with platform info if healthy
    """
    return gdb_request("/health")


@mcp.tool()
@recorded_tool
def gdb_check_arch(binary: str) -> dict:
    """
    Check the architecture of a binary and what emulator will be used.

    Args:
        binary: Name of the binary to check

    Returns:
        Dict with architecture info:
        - architecture: Detected arch (x86_64, arm, aarch64, mips, etc.)
        - emulator: QEMU emulator that will be used (or None if native)
        - native: True if runs without emulation
        - file_info: Detailed file command output
    """
    return gdb_request("/arch", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_list_binaries() -> dict:
    """
    List all binaries uploaded to the GDB container for analysis.

    Returns:
        Dict with list of binaries and their file info
    """
    return gdb_request("/list_bins")


@mcp.tool()
@recorded_tool
def gdb_upload_binary(local_path: str, remote_name: str = None) -> dict:
    """
    Upload a binary from the local filesystem to the GDB container.

    Args:
        local_path: Path to the binary on the local system
        remote_name: Optional name for the binary in the container (defaults to filename)

    Returns:
        Upload status and file info
    """
    path = Path(local_path)
    if not path.exists():
        return {"error": f"File not found: {local_path}"}

    url = urljoin(gdb_server_url, "/upload")
    start = time.time()
    try:
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"filename": remote_name or path.name}
            response = requests.post(url, files=files, data=data, timeout=30)
        result = cast(dict[str, Any], response.json())
        # Record manually since we can't use decorator with file upload
        if trajectory_recorder:
            duration_ms = (time.time() - start) * 1000
            _record_call("gdb_upload_binary", {"local_path": local_path, "remote_name": remote_name}, result, duration_ms)
        return result
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
@recorded_tool
def gdb_run_binary(binary: str, args: list = None, stdin: str = "", timeout: int = 10, arch: str = None) -> dict:
    """
    Run a binary in the GDB container and capture its output.
    Auto-detects architecture and uses QEMU emulation for non-x86 binaries.

    Args:
        binary: Name of the binary (must be uploaded first)
        args: List of command line arguments
        stdin: Input to send to the binary's stdin
        timeout: Maximum execution time in seconds
        arch: Override architecture detection (aarch64, arm, mips, mipsel, etc.)

    Returns:
        Dict with stdout, stderr, return code, and architecture info

    Supported architectures (via QEMU emulation):
        - x86_64, i386 (native)
        - aarch64, arm (ARM 64-bit and 32-bit)
        - mips, mipsel, mips64, mips64el
        - ppc, ppc64 (PowerPC)
        - riscv64
    """
    data = {
        "binary": binary,
        "args": args or [],
        "stdin": stdin,
        "timeout": timeout
    }
    if arch:
        data["arch"] = arch
    return gdb_request("/run", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_execute(binary: str, commands: list) -> dict:
    """
    Execute GDB commands on a binary.

    Args:
        binary: Name of the binary to debug
        commands: List of GDB commands to execute (e.g., ["break main", "run", "info registers"])

    Returns:
        Dict with GDB output

    Example:
        gdb_execute("myprogram", ["break main", "run", "info registers", "bt"])
    """
    return gdb_request("/gdb", "POST", {
        "binary": binary,
        "commands": commands
    })


@mcp.tool()
@recorded_tool
def gdb_breakpoint_run(binary: str, breakpoints: list, stdin: str = "") -> dict:
    """
    Run a binary with breakpoints and capture register/stack state at each breakpoint.

    Args:
        binary: Name of the binary to debug
        breakpoints: List of breakpoint locations (addresses like "0x401000" or symbols like "main")
        stdin: Optional input for the program

    Returns:
        Dict with register state, disassembly at PC, and backtrace at each breakpoint
    """
    return gdb_request("/gdb/breakpoint_run", "POST", {
        "binary": binary,
        "breakpoints": breakpoints,
        "stdin": stdin
    })


@mcp.tool()
@recorded_tool
def gdb_strace(binary: str, args: list = None, stdin: str = "", timeout: int = 10) -> dict:
    """
    Run strace on a binary to capture all system calls.

    Args:
        binary: Name of the binary to trace
        args: Command line arguments
        stdin: Input for the program
        timeout: Maximum execution time

    Returns:
        Dict with program output and strace output showing all syscalls
    """
    return gdb_request("/strace", "POST", {
        "binary": binary,
        "args": args or [],
        "stdin": stdin,
        "timeout": timeout
    })


@mcp.tool()
@recorded_tool
def gdb_ltrace(binary: str, args: list = None, stdin: str = "", timeout: int = 10) -> dict:
    """
    Run ltrace on a binary to capture all library function calls.

    Args:
        binary: Name of the binary to trace
        args: Command line arguments
        stdin: Input for the program
        timeout: Maximum execution time

    Returns:
        Dict with program output and ltrace output showing all library calls
    """
    return gdb_request("/ltrace", "POST", {
        "binary": binary,
        "args": args or [],
        "stdin": stdin,
        "timeout": timeout
    })


@mcp.tool()
@recorded_tool
def gdb_checksec(binary: str) -> dict:
    """
    Check security features of a binary (NX, PIE, RELRO, Stack Canary).

    Args:
        binary: Name of the binary to check

    Returns:
        Dict with security feature status:
        - nx: True if non-executable stack is enabled
        - pie: True if Position Independent Executable
        - relro: "None", "Partial", or "Full" RELRO
        - canary: True if stack canary is present
    """
    return gdb_request("/checksec", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_disassemble(binary: str, symbol: str = None) -> dict:
    """
    Disassemble a binary or specific function using objdump.

    Args:
        binary: Name of the binary
        symbol: Optional function name to disassemble (if omitted, disassembles entire binary)

    Returns:
        Dict with disassembly in Intel syntax
    """
    return gdb_request("/disassemble", "POST", {
        "binary": binary,
        "symbol": symbol
    })


@mcp.tool()
@recorded_tool
def gdb_strings(binary: str, min_length: int = 4) -> dict:
    """
    Extract strings from a binary.

    Args:
        binary: Name of the binary
        min_length: Minimum string length (default: 4)

    Returns:
        Dict with list of strings found in the binary
    """
    return gdb_request("/strings", "POST", {
        "binary": binary,
        "min_length": min_length
    })


# =============================================================================
# BINARY ANALYSIS TOOLS (Docker)
# =============================================================================

@mcp.tool()
@recorded_tool
def gdb_file_info(binary: str) -> dict:
    """
    Get comprehensive file information about a binary.

    Args:
        binary: Name of the binary to analyze

    Returns:
        Dict with file type, size, hashes, architecture, format details
    """
    return gdb_request("/file_info", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_readelf(binary: str, section: str = "all") -> dict:
    """
    Get ELF header and structural information using readelf.

    Args:
        binary: Name of the binary to analyze
        section: What to show - "all", "headers", "sections", "symbols",
                 "dynamic", "relocs", "program", "notes"

    Returns:
        Dict with readelf output
    """
    return gdb_request("/readelf", "POST", {"binary": binary, "section": section})


@mcp.tool()
@recorded_tool
def gdb_sections(binary: str) -> dict:
    """
    Get parsed section information from an ELF binary.

    Args:
        binary: Name of the binary to analyze

    Returns:
        Dict with list of sections (name, type, address, size)
    """
    return gdb_request("/sections", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_symbols(binary: str, filter_type: str = None) -> dict:
    """
    Get symbol table from a binary.

    Args:
        binary: Name of the binary to analyze
        filter_type: Optional filter - "T" (text/code), "D" (data), "U" (undefined)

    Returns:
        Dict with list of symbols (address, type, name)
    """
    data = {"binary": binary}
    if filter_type:
        data["filter"] = filter_type
    return gdb_request("/symbols", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_entropy(binary: str, block_size: int = 256) -> dict:
    """
    Analyze entropy of a binary to detect packing/encryption.
    High entropy (>7.0) often indicates packed or encrypted content.

    Args:
        binary: Name of the binary to analyze
        block_size: Size of blocks for entropy calculation (default: 256)

    Returns:
        Dict with entropy values and packing likelihood analysis
    """
    return gdb_request("/entropy", "POST", {"binary": binary, "block_size": block_size})


@mcp.tool()
@recorded_tool
def gdb_binwalk(binary: str, extract: bool = False) -> dict:
    """
    Run binwalk to detect embedded files, signatures, and firmware components.

    Args:
        binary: Name of the binary to analyze
        extract: Whether to extract embedded files (default: False)

    Returns:
        Dict with detected signatures and their offsets
    """
    return gdb_request("/binwalk", "POST", {"binary": binary, "extract": extract})


@mcp.tool()
@recorded_tool
def gdb_hexdump(binary: str, offset: int = 0, length: int = 256) -> dict:
    """
    Get hex dump of a binary at a specific offset.

    Args:
        binary: Name of the binary
        offset: Byte offset to start from (default: 0)
        length: Number of bytes to dump (default: 256, max: 4096)

    Returns:
        Dict with formatted hex dump and raw hex
    """
    return gdb_request("/hexdump", "POST", {"binary": binary, "offset": offset, "length": length})


@mcp.tool()
@recorded_tool
def gdb_imports(binary: str) -> dict:
    """
    Get imported functions from a binary (dynamically linked).

    Args:
        binary: Name of the binary to analyze

    Returns:
        Dict with list of imported function names
    """
    return gdb_request("/imports", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_libs(binary: str) -> dict:
    """
    Get shared libraries required by a binary.

    Args:
        binary: Name of the binary to analyze

    Returns:
        Dict with list of required shared libraries
    """
    return gdb_request("/libs", "POST", {"binary": binary})


@mcp.tool()
@recorded_tool
def gdb_patch_elf(binary: str, address: str, hex_bytes: str, output: str = None) -> dict:
    """
    Patch an ELF binary at a virtual address, preserving the ELF structure.
    This calculates the file offset and patches the original file correctly.

    Args:
        binary: Name of the binary to patch
        address: Virtual address to patch (e.g., "0x401000")
        hex_bytes: Hex bytes to write (e.g., "90 90 90" or "EB05")
        output: Optional output filename (defaults to {binary}_patched)

    Returns:
        Dict with patch details including file offset and original/new bytes

    Example:
        gdb_patch_elf("myprogram", "0x401234", "EB 05")  # Patch JMP
    """
    data = {
        "binary": binary,
        "address": address,
        "bytes": hex_bytes
    }
    if output:
        data["output"] = output
    return gdb_request("/patch_elf", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_get_logs(lines: int = 100) -> dict:
    """
    Get recent GDB server logs for debugging.

    Args:
        lines: Number of recent log lines to retrieve (default: 100)

    Returns:
        Dict with log lines
    """
    return gdb_request(f"/logs?lines={lines}")


@mcp.tool()
@recorded_tool
def gdb_get_telemetry(lines: int = 100) -> dict:
    """
    Get tool call telemetry from the GDB server.
    Shows recent tool calls with timing and success/failure status.

    Args:
        lines: Number of recent entries to retrieve (default: 100)

    Returns:
        Dict with telemetry entries
    """
    return gdb_request(f"/telemetry?lines={lines}")


# =============================================================================
# ENHANCED DYNAMIC ANALYSIS TOOLS (Registers, Memory, Frida, etc.)
# =============================================================================

@mcp.tool()
@recorded_tool
def gdb_read_registers(binary: str, breakpoint: str = "main") -> dict:
    """
    Read all CPU registers at a breakpoint location during execution.
    Sets a breakpoint, runs the binary, and dumps the full register state
    including general-purpose, flags, segment, and floating-point registers.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        breakpoint: Location to break at before reading registers.
                    Can be a symbol name (e.g. "main", "encrypt") or
                    an address (e.g. "0x401000"). Default: "main"

    Returns:
        Dict with register names and their current values at the breakpoint,
        including general-purpose registers (rax, rbx, etc.), instruction
        pointer (rip), stack pointer (rsp), flags register (eflags), and
        any architecture-specific registers.

    Example:
        gdb_read_registers("crackme")
        gdb_read_registers("crackme", breakpoint="0x401234")
        gdb_read_registers("crackme", breakpoint="check_password")
    """
    return gdb_request("/gdb/registers", "POST", {
        "binary": binary,
        "breakpoint": breakpoint
    })


@mcp.tool()
@recorded_tool
def gdb_read_memory(binary: str, address: str, length: int = 64, format: str = "hex") -> dict:
    """
    Read memory at a specific address during binary execution.
    Runs the binary under GDB and reads memory contents at the target address.
    Supports multiple output formats for different analysis needs.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        address: Memory address to read from (e.g. "0x7fffffffe000", "$rsp",
                 "$rsp-0x20"). Supports GDB expressions and register references.
        length: Number of bytes to read (default: 64, max varies by server config)
        format: Output format for the memory dump:
                - "hex": Raw hex bytes with ASCII side panel (default)
                - "string": Interpret memory as a null-terminated string
                - "instructions": Disassemble memory as machine code instructions

    Returns:
        Dict with the memory contents in the requested format, the resolved
        address, and the number of bytes read.

    Example:
        gdb_read_memory("crackme", "0x404000", length=128)
        gdb_read_memory("crackme", "$rsp", length=256, format="hex")
        gdb_read_memory("crackme", "0x401000", length=64, format="instructions")
        gdb_read_memory("crackme", "$rdi", format="string")
    """
    return gdb_request("/gdb/memory", "POST", {
        "binary": binary,
        "address": address,
        "length": length,
        "format": format
    })


@mcp.tool()
@recorded_tool
def gdb_step_execution(binary: str, breakpoint: str = "main", command: str = "stepi", count: int = 1) -> dict:
    """
    Single-step through code execution and capture the register and instruction
    state after each step. Useful for tracing exact execution flow, understanding
    how data transforms through registers, and debugging at the instruction level.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        breakpoint: Location to break at before stepping. Can be a symbol name
                    or address (e.g. "main", "0x401000"). Default: "main"
        command: GDB step command to use:
                 - "stepi": Step one machine instruction, entering function calls
                 - "nexti": Step one machine instruction, stepping over calls
                 - "step": Step one source line, entering function calls
                 - "next": Step one source line, stepping over calls
        count: Number of steps to execute (default: 1). Each step captures the
               full register state and current instruction, so large counts
               may produce substantial output.

    Returns:
        Dict with an array of step results, each containing:
        - Register values after the step
        - Current instruction at the program counter
        - Step number in the sequence

    Example:
        gdb_step_execution("crackme", breakpoint="main", command="stepi", count=10)
        gdb_step_execution("crackme", breakpoint="0x401050", command="nexti", count=5)
        gdb_step_execution("crackme", breakpoint="check_password", command="step", count=3)
    """
    return gdb_request("/gdb/step", "POST", {
        "binary": binary,
        "breakpoint": breakpoint,
        "command": command,
        "count": count
    })


@mcp.tool()
@recorded_tool
def gdb_set_watchpoint(binary: str, expression: str, watch_type: str = "write", breakpoints: list = None) -> dict:
    """
    Set a hardware or software watchpoint to break when a memory location is
    accessed. Watchpoints are essential for tracking when and where specific
    variables or memory regions are read or modified during execution.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        expression: Memory expression to watch. Can be a variable name,
                    a dereferenced pointer, or a raw address cast:
                    - "my_variable"
                    - "*0x404060"
                    - "*(int*)0x7fffffffe100"
        watch_type: Type of memory access to watch for:
                    - "write": Break when the memory is written to (default)
                    - "read": Break when the memory is read from (rwatch)
                    - "access": Break on any read or write access (awatch)
        breakpoints: Optional list of breakpoints to set before running.
                     Useful for ensuring the program reaches a state where
                     the watched memory is valid. Default: None (runs from start)

    Returns:
        Dict with watchpoint hit information including the old and new values,
        the instruction that triggered the watchpoint, register state, and
        backtrace at the point of access.

    Example:
        gdb_set_watchpoint("crackme", "*0x404060", watch_type="write")
        gdb_set_watchpoint("crackme", "*(char*)0x7fffe100", watch_type="access")
        gdb_set_watchpoint("crackme", "password_buffer", watch_type="write",
                           breakpoints=["main"])
    """
    data: dict[str, Any] = {
        "binary": binary,
        "expression": expression,
        "watch_type": watch_type
    }
    if breakpoints is not None:
        data["breakpoints"] = breakpoints
    return gdb_request("/gdb/watchpoint", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_inspect_stack(binary: str, breakpoint: str = "main", depth: int = 20) -> dict:
    """
    Perform a full stack frame inspection at a breakpoint location.
    Captures the backtrace, stack memory dump, frame-local variables,
    and function arguments for comprehensive stack analysis.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        breakpoint: Location to break at before inspecting the stack.
                    Can be a symbol name or address. Default: "main"
        depth: Number of stack words/entries to dump from the stack pointer
               downward (default: 20). Controls how much raw stack memory
               is included in the output.

    Returns:
        Dict with:
        - backtrace: Full call stack with frame numbers, addresses, and symbols
        - stack_memory: Raw hex dump of stack contents from current RSP
        - frame_info: Current frame details including saved registers
        - local_variables: Variables in the current stack frame (if debug info available)

    Example:
        gdb_inspect_stack("crackme")
        gdb_inspect_stack("crackme", breakpoint="vulnerable_function", depth=50)
        gdb_inspect_stack("crackme", breakpoint="0x401234", depth=32)
    """
    return gdb_request("/gdb/stack", "POST", {
        "binary": binary,
        "breakpoint": breakpoint,
        "depth": depth
    })


@mcp.tool()
@recorded_tool
def gdb_analyze_heap(binary: str, breakpoint: str = None) -> dict:
    """
    Analyze the heap state of a running process using GEF (GDB Enhanced Features)
    commands. Provides detailed information about heap chunks, bins (fast, tcache,
    unsorted, small, large), and arena metadata. Essential for heap exploitation
    analysis and understanding dynamic memory usage patterns.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        breakpoint: Optional breakpoint to set before analyzing the heap.
                    If None, the analysis runs after the program's initial
                    allocations. Set to a specific location to inspect heap
                    state at a particular point in execution.

    Returns:
        Dict with heap analysis results including:
        - chunks: List of heap chunks with addresses, sizes, and flags
        - bins: State of fastbins, tcache bins, unsorted bin, small/large bins
        - arenas: Main arena and thread arena information
        - top_chunk: Address and size of the wilderness/top chunk

    Example:
        gdb_analyze_heap("crackme")
        gdb_analyze_heap("crackme", breakpoint="after_malloc")
        gdb_analyze_heap("crackme", breakpoint="0x401300")
    """
    data = {"binary": binary}
    if breakpoint is not None:
        data["breakpoint"] = breakpoint
    return gdb_request("/gdb/heap", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_got_plt(binary: str) -> dict:
    """
    Inspect the Global Offset Table (GOT) and Procedure Linkage Table (PLT)
    entries of a binary. Shows the resolved and unresolved addresses for
    dynamically linked functions. Critical for understanding dynamic linking,
    detecting GOT overwrites, and analyzing lazy binding behavior.

    Args:
        binary: Name of the binary to analyze (must be uploaded first)

    Returns:
        Dict with GOT and PLT entries including:
        - got_entries: List of GOT slots with addresses and resolved targets
        - plt_entries: List of PLT stubs with their corresponding GOT slots
        - relocation_info: Relocation records for dynamic symbols

    Example:
        gdb_got_plt("crackme")
    """
    return gdb_request("/got_plt", "POST", {
        "binary": binary
    })


@mcp.tool()
@recorded_tool
def gdb_rop_gadgets(binary: str, max_depth: int = 5, filter: str = None) -> dict:
    """
    Find Return-Oriented Programming (ROP) gadgets in a binary for exploit
    development. Searches for useful instruction sequences ending in RET,
    CALL, JMP, or SYSCALL instructions that can be chained together.

    Args:
        binary: Name of the binary to analyze (must be uploaded first)
        max_depth: Maximum number of instructions per gadget to search for
                   (default: 5). Higher values find longer gadgets but take
                   more time.
        filter: Optional regex or keyword filter to narrow results.
                Examples: "pop rdi", "syscall", "mov .*, .*; ret",
                "xor eax". If None, returns all discovered gadgets.

    Returns:
        Dict with:
        - gadgets: List of gadgets with addresses and instruction sequences
        - total_count: Total number of gadgets found
        - unique_count: Number of unique instruction sequences

    Example:
        gdb_rop_gadgets("crackme")
        gdb_rop_gadgets("crackme", max_depth=8, filter="pop rdi")
        gdb_rop_gadgets("crackme", filter="syscall")
    """
    data = {
        "binary": binary,
        "max_depth": max_depth
    }
    if filter is not None:
        data["filter"] = filter
    return gdb_request("/rop_gadgets", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_frida_instrument(binary: str, script: str, timeout: int = 10) -> dict:
    """
    Run a Frida instrumentation script on a binary for dynamic analysis.
    Frida allows injecting JavaScript into the target process for powerful
    runtime introspection, hooking, and modification capabilities.

    Args:
        binary: Name of the binary to instrument (must be uploaded first)
        script: Frida JavaScript instrumentation script to execute.
                The script has access to the full Frida API including
                Interceptor, Memory, Module, Process, and Thread objects.
        timeout: Maximum execution time in seconds (default: 10).
                 The process will be terminated after this timeout.

    Returns:
        Dict with:
        - output: Console output from the Frida script (send() messages)
        - program_output: stdout/stderr from the target binary
        - errors: Any errors encountered during instrumentation

    Example:
        gdb_frida_instrument("crackme",
            script='Interceptor.attach(Module.findExportByName(null, "strcmp"), {'
                   '  onEnter: function(args) {'
                   '    send("strcmp: " + args[0].readUtf8String() + " vs " + args[1].readUtf8String());'
                   '  }'
                   '});',
            timeout=15)
        gdb_frida_instrument("crackme",
            script='var base = Module.findBaseAddress("crackme");'
                   'send("Base address: " + base);'
                   'Memory.scan(base, 0x1000, "48 89 5C 24", {'
                   '  onMatch: function(addr, size) { send("Found at: " + addr); }'
                   '});')
    """
    return gdb_request("/frida/attach", "POST", {
        "binary": binary,
        "script": script,
        "timeout": timeout
    })


@mcp.tool()
@recorded_tool
def gdb_frida_trace(binary: str, functions: list, timeout: int = 10) -> dict:
    """
    Trace function calls in a binary using Frida. Automatically hooks the
    specified functions and logs every call with arguments and return values.
    Simpler than writing a full Frida script when you just need call tracing.

    Args:
        binary: Name of the binary to trace (must be uploaded first)
        functions: List of function names or addresses to trace.
                   Supports exported symbols (e.g. "malloc", "strcmp"),
                   module-qualified names (e.g. "libc.so!printf"),
                   and raw addresses (e.g. "0x401234").
        timeout: Maximum execution time in seconds (default: 10).
                 Tracing stops when the process exits or timeout is reached.

    Returns:
        Dict with:
        - traces: Ordered list of function call events with timestamps,
                  function name, arguments, and return values
        - call_counts: Summary of how many times each function was called
        - program_output: stdout/stderr from the target binary

    Example:
        gdb_frida_trace("crackme", functions=["strcmp", "strlen", "malloc"])
        gdb_frida_trace("crackme", functions=["0x401234", "encrypt", "decrypt"],
                        timeout=30)
        gdb_frida_trace("crackme", functions=["libc.so!write", "libc.so!read"])
    """
    return gdb_request("/frida/trace", "POST", {
        "binary": binary,
        "functions": functions,
        "timeout": timeout
    })


@mcp.tool()
@recorded_tool
def gdb_frida_hook(binary: str, target: str, on_enter: str = None, on_leave: str = None, timeout: int = 10) -> dict:
    """
    Hook and intercept a specific function call using Frida with custom
    onEnter and onLeave JavaScript callbacks. Provides fine-grained control
    over function interception, allowing argument inspection, modification,
    and return value manipulation.

    Args:
        binary: Name of the binary to hook (must be uploaded first)
        target: Function to hook. Can be an exported symbol name (e.g. "strcmp"),
                a module-qualified name (e.g. "libc.so!malloc"), or an address
                (e.g. "0x401234").
        on_enter: JavaScript code for the onEnter callback. Has access to the
                  'args' array (NativePointer[]) for reading/modifying arguments.
                  Use send() to emit data back. If None, a default logger is used.
        on_leave: JavaScript code for the onLeave callback. Has access to
                  'retval' (NativePointer) for reading/modifying the return value.
                  Use send() to emit data back. If None, a default logger is used.
        timeout: Maximum execution time in seconds (default: 10).

    Returns:
        Dict with:
        - messages: Data emitted by send() calls in the hook callbacks
        - program_output: stdout/stderr from the target binary
        - errors: Any errors from the hook execution

    Example:
        gdb_frida_hook("crackme", target="strcmp",
            on_enter='send("arg0=" + args[0].readUtf8String() + " arg1=" + args[1].readUtf8String());',
            on_leave='send("retval=" + retval.toInt32());')
        gdb_frida_hook("crackme", target="0x401234",
            on_enter='send("Called with: " + args[0] + ", " + args[1]);')
        gdb_frida_hook("crackme", target="malloc",
            on_enter='this.size = args[0].toInt32(); send("malloc(" + this.size + ")");',
            on_leave='send("  => " + retval);')
    """
    data = {
        "binary": binary,
        "target": target,
        "timeout": timeout
    }
    if on_enter is not None:
        data["on_enter"] = on_enter
    if on_leave is not None:
        data["on_leave"] = on_leave
    return gdb_request("/frida/hook", "POST", data)


@mcp.tool()
@recorded_tool
def gdb_vmmap(binary: str, breakpoint: str = "main") -> dict:
    """
    Get the virtual memory map of a running process. Shows all memory regions
    including code, data, heap, stack, shared libraries, and mapped files
    with their permissions and backing sources. Essential for understanding
    memory layout, finding writable/executable regions, and ASLR analysis.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        breakpoint: Location to break at before dumping the memory map.
                    Can be a symbol name or address. Default: "main"

    Returns:
        Dict with:
        - regions: List of memory regions, each containing:
          - start: Region start address
          - end: Region end address
          - permissions: rwxp permission string
          - offset: File offset for mapped files
          - path: Backing file path (if file-backed)
        - summary: Count of regions by type (code, data, stack, heap, etc.)

    Example:
        gdb_vmmap("crackme")
        gdb_vmmap("crackme", breakpoint="0x401234")
        gdb_vmmap("crackme", breakpoint="after_mmap")
    """
    return gdb_request("/gdb/vmmap", "POST", {
        "binary": binary,
        "breakpoint": breakpoint
    })


@mcp.tool()
@recorded_tool
def gdb_search_pattern(binary: str, pattern: str, breakpoint: str = "main", pattern_type: str = "string") -> dict:
    """
    Search for a pattern in the memory of a running process. Scans all readable
    memory regions for occurrences of the given pattern. Useful for finding
    strings, byte sequences, pointers, and data structures at runtime.

    Args:
        binary: Name of the binary to debug (must be uploaded first)
        pattern: The pattern to search for. Interpretation depends on pattern_type:
                 - For "string": a literal text string (e.g. "password", "FLAG{")
                 - For "hex": hex byte sequence (e.g. "deadbeef", "48 89 e5")
                 - For "pointer": an address value to find references to (e.g. "0x401000")
        breakpoint: Location to break at before searching. The search runs
                    against the process memory state at this point. Default: "main"
        pattern_type: How to interpret the pattern argument:
                      - "string": Search for UTF-8 string (default)
                      - "hex": Search for raw byte pattern
                      - "pointer": Search for pointer/address value

    Returns:
        Dict with:
        - matches: List of addresses where the pattern was found
        - regions: Which memory regions contained matches
        - count: Total number of matches found

    Example:
        gdb_search_pattern("crackme", "password", pattern_type="string")
        gdb_search_pattern("crackme", "deadbeef", pattern_type="hex")
        gdb_search_pattern("crackme", "0x401000", breakpoint="check_input",
                           pattern_type="pointer")
    """
    return gdb_request("/gdb/search_pattern", "POST", {
        "binary": binary,
        "pattern": pattern,
        "breakpoint": breakpoint,
        "pattern_type": pattern_type
    })


# =============================================================================
# TRAJECTORY RECORDING TOOLS
# =============================================================================

@mcp.tool()
def trajectory_start(binary_name: str = None, output_dir: str = None) -> dict:
    """
    Start recording a reverse engineering trajectory.
    Records all tool calls, results, and timing for later analysis.

    Args:
        binary_name: Name of the binary being analyzed. If not provided,
                     auto-detects from Ghidra's currently open program.
        output_dir: Optional directory for trajectory files (default: ~/Github/GhidraMCP/trajectories)

    Returns:
        Dict with session_id and output path

    Example:
        trajectory_start()              # Auto-detect binary name from Ghidra
        trajectory_start("my_sample")   # Explicit name
    """
    global trajectory_recorder

    if trajectory_recorder:
        return {"error": "Recording already active. Call trajectory_stop() first."}

    # Auto-detect binary name from Ghidra if not provided
    if not binary_name:
        try:
            response = requests.get(urljoin(ghidra_server_url, "get_program_name"), timeout=2)
            if response.ok and response.text.strip() != "No program loaded":
                binary_name = response.text.strip()
            else:
                binary_name = "unknown_binary"
        except Exception:
            binary_name = "unknown_binary"

    output = output_dir or DEFAULT_TRAJECTORY_DIR
    trajectory_recorder = TrajectoryRecorder(output_dir=output, binary_name=binary_name)

    return {
        "status": "recording_started",
        "session_id": trajectory_recorder.session_id,
        "binary": binary_name,
        "output_path": str(trajectory_recorder.get_session_path()),
        "note": "All tool calls will now be recorded. Call trajectory_stop() when done."
    }


@mcp.tool()
def trajectory_stop(summary: str = None) -> dict:
    """
    Stop recording the current trajectory session.

    Args:
        summary: Optional summary of the analysis session

    Returns:
        Dict with session info and path to trajectory file
    """
    global trajectory_recorder

    if not trajectory_recorder:
        return {"error": "No active recording session."}

    session_path = trajectory_recorder.get_session_path()
    session_id = trajectory_recorder.session_id
    trajectory_recorder.end_session(summary)
    trajectory_recorder = None

    return {
        "status": "recording_stopped",
        "session_id": session_id,
        "trajectory_path": str(session_path),
        "summary": summary,
    }


@mcp.tool()
def trajectory_note(note: str, category: str = "observation") -> dict:
    """
    Add a note or observation to the current trajectory.
    Useful for recording insights, hypotheses, or important findings.

    Args:
        note: The note text
        category: Category (observation, hypothesis, finding, question, todo)

    Returns:
        Confirmation of note added

    Example:
        trajectory_note("Function at 0x401000 appears to be the main decryption routine", "finding")
    """
    global trajectory_recorder

    if not trajectory_recorder:
        return {"error": "No active recording session. Call trajectory_start() first."}

    trajectory_recorder.add_note(note, category)
    return {"status": "note_added", "category": category, "note": note}


@mcp.tool()
def trajectory_status() -> dict:
    """
    Get the status of the current trajectory recording session.

    Returns:
        Dict with recording status, session info, and statistics
    """
    global trajectory_recorder

    if not trajectory_recorder:
        return {"recording": False, "message": "No active session"}

    return {
        "recording": True,
        "session_id": trajectory_recorder.session_id,
        "binary": trajectory_recorder.binary_name,
        "output_path": str(trajectory_recorder.get_session_path()),
        "started": trajectory_recorder.start_time.isoformat(),
    }


@mcp.tool()
def trajectory_analyze(trajectory_path: str) -> dict:
    """
    Analyze a completed trajectory file.

    Args:
        trajectory_path: Path to the .jsonl trajectory file

    Returns:
        Analysis including tool usage stats, patches applied, timeline, etc.
    """
    try:
        return analyze_trajectory(trajectory_path)
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def trajectory_export_markdown(trajectory_path: str, output_path: str = None) -> dict:
    """
    Export a trajectory as a readable Markdown document.

    Args:
        trajectory_path: Path to the .jsonl trajectory file
        output_path: Optional output path for the .md file

    Returns:
        Dict with markdown content or path to exported file
    """
    try:
        if output_path:
            export_trajectory_markdown(trajectory_path, output_path)
            return {"status": "exported", "output_path": output_path}
        else:
            md = export_trajectory_markdown(trajectory_path)
            return {"markdown": md}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def trajectory_list() -> dict:
    """
    List all recorded trajectory files.

    Returns:
        List of trajectory files with basic info
    """
    trajectory_dir = Path(DEFAULT_TRAJECTORY_DIR)
    if not trajectory_dir.exists():
        return {"trajectories": [], "directory": str(trajectory_dir)}

    trajectories = []
    for f in sorted(trajectory_dir.glob("*.jsonl"), reverse=True):
        try:
            # Read first line to get session info
            with open(f) as file:
                first_line = json.loads(file.readline())
            trajectories.append({
                "filename": f.name,
                "path": str(f),
                "session_id": first_line.get("session_id"),
                "binary": first_line.get("binary"),
                "timestamp": first_line.get("timestamp"),
                "size_kb": round(f.stat().st_size / 1024, 1),
            })
        except Exception:
            trajectories.append({"filename": f.name, "path": str(f), "error": "Could not parse"})

    return {"trajectories": trajectories, "directory": str(trajectory_dir)}


def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra + GDB dynamic analysis")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--gdb-server", type=str, default=DEFAULT_GDB_SERVER,
                        help=f"GDB Docker container URL, default: {DEFAULT_GDB_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()

    # Use global variables to ensure they're properly updated
    global ghidra_server_url, gdb_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    if args.gdb_server:
        gdb_server_url = args.gdb_server

    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()

if __name__ == "__main__":
    main()

