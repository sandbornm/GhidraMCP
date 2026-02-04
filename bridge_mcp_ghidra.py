# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
import json
import time
import os
from urllib.parse import urljoin
from pathlib import Path

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
trajectory_recorder: TrajectoryRecorder = None

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
        response = requests.get(url, params=params, timeout=5)
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
            response = requests.post(url, data=data, timeout=5)
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
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


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

def gdb_request(endpoint: str, method: str = "GET", data: dict = None) -> dict:
    """Make a request to the GDB Docker container API."""
    url = urljoin(gdb_server_url, endpoint)
    try:
        if method == "GET":
            response = requests.get(url, timeout=30)
        else:
            response = requests.post(url, json=data, timeout=60)
        response.encoding = 'utf-8'
        if response.ok:
            return response.json()
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
        result = response.json()
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
        except:
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

