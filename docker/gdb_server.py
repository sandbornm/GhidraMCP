#!/usr/bin/env python3
"""
HTTP API server for GDB dynamic analysis.
Runs inside the Docker container and accepts commands from the MCP bridge.
"""

import subprocess
import os
import signal
import tempfile
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from pathlib import Path

# Set up logging
LOG_DIR = Path("/analysis/logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_DIR / "gdb_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Tool call telemetry
TELEMETRY_FILE = LOG_DIR / "tool_calls.jsonl"

def log_tool_call(tool_name: str, params: dict, result: dict, duration_ms: float = None):
    """Log a tool call for telemetry."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": tool_name,
        "params": params,
        "success": "error" not in result,
        "duration_ms": duration_ms
    }
    try:
        with open(TELEMETRY_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to log telemetry: {e}")

app = Flask(__name__)

# Track running processes
running_processes = {}
BINS_DIR = Path("/analysis/bins")


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    # Check available QEMU emulators
    qemu_arches = []
    for arch in ["aarch64", "arm", "mips", "mipsel", "mips64", "mips64el", "ppc", "ppc64", "riscv64", "i386"]:
        if Path(f"/usr/bin/qemu-{arch}").exists() or Path(f"/usr/bin/qemu-{arch}-static").exists():
            qemu_arches.append(arch)
    
    return jsonify({
        "status": "ok",
        "platform": "linux/amd64",
        "qemu_architectures": qemu_arches,
        "note": "Use arch parameter to run non-x86 binaries"
    })


@app.route("/arch", methods=["POST"])
def check_arch():
    """Check the architecture of a binary and what emulator would be used."""
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    arch, qemu_cmd = detect_arch(binary_path)
    
    # Get detailed file info
    result = subprocess.run(["file", str(binary_path)], capture_output=True, text=True)
    
    return jsonify({
        "binary": str(binary_path),
        "architecture": arch,
        "emulator": qemu_cmd,
        "native": qemu_cmd is None,
        "file_info": result.stdout.strip()
    })


@app.route("/file_info", methods=["POST"])
def file_info():
    """Get comprehensive file information about a binary."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    result = {}
    
    # Basic file info
    file_result = subprocess.run(["file", "-b", str(binary_path)], capture_output=True, text=True)
    result["type"] = file_result.stdout.strip()
    
    # File size
    stat = binary_path.stat()
    result["size_bytes"] = stat.st_size
    result["size_human"] = f"{stat.st_size / 1024:.1f} KB" if stat.st_size < 1024*1024 else f"{stat.st_size / (1024*1024):.1f} MB"
    
    # MD5/SHA256 hash
    import hashlib
    with open(binary_path, "rb") as f:
        data_bytes = f.read()
        result["md5"] = hashlib.md5(data_bytes).hexdigest()
        result["sha256"] = hashlib.sha256(data_bytes).hexdigest()
    
    # Architecture detection
    arch, qemu = detect_arch(binary_path)
    result["architecture"] = arch
    result["emulator"] = qemu
    result["native_execution"] = qemu is None
    
    # Check if it's an ELF
    if data_bytes[:4] == b'\x7fELF':
        result["format"] = "ELF"
        result["is_elf"] = True
        
        # ELF class (32/64 bit)
        result["bits"] = 32 if data_bytes[4] == 1 else 64
        
        # Endianness
        result["endian"] = "little" if data_bytes[5] == 1 else "big"
        
        # ELF type
        elf_types = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
        elf_type = int.from_bytes(data_bytes[16:18], "little" if data_bytes[5] == 1 else "big")
        result["elf_type"] = elf_types.get(elf_type, f"UNKNOWN({elf_type})")
        result["is_pie"] = elf_type == 3  # DYN type = PIE or shared lib
    elif data_bytes[:2] == b'MZ':
        result["format"] = "PE"
        result["is_elf"] = False
    else:
        result["format"] = "unknown"
        result["is_elf"] = False
    
    duration = (time.time() - start) * 1000
    log_tool_call("file_info", {"binary": binary}, result, duration)
    
    return jsonify(result)


@app.route("/readelf", methods=["POST"])
def readelf_info():
    """Get ELF header and program header information."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    section = data.get("section", "all")  # all, headers, sections, symbols, dynamic, relocs
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    result = {"binary": str(binary_path)}
    
    flags_map = {
        "all": "-a",
        "headers": "-h",
        "sections": "-S",
        "symbols": "-s",
        "dynamic": "-d",
        "relocs": "-r",
        "program": "-l",
        "notes": "-n",
    }
    
    flag = flags_map.get(section, "-a")
    cmd_result = subprocess.run(["readelf", flag, str(binary_path)], capture_output=True, text=True)
    result["output"] = cmd_result.stdout
    if cmd_result.stderr:
        result["errors"] = cmd_result.stderr
    
    duration = (time.time() - start) * 1000
    log_tool_call("readelf", {"binary": binary, "section": section}, {"success": True}, duration)
    
    return jsonify(result)


@app.route("/sections", methods=["POST"])
def get_sections():
    """Get parsed section information from an ELF binary."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Parse readelf output
    cmd_result = subprocess.run(["readelf", "-S", "-W", str(binary_path)], capture_output=True, text=True)
    
    sections = []
    for line in cmd_result.stdout.split("\n"):
        # Parse section lines like: [ 1] .interp PROGBITS 0000000000400238 00000238 0000001c 00 A 0 0 1
        if line.strip().startswith("["):
            parts = line.split()
            if len(parts) >= 7:
                try:
                    sections.append({
                        "index": parts[0].strip("[]"),
                        "name": parts[1],
                        "type": parts[2] if len(parts) > 2 else "",
                        "address": parts[3] if len(parts) > 3 else "",
                        "offset": parts[4] if len(parts) > 4 else "",
                        "size": parts[5] if len(parts) > 5 else "",
                    })
                except:
                    pass
    
    result = {"binary": str(binary_path), "sections": sections, "count": len(sections)}
    
    duration = (time.time() - start) * 1000
    log_tool_call("sections", {"binary": binary}, {"count": len(sections)}, duration)
    
    return jsonify(result)


@app.route("/symbols", methods=["POST"])
def get_symbols():
    """Get symbol table from a binary."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    filter_type = data.get("filter")  # Optional: FUNC, OBJECT, etc.
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Use nm for symbol extraction
    cmd_result = subprocess.run(["nm", "-C", str(binary_path)], capture_output=True, text=True)
    
    symbols = []
    for line in cmd_result.stdout.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            addr, sym_type, name = parts[0], parts[1], " ".join(parts[2:])
            if not filter_type or sym_type.upper() == filter_type.upper():
                symbols.append({"address": addr, "type": sym_type, "name": name})
        elif len(parts) == 2:
            # Undefined symbols
            sym_type, name = parts[0], parts[1]
            if not filter_type or sym_type.upper() == filter_type.upper():
                symbols.append({"address": None, "type": sym_type, "name": name})
    
    result = {"binary": str(binary_path), "symbols": symbols[:500], "total": len(symbols)}  # Limit to 500
    if len(symbols) > 500:
        result["truncated"] = True
    
    duration = (time.time() - start) * 1000
    log_tool_call("symbols", {"binary": binary, "filter": filter_type}, {"count": len(symbols)}, duration)
    
    return jsonify(result)


@app.route("/entropy", methods=["POST"])
def analyze_entropy():
    """Analyze entropy of a binary to detect packing/encryption."""
    import time
    import math
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    block_size = data.get("block_size", 256)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    def calculate_entropy(data):
        if not data:
            return 0
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        return entropy
    
    with open(binary_path, "rb") as f:
        data_bytes = f.read()
    
    # Overall entropy
    overall_entropy = calculate_entropy(data_bytes)
    
    # Block-by-block entropy
    blocks = []
    for i in range(0, len(data_bytes), block_size):
        block = data_bytes[i:i+block_size]
        blocks.append(calculate_entropy(block))
    
    # Detect likely packing
    avg_entropy = sum(blocks) / len(blocks) if blocks else 0
    high_entropy_blocks = sum(1 for e in blocks if e > 7.0)
    high_entropy_ratio = high_entropy_blocks / len(blocks) if blocks else 0
    
    likely_packed = overall_entropy > 7.0 or high_entropy_ratio > 0.5
    
    result = {
        "binary": str(binary_path),
        "overall_entropy": round(overall_entropy, 4),
        "max_entropy": 8.0,
        "average_block_entropy": round(avg_entropy, 4),
        "high_entropy_blocks": high_entropy_blocks,
        "total_blocks": len(blocks),
        "high_entropy_ratio": round(high_entropy_ratio, 4),
        "likely_packed": likely_packed,
        "analysis": "HIGH - likely packed/encrypted" if likely_packed else "NORMAL - likely not packed"
    }
    
    duration = (time.time() - start) * 1000
    log_tool_call("entropy", {"binary": binary}, result, duration)
    
    return jsonify(result)


@app.route("/binwalk", methods=["POST"])
def binwalk_analyze():
    """Run binwalk to detect embedded files and signatures."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    extract = data.get("extract", False)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Run binwalk signature scan
    cmd = ["binwalk", str(binary_path)]
    if extract:
        cmd.insert(1, "-e")
    
    cmd_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    
    # Parse binwalk output
    signatures = []
    for line in cmd_result.stdout.split("\n"):
        if line.strip() and not line.startswith("DECIMAL") and not line.startswith("-"):
            parts = line.split(None, 2)
            if len(parts) >= 3:
                try:
                    signatures.append({
                        "offset_dec": int(parts[0]),
                        "offset_hex": parts[1],
                        "description": parts[2]
                    })
                except:
                    pass
    
    result = {
        "binary": str(binary_path),
        "signatures": signatures,
        "count": len(signatures),
        "raw_output": cmd_result.stdout
    }
    
    duration = (time.time() - start) * 1000
    log_tool_call("binwalk", {"binary": binary, "extract": extract}, {"count": len(signatures)}, duration)
    
    return jsonify(result)


@app.route("/hexdump", methods=["POST"])
def hexdump():
    """Get hex dump of a binary at a specific offset."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    offset = data.get("offset", 0)
    length = data.get("length", 256)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Limit length
    length = min(length, 4096)
    
    with open(binary_path, "rb") as f:
        f.seek(offset)
        data_bytes = f.read(length)
    
    # Format hex dump
    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset+i:08x}  {hex_part:<48}  |{ascii_part}|")
    
    result = {
        "binary": str(binary_path),
        "offset": offset,
        "length": len(data_bytes),
        "hex_dump": "\n".join(lines),
        "raw_hex": data_bytes.hex(),
    }
    
    duration = (time.time() - start) * 1000
    log_tool_call("hexdump", {"binary": binary, "offset": offset, "length": length}, {"bytes_read": len(data_bytes)}, duration)
    
    return jsonify(result)


@app.route("/imports", methods=["POST"])
def get_imports():
    """Get imported functions from a binary."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Use objdump to get dynamic relocations
    cmd_result = subprocess.run(
        ["objdump", "-T", str(binary_path)], 
        capture_output=True, text=True
    )
    
    imports = []
    for line in cmd_result.stdout.split("\n"):
        if "*UND*" in line:  # Undefined = imported
            parts = line.split()
            if parts:
                name = parts[-1]
                imports.append({"name": name, "type": "function"})
    
    result = {
        "binary": str(binary_path),
        "imports": imports,
        "count": len(imports)
    }
    
    duration = (time.time() - start) * 1000
    log_tool_call("imports", {"binary": binary}, {"count": len(imports)}, duration)
    
    return jsonify(result)


@app.route("/libs", methods=["POST"])
def get_libraries():
    """Get shared libraries required by a binary."""
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Use ldd or readelf to get libraries
    cmd_result = subprocess.run(
        ["readelf", "-d", str(binary_path)], 
        capture_output=True, text=True
    )
    
    libraries = []
    for line in cmd_result.stdout.split("\n"):
        if "NEEDED" in line:
            # Extract library name from: 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
            if "[" in line and "]" in line:
                lib = line[line.index("[")+1:line.index("]")]
                libraries.append(lib)
    
    result = {
        "binary": str(binary_path),
        "libraries": libraries,
        "count": len(libraries)
    }
    
    duration = (time.time() - start) * 1000
    log_tool_call("libs", {"binary": binary}, {"count": len(libraries)}, duration)
    
    return jsonify(result)


@app.route("/upload", methods=["POST"])
def upload_binary():
    """Upload a binary for analysis."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    filename = request.form.get("filename", file.filename)
    
    # Save to bins directory
    filepath = BINS_DIR / filename
    file.save(filepath)
    
    # Make executable
    os.chmod(filepath, 0o755)
    
    # Get file info
    result = subprocess.run(["file", str(filepath)], capture_output=True, text=True)
    
    return jsonify({
        "status": "uploaded",
        "path": str(filepath),
        "info": result.stdout.strip()
    })


@app.route("/list_bins", methods=["GET"])
def list_bins():
    """List uploaded binaries."""
    bins = []
    for f in BINS_DIR.iterdir():
        if f.is_file():
            result = subprocess.run(["file", str(f)], capture_output=True, text=True)
            bins.append({
                "name": f.name,
                "path": str(f),
                "info": result.stdout.strip()
            })
    return jsonify({"binaries": bins})


def detect_arch(binary_path: Path) -> tuple[str, str]:
    """Detect binary architecture and return (arch_name, qemu_command or None)."""
    result = subprocess.run(["file", str(binary_path)], capture_output=True, text=True)
    file_info = result.stdout.lower()
    
    # Map file output to QEMU emulator
    arch_map = {
        "arm aarch64": ("aarch64", "qemu-aarch64-static"),
        "arm,": ("arm", "qemu-arm-static"),
        "mips64": ("mips64", "qemu-mips64-static"),
        "mips,": ("mips", "qemu-mips-static"),
        "mipsel": ("mipsel", "qemu-mipsel-static"),
        "powerpc64": ("ppc64", "qemu-ppc64-static"),
        "powerpc": ("ppc", "qemu-ppc-static"),
        "riscv64": ("riscv64", "qemu-riscv64-static"),
        "x86-64": ("x86_64", None),  # Native
        "intel 80386": ("i386", None),  # Native via compat
        "i386": ("i386", None),
    }
    
    for pattern, (arch, qemu) in arch_map.items():
        if pattern in file_info:
            return arch, qemu
    
    return "unknown", None


@app.route("/run", methods=["POST"])
def run_binary():
    """Run a binary with optional arguments and input. Auto-detects architecture."""
    data = request.json or {}
    binary = data.get("binary")
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")
    timeout = data.get("timeout", 10)
    arch_override = data.get("arch")  # Optional: force specific architecture
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Detect or use override architecture
    if arch_override:
        arch = arch_override
        qemu_cmd = f"qemu-{arch}-static" if arch not in ["x86_64", "i386"] else None
    else:
        arch, qemu_cmd = detect_arch(binary_path)
    
    # Build command
    if qemu_cmd and Path(f"/usr/bin/{qemu_cmd}").exists():
        cmd = [f"/usr/bin/{qemu_cmd}", str(binary_path)] + args
    else:
        cmd = [str(binary_path)] + args
    
    try:
        result = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "architecture": arch,
            "emulated": qemu_cmd is not None
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout expired", "timeout": timeout, "architecture": arch})
    except Exception as e:
        return jsonify({"error": str(e), "architecture": arch})


@app.route("/gdb", methods=["POST"])
def gdb_command():
    """
    Run GDB commands on a binary.
    Accepts a list of GDB commands to execute.
    """
    data = request.json or {}
    binary = data.get("binary")
    commands = data.get("commands", [])
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Build GDB command file
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        *commands,
        "quit"
    ])
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_script)
        script_path = f.name
    
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", script_path, str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        return jsonify({
            "output": result.stdout + result.stderr,
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "GDB timeout"})
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        os.unlink(script_path)


@app.route("/gdb/breakpoint_run", methods=["POST"])
def gdb_breakpoint_run():
    """
    Run binary with breakpoints and capture state at each.
    """
    data = request.json or {}
    binary = data.get("binary")
    breakpoints = data.get("breakpoints", [])  # List of addresses or symbols
    stdin_input = data.get("stdin", "")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    # Build GDB commands
    commands = [
        "set pagination off",
        "set confirm off",
    ]
    
    for bp in breakpoints:
        commands.append(f"break *{bp}" if bp.startswith("0x") else f"break {bp}")
    
    commands.extend([
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "info registers",
        "x/20i $pc",
        "bt",
        "continue",
        "quit"
    ])
    
    gdb_script = "\n".join(commands)
    
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_script)
        script_path = f.name
    
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", script_path, str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        return jsonify({
            "output": result.stdout + result.stderr,
            "returncode": result.returncode
        })
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        os.unlink(script_path)


@app.route("/strace", methods=["POST"])
def strace_binary():
    """Run strace on a binary to capture system calls."""
    data = request.json or {}
    binary = data.get("binary")
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")
    timeout = data.get("timeout", 10)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    try:
        result = subprocess.run(
            ["strace", "-f", str(binary_path)] + args,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return jsonify({
            "stdout": result.stdout,
            "strace_output": result.stderr,  # strace outputs to stderr
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout expired"})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/ltrace", methods=["POST"])
def ltrace_binary():
    """Run ltrace on a binary to capture library calls."""
    data = request.json or {}
    binary = data.get("binary")
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")
    timeout = data.get("timeout", 10)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    try:
        result = subprocess.run(
            ["ltrace", "-f", str(binary_path)] + args,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return jsonify({
            "stdout": result.stdout,
            "ltrace_output": result.stderr,  # ltrace outputs to stderr
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout expired"})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/disassemble", methods=["POST"])
def disassemble():
    """Disassemble a function or address range using objdump."""
    data = request.json or {}
    binary = data.get("binary")
    symbol = data.get("symbol")  # Function name
    start_addr = data.get("start")  # Or start address
    end_addr = data.get("end")  # And end address
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    cmd = ["objdump", "-d", "-M", "intel"]
    
    if start_addr and end_addr:
        cmd.extend([f"--start-address={start_addr}", f"--end-address={end_addr}"])
    
    cmd.append(str(binary_path))
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = result.stdout
        
        # If symbol specified, filter to just that function
        if symbol:
            lines = output.split("\n")
            in_function = False
            filtered = []
            for line in lines:
                if f"<{symbol}>:" in line:
                    in_function = True
                elif in_function and line.strip() == "":
                    break
                if in_function:
                    filtered.append(line)
            output = "\n".join(filtered)
        
        return jsonify({"disassembly": output})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/strings", methods=["POST"])
def get_strings():
    """Extract strings from binary."""
    data = request.json or {}
    binary = data.get("binary")
    min_len = data.get("min_length", 4)
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    try:
        result = subprocess.run(
            ["strings", f"-n{min_len}", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        return jsonify({"strings": result.stdout.splitlines()})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/checksec", methods=["POST"])
def checksec():
    """Check binary security features (NX, PIE, RELRO, etc.)."""
    data = request.json or {}
    binary = data.get("binary")
    
    if not binary:
        return jsonify({"error": "No binary specified"}), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404
    
    # Use readelf to check security features
    try:
        # Check for NX (non-executable stack)
        result = subprocess.run(
            ["readelf", "-l", str(binary_path)],
            capture_output=True, text=True
        )
        nx_enabled = "GNU_STACK" in result.stdout and "RWE" not in result.stdout
        
        # Check for PIE
        result_type = subprocess.run(
            ["file", str(binary_path)],
            capture_output=True, text=True
        )
        pie_enabled = "pie executable" in result_type.stdout.lower() or "shared object" in result_type.stdout.lower()
        
        # Check for RELRO
        relro = "None"
        if "GNU_RELRO" in result.stdout:
            # Check for full RELRO (BIND_NOW)
            result_dyn = subprocess.run(
                ["readelf", "-d", str(binary_path)],
                capture_output=True, text=True
            )
            if "BIND_NOW" in result_dyn.stdout:
                relro = "Full"
            else:
                relro = "Partial"
        
        # Check for canary (stack protector)
        result_syms = subprocess.run(
            ["readelf", "-s", str(binary_path)],
            capture_output=True, text=True
        )
        canary = "__stack_chk_fail" in result_syms.stdout
        
        return jsonify({
            "binary": str(binary_path),
            "nx": nx_enabled,
            "pie": pie_enabled,
            "relro": relro,
            "canary": canary,
            "file_info": result_type.stdout.strip()
        })
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/logs", methods=["GET"])
def get_logs():
    """Get recent server logs."""
    lines = request.args.get("lines", 100, type=int)
    log_file = LOG_DIR / "gdb_server.log"
    
    if not log_file.exists():
        return jsonify({"logs": [], "message": "No logs yet"})
    
    try:
        with open(log_file) as f:
            all_lines = f.readlines()
        return jsonify({"logs": all_lines[-lines:]})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/telemetry", methods=["GET"])
def get_telemetry():
    """Get tool call telemetry."""
    lines = request.args.get("lines", 100, type=int)
    
    if not TELEMETRY_FILE.exists():
        return jsonify({"calls": [], "message": "No telemetry yet"})
    
    try:
        with open(TELEMETRY_FILE) as f:
            all_lines = f.readlines()
        calls = [json.loads(line) for line in all_lines[-lines:]]
        return jsonify({"calls": calls, "total": len(all_lines)})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/patch_elf", methods=["POST"])
def patch_elf():
    """
    Patch an ELF binary at a specific virtual address.
    This calculates the file offset and patches the original file.
    """
    import time
    start = time.time()
    
    data = request.json or {}
    binary = data.get("binary")
    address = data.get("address")  # Virtual address (hex string like "0x401000")
    hex_bytes = data.get("bytes")  # Hex string like "90 90 90"
    output_name = data.get("output")  # Optional: output filename
    
    logger.info(f"patch_elf called: binary={binary}, address={address}, bytes={hex_bytes}")
    
    if not all([binary, address, hex_bytes]):
        result = {"error": "Required: binary, address, bytes"}
        log_tool_call("patch_elf", data, result)
        return jsonify(result), 400
    
    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)
    
    if not binary_path.exists():
        result = {"error": f"Binary not found: {binary_path}"}
        log_tool_call("patch_elf", data, result)
        return jsonify(result), 404
    
    try:
        # Parse the virtual address
        vaddr = int(address, 16) if isinstance(address, str) else address
        
        # Parse hex bytes
        hex_bytes = hex_bytes.replace(" ", "")
        patch_bytes = bytes.fromhex(hex_bytes)
        
        # Use readelf to find the file offset for this virtual address
        result = subprocess.run(
            ["readelf", "-l", str(binary_path)],
            capture_output=True, text=True
        )
        
        # Parse program headers to find the segment containing our address
        file_offset = None
        for line in result.stdout.split("\n"):
            if "LOAD" in line:
                parts = line.split()
                if len(parts) >= 6:
                    try:
                        # Format: Type Offset VirtAddr PhysAddr FileSiz MemSiz Flg Align
                        seg_offset = int(parts[1], 16)
                        seg_vaddr = int(parts[2], 16)
                        seg_filesz = int(parts[4], 16)
                        
                        # Check if our address falls within this segment
                        if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
                            file_offset = seg_offset + (vaddr - seg_vaddr)
                            break
                    except (ValueError, IndexError):
                        continue
        
        if file_offset is None:
            result = {"error": f"Could not find file offset for virtual address {address}"}
            log_tool_call("patch_elf", data, result)
            return jsonify(result), 400
        
        # Create output file (copy of original)
        if output_name:
            output_path = BINS_DIR / output_name
        else:
            output_path = BINS_DIR / f"{binary_path.stem}_patched{binary_path.suffix}"
        
        # Copy original file
        import shutil
        shutil.copy2(binary_path, output_path)
        
        # Read original bytes for logging
        with open(output_path, "rb") as f:
            f.seek(file_offset)
            original_bytes = f.read(len(patch_bytes))
        
        # Apply patch
        with open(output_path, "r+b") as f:
            f.seek(file_offset)
            f.write(patch_bytes)
        
        # Make executable
        os.chmod(output_path, 0o755)
        
        duration = (time.time() - start) * 1000
        result = {
            "status": "patched",
            "output": str(output_path),
            "virtual_address": hex(vaddr),
            "file_offset": hex(file_offset),
            "original_bytes": original_bytes.hex(),
            "new_bytes": patch_bytes.hex(),
            "size": len(patch_bytes)
        }
        
        logger.info(f"Successfully patched {output_path} at offset {hex(file_offset)}")
        log_tool_call("patch_elf", data, result, duration)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error patching ELF: {e}")
        result = {"error": str(e)}
        log_tool_call("patch_elf", data, result)
        return jsonify(result), 500


if __name__ == "__main__":
    # Ensure directories exist
    BINS_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)
    
    logger.info("Starting GDB API server on port 5000...")
    logger.info(f"Binaries directory: {BINS_DIR}")
    logger.info(f"Logs directory: {LOG_DIR}")
    logger.info("Upload binaries to /analysis/bins or via POST /upload")
    
    app.run(host="0.0.0.0", port=5000, debug=False)
