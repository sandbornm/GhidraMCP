#!/usr/bin/env python3
"""
HTTP API server for GDB dynamic analysis.
Runs inside the Docker container and accepts commands from the MCP bridge.
"""

import contextlib
import json
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request

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
        result["md5"] = hashlib.md5(data_bytes).hexdigest()  # noqa: S324
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
                with contextlib.suppress(BaseException):
                    sections.append({
                        "index": parts[0].strip("[]"),
                        "name": parts[1],
                        "type": parts[2] if len(parts) > 2 else "",
                        "address": parts[3] if len(parts) > 3 else "",
                        "offset": parts[4] if len(parts) > 4 else "",
                        "size": parts[5] if len(parts) > 5 else "",
                    })

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
    import math
    import time
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
                with contextlib.suppress(BaseException):
                    signatures.append({
                        "offset_dec": int(parts[0]),
                        "offset_hex": parts[1],
                        "description": parts[2]
                    })

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
        # Extract library name from: 0x0000000000000001 (NEEDED) Shared library: [libc.so.6]
        if "NEEDED" in line and "[" in line and "]" in line:
            lib = line[line.index("[") + 1:line.index("]")]
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
    os.chmod(filepath, 0o755)  # noqa: S103

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
            relro = "Full" if "BIND_NOW" in result_dyn.stdout else "Partial"

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
        os.chmod(output_path, 0o755)  # noqa: S103

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


# =============================================================================
# ENHANCED DYNAMIC ANALYSIS ENDPOINTS
# =============================================================================


@app.route("/gdb/registers", methods=["POST"])
def gdb_registers():
    """
    Read all registers for a binary at a specified breakpoint.
    Breaks at the given location, dumps general and extended registers,
    and returns a parsed register dictionary.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Build GDB script to break and dump registers
    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run",
        "info registers",
        "echo ===ALL_REGISTERS_SEPARATOR===\\n",
        "info registers all",
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

        raw_output = result.stdout + result.stderr

        # Parse registers into a dictionary
        registers = {}
        general_regs = {}
        all_regs = {}

        # Split on the separator to get general vs all registers
        parts = raw_output.split("===ALL_REGISTERS_SEPARATOR===")
        general_section = parts[0] if len(parts) > 0 else ""
        all_section = parts[1] if len(parts) > 1 else ""

        def parse_register_lines(text):
            regs = {}
            for line in text.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("Breakpoint") or line.startswith("["):
                    continue
                # Register lines typically look like: rax  0x555555555149  93824992235849
                tokens = line.split()
                if len(tokens) >= 2:
                    reg_name = tokens[0]
                    reg_value = tokens[1]
                    # Skip lines that don't look like register output
                    if reg_name.isalnum() or reg_name.startswith("$"):
                        regs[reg_name] = reg_value
            return regs

        general_regs = parse_register_lines(general_section)
        all_regs = parse_register_lines(all_section)

        # Merge: all_regs includes general, but general_regs is the clean set
        registers = {**all_regs, **general_regs}

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "breakpoint": breakpoint,
            "registers": registers,
            "general_registers": general_regs,
            "register_count": len(registers),
            "raw_output": raw_output
        }
        log_tool_call("gdb_registers", {"binary": binary, "breakpoint": breakpoint}, {"count": len(registers)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout while reading registers"}
        log_tool_call("gdb_registers", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_registers: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_registers", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/memory", methods=["POST"])
def gdb_memory():
    """
    Read memory at a given address using GDB's x/ command.
    Supports hex, string, and instruction formats.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    address = data.get("address")
    length = data.get("length", 64)
    fmt = data.get("format", "hex")
    breakpoint = data.get("breakpoint", "main")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not address:
        return jsonify({"error": "No address specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Map format to GDB x/ format character
    format_map = {
        "hex": "x",
        "string": "s",
        "instructions": "i",
        "bytes": "b",
        "words": "w",
        "giant": "g",
        "decimal": "d",
        "char": "c",
    }

    gdb_fmt = format_map.get(fmt, "x")

    # Build the x/ command
    if fmt == "string":
        examine_cmd = f"x/s {address}"
    elif fmt == "instructions":
        examine_cmd = f"x/{length}i {address}"
    else:
        examine_cmd = f"x/{length}{gdb_fmt}b {address}"

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run",
        examine_cmd,
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

        raw_output = result.stdout + result.stderr

        # Parse the memory output
        memory_lines = []
        for line in raw_output.strip().split("\n"):
            line = line.strip()
            # Memory output lines typically start with 0x
            if line.startswith("0x") and ":" in line:
                memory_lines.append(line)

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "address": address,
            "length": length,
            "format": fmt,
            "memory": memory_lines,
            "raw_output": raw_output
        }
        log_tool_call("gdb_memory", {"binary": binary, "address": address, "length": length, "format": fmt}, {"lines": len(memory_lines)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout while reading memory"}
        log_tool_call("gdb_memory", {"binary": binary, "address": address}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_memory: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_memory", {"binary": binary, "address": address}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/step", methods=["POST"])
def gdb_step():
    """
    Execute step/next/stepi/nexti commands from a breakpoint.
    Returns register state and disassembly after stepping.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")
    command = data.get("command", "stepi")
    count = data.get("count", 1)

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Validate step command
    valid_commands = ["step", "next", "stepi", "nexti", "si", "ni", "s", "n"]
    if command not in valid_commands:
        return jsonify({"error": f"Invalid step command: {command}. Valid: {valid_commands}"}), 400

    # Clamp count to reasonable range
    count = max(1, min(count, 1000))

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"

    # Build step commands with intermediate state capture
    step_commands = []
    for i in range(count):
        step_commands.append(command)
        # Capture state at each step
        step_commands.append(f"echo ===STEP_{i}===\\n")
        step_commands.append("info registers")
        step_commands.append("x/3i $pc")

    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run",
        "echo ===INITIAL_STATE===\\n",
        "info registers",
        "x/5i $pc",
        *step_commands,
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
            timeout=60
        )

        raw_output = result.stdout + result.stderr

        # Parse steps from output
        steps = []
        parts = raw_output.split("===STEP_")
        for part in parts[1:]:  # Skip everything before first step marker
            step_num_end = part.find("===")
            if step_num_end == -1:
                continue
            step_num = part[:step_num_end]
            step_content = part[step_num_end + 3:]

            # Parse register values from this step
            regs = {}
            disasm_lines = []
            for line in step_content.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("[") or line.startswith("Breakpoint"):
                    continue
                # Disassembly lines contain => or start with 0x and have <
                if "=>" in line or (line.startswith("0x") and ":" in line and ("<" in line or "\t" in line)):
                    disasm_lines.append(line)
                else:
                    tokens = line.split()
                    if len(tokens) >= 2 and (tokens[0].isalnum() or tokens[0].startswith("$")):
                        regs[tokens[0]] = tokens[1]

            steps.append({
                "step": int(step_num) if step_num.isdigit() else step_num,
                "registers": regs,
                "disassembly": disasm_lines
            })

        # Extract initial state
        initial_state = ""
        if "===INITIAL_STATE===" in raw_output:
            initial_part = raw_output.split("===INITIAL_STATE===")[1]
            if "===STEP_" in initial_part:
                initial_state = initial_part.split("===STEP_")[0].strip()
            else:
                initial_state = initial_part.strip()

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "breakpoint": breakpoint,
            "command": command,
            "count": count,
            "steps": steps,
            "total_steps_executed": len(steps),
            "initial_state": initial_state,
            "raw_output": raw_output
        }
        log_tool_call("gdb_step", {"binary": binary, "breakpoint": breakpoint, "command": command, "count": count}, {"steps": len(steps)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout during stepping"}
        log_tool_call("gdb_step", {"binary": binary, "command": command}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_step: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_step", {"binary": binary, "command": command}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/watchpoint", methods=["POST"])
def gdb_watchpoint():
    """
    Set a watchpoint on an expression and run until it triggers.
    Supports write, read, and access watchpoints.
    Returns the program state when the watchpoint fires.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    expression = data.get("expression")
    wp_type = data.get("type", "write")
    breakpoints = data.get("breakpoints", ["main"])
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not expression:
        return jsonify({"error": "No watchpoint expression specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Map watchpoint type to GDB command
    wp_commands = {
        "write": "watch",
        "read": "rwatch",
        "access": "awatch",
    }

    wp_cmd = wp_commands.get(wp_type, "watch")

    # Build breakpoint commands - we set breakpoints first so we can set
    # watchpoints after the program has started (needed for data watchpoints)
    bp_cmds = []
    for bp in breakpoints:
        bp_cmds.append(f"break *{bp}" if bp.startswith("0x") else f"break {bp}")

    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        *bp_cmds,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        f"{wp_cmd} {expression}",
        "continue",
        "echo ===WATCHPOINT_HIT===\\n",
        "info registers",
        "echo ===BACKTRACE===\\n",
        "bt",
        "echo ===DISASSEMBLY===\\n",
        "x/10i $pc",
        "echo ===WATCH_VALUE===\\n",
        f"print {expression}",
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

        raw_output = result.stdout + result.stderr

        # Parse sections from the output
        registers = {}
        backtrace = ""
        disassembly = ""
        watch_value = ""
        watchpoint_hit = "===WATCHPOINT_HIT===" in raw_output

        if watchpoint_hit:
            sections = raw_output.split("===WATCHPOINT_HIT===")
            post_hit = sections[1] if len(sections) > 1 else ""

            # Parse registers
            if "===BACKTRACE===" in post_hit:
                reg_section = post_hit.split("===BACKTRACE===")[0]
                for line in reg_section.strip().split("\n"):
                    tokens = line.strip().split()
                    if len(tokens) >= 2 and (tokens[0].isalnum() or tokens[0].startswith("$")):
                        registers[tokens[0]] = tokens[1]

            # Parse backtrace
            if "===BACKTRACE===" in post_hit and "===DISASSEMBLY===" in post_hit:
                backtrace = post_hit.split("===BACKTRACE===")[1].split("===DISASSEMBLY===")[0].strip()

            # Parse disassembly
            if "===DISASSEMBLY===" in post_hit and "===WATCH_VALUE===" in post_hit:
                disassembly = post_hit.split("===DISASSEMBLY===")[1].split("===WATCH_VALUE===")[0].strip()

            # Parse watch value
            if "===WATCH_VALUE===" in post_hit:
                watch_value = post_hit.split("===WATCH_VALUE===")[1].strip()

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "expression": expression,
            "type": wp_type,
            "watchpoint_triggered": watchpoint_hit,
            "registers": registers,
            "backtrace": backtrace,
            "disassembly": disassembly,
            "watch_value": watch_value,
            "raw_output": raw_output
        }
        log_tool_call("gdb_watchpoint", {"binary": binary, "expression": expression, "type": wp_type}, {"triggered": watchpoint_hit}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout waiting for watchpoint"}
        log_tool_call("gdb_watchpoint", {"binary": binary, "expression": expression}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_watchpoint: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_watchpoint", {"binary": binary, "expression": expression}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/stack", methods=["POST"])
def gdb_stack():
    """
    Full stack inspection at a breakpoint.
    Returns backtrace, stack memory dump, and frame info.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")
    depth = data.get("depth", 20)
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Clamp depth
    depth = max(1, min(depth, 100))

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===BACKTRACE===\\n",
        f"bt {depth}",
        "echo ===FRAME_INFO===\\n",
        "info frame",
        "echo ===LOCALS===\\n",
        "info locals",
        "echo ===ARGS===\\n",
        "info args",
        "echo ===STACK_MEMORY===\\n",
        "x/32gx $sp",
        "echo ===REGISTERS===\\n",
        "info registers rsp rbp rip",
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

        raw_output = result.stdout + result.stderr

        # Parse sections
        def extract_section(output, start_marker, end_marker=None):
            if start_marker not in output:
                return ""
            section = output.split(start_marker)[1]
            if end_marker and end_marker in section:
                section = section.split(end_marker)[0]
            return section.strip()

        backtrace = extract_section(raw_output, "===BACKTRACE===", "===FRAME_INFO===")
        frame_info = extract_section(raw_output, "===FRAME_INFO===", "===LOCALS===")
        locals_info = extract_section(raw_output, "===LOCALS===", "===ARGS===")
        args_info = extract_section(raw_output, "===ARGS===", "===STACK_MEMORY===")
        stack_memory = extract_section(raw_output, "===STACK_MEMORY===", "===REGISTERS===")
        registers = extract_section(raw_output, "===REGISTERS===")

        # Parse backtrace into structured frames
        frames = []
        for line in backtrace.split("\n"):
            line = line.strip()
            if line.startswith("#"):
                frames.append(line)

        # Parse stack memory into structured format
        stack_entries = []
        for line in stack_memory.split("\n"):
            line = line.strip()
            if line.startswith("0x") and ":" in line:
                stack_entries.append(line)

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "breakpoint": breakpoint,
            "backtrace": backtrace,
            "frames": frames,
            "frame_count": len(frames),
            "frame_info": frame_info,
            "locals": locals_info,
            "args": args_info,
            "stack_memory": stack_entries,
            "registers": registers,
            "raw_output": raw_output
        }
        log_tool_call("gdb_stack", {"binary": binary, "breakpoint": breakpoint, "depth": depth}, {"frames": len(frames)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout during stack inspection"}
        log_tool_call("gdb_stack", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_stack: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_stack", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/heap", methods=["POST"])
def gdb_heap():
    """
    Heap analysis using GEF (GDB Enhanced Features).
    Runs GEF's heap chunks and heap bins commands to inspect heap state.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"

    # Try GEF commands first; fall back to manual heap inspection
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===HEAP_CHUNKS===\\n",
        "heap chunks",
        "echo ===HEAP_BINS===\\n",
        "heap bins",
        "echo ===HEAP_ARENA===\\n",
        "heap arenas",
        "echo ===MALLOC_INFO===\\n",
        "info proc mappings",
        "quit"
    ])

    # Fallback script without GEF commands
    gdb_script_fallback = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===HEAP_INFO===\\n",
        "info proc mappings",
        "echo ===MALLOC_STATE===\\n",
        "print (int)mallinfo()",
        "echo ===HEAP_MEMORY===\\n",
        "x/64gx &__malloc_hook",
        "quit"
    ])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_script)
        script_path = f.name

    fallback_path = None
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", script_path, str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        raw_output = result.stdout + result.stderr
        used_gef = True

        # If GEF commands failed, try fallback
        if "Undefined command" in raw_output or "No symbol" in raw_output:
            used_gef = False
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_script_fallback)
                fallback_path = f.name

            result = subprocess.run(
                ["gdb", "-batch", "-x", fallback_path, str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            raw_output = result.stdout + result.stderr

        # Parse output sections
        def extract_section(output, start_marker, end_marker=None):
            if start_marker not in output:
                return ""
            section = output.split(start_marker)[1]
            if end_marker and end_marker in section:
                section = section.split(end_marker)[0]
            return section.strip()

        if used_gef:
            heap_chunks = extract_section(raw_output, "===HEAP_CHUNKS===", "===HEAP_BINS===")
            heap_bins = extract_section(raw_output, "===HEAP_BINS===", "===HEAP_ARENA===")
            heap_arena = extract_section(raw_output, "===HEAP_ARENA===", "===MALLOC_INFO===")
            malloc_info = extract_section(raw_output, "===MALLOC_INFO===")

            # Parse chunks into structured data
            chunks = []
            for line in heap_chunks.split("\n"):
                line = line.strip()
                if line and ("Chunk" in line or line.startswith("0x")):
                    chunks.append(line)

            result_data = {
                "binary": str(binary_path),
                "breakpoint": breakpoint,
                "gef_available": True,
                "heap_chunks_raw": heap_chunks,
                "heap_chunks": chunks,
                "heap_bins": heap_bins,
                "heap_arena": heap_arena,
                "malloc_info": malloc_info,
                "raw_output": raw_output
            }
        else:
            heap_info = extract_section(raw_output, "===HEAP_INFO===", "===MALLOC_STATE===")
            malloc_state = extract_section(raw_output, "===MALLOC_STATE===", "===HEAP_MEMORY===")
            heap_memory = extract_section(raw_output, "===HEAP_MEMORY===")

            result_data = {
                "binary": str(binary_path),
                "breakpoint": breakpoint,
                "gef_available": False,
                "heap_info": heap_info,
                "malloc_state": malloc_state,
                "heap_memory": heap_memory,
                "note": "GEF not available; showing basic heap info from /proc mappings",
                "raw_output": raw_output
            }

        duration = (time.time() - start) * 1000
        log_tool_call("gdb_heap", {"binary": binary, "breakpoint": breakpoint}, {"gef": used_gef}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout during heap analysis"}
        log_tool_call("gdb_heap", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_heap: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_heap", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)
        if fallback_path:
            os.unlink(fallback_path)


@app.route("/got_plt", methods=["POST"])
def got_plt():
    """
    Inspect the GOT (Global Offset Table) and PLT (Procedure Linkage Table).
    Uses objdump and readelf to parse entries with names and addresses.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    try:
        # Get GOT entries via readelf relocations
        reloc_result = subprocess.run(
            ["readelf", "-r", str(binary_path)],
            capture_output=True, text=True, timeout=10
        )

        got_entries = []
        for line in reloc_result.stdout.split("\n"):
            line = line.strip()
            # Relocation entries look like:
            # 000000404018  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
            parts = line.split()
            if len(parts) >= 5 and parts[0].startswith("0"):
                try:
                    offset = parts[0]
                    reloc_type = parts[2] if len(parts) > 2 else ""
                    # The symbol name may contain @ for versioning
                    sym_name = ""
                    for p in parts[3:]:
                        if "@" in p or (p.isalpha() or "_" in p):
                            sym_name = p.split("@")[0] if "@" in p else p
                            break

                    if "PLT" in reloc_type or "JUMP_SLO" in reloc_type or "GLOB_DAT" in reloc_type:
                        got_entries.append({
                            "address": f"0x{offset}" if not offset.startswith("0x") else offset,
                            "type": reloc_type,
                            "name": sym_name
                        })
                except (ValueError, IndexError):
                    continue

        # Get PLT entries via objdump
        plt_result = subprocess.run(
            ["objdump", "-d", "-j", ".plt", "-j", ".plt.got", "-j", ".plt.sec", "-M", "intel", str(binary_path)],
            capture_output=True, text=True, timeout=10
        )

        plt_entries = []
        current_entry = None
        for line in plt_result.stdout.split("\n"):
            # PLT function headers look like: 0000000000401030 <puts@plt>:
            if "@plt" in line and ":" in line:
                parts = line.split()
                if parts:
                    addr = parts[0]
                    name = ""
                    for p in parts:
                        if "<" in p and "@plt" in p:
                            name = p.strip("<>:").replace("@plt", "")
                            break
                    current_entry = {
                        "address": f"0x{addr}" if not addr.startswith("0x") else addr,
                        "name": name,
                        "instructions": []
                    }
                    plt_entries.append(current_entry)
            elif current_entry and line.strip() and ":" in line and line.strip()[0].isdigit():
                current_entry["instructions"].append(line.strip())

        # Get section addresses for .got and .plt
        sections_result = subprocess.run(
            ["readelf", "-S", "-W", str(binary_path)],
            capture_output=True, text=True, timeout=10
        )

        section_info = {}
        for line in sections_result.stdout.split("\n"):
            for sec_name in [".got", ".got.plt", ".plt", ".plt.got", ".plt.sec"]:
                if sec_name in line and "[" in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == sec_name and i + 2 < len(parts):
                            with contextlib.suppress(IndexError):
                                section_info[sec_name] = {
                                    "address": f"0x{parts[i+2]}",
                                    "size": f"0x{parts[i+4]}" if i + 4 < len(parts) else "unknown"
                                }

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "got_entries": got_entries,
            "got_count": len(got_entries),
            "plt_entries": plt_entries,
            "plt_count": len(plt_entries),
            "sections": section_info,
            "raw_relocations": reloc_result.stdout
        }
        log_tool_call("got_plt", {"binary": binary}, {"got": len(got_entries), "plt": len(plt_entries)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "Timeout parsing GOT/PLT"}
        log_tool_call("got_plt", {"binary": binary}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in got_plt: {e}")
        result_data = {"error": str(e)}
        log_tool_call("got_plt", {"binary": binary}, result_data)
        return jsonify(result_data), 500


@app.route("/rop_gadgets", methods=["POST"])
def rop_gadgets():
    """
    Find ROP gadgets in a binary using ROPgadget or ropper.
    Returns a list of gadgets with addresses and instructions.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    max_depth = data.get("max_depth", 5)
    gadget_filter = data.get("filter", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Clamp depth
    max_depth = max(1, min(max_depth, 20))

    gadgets = []
    tool_used = None

    try:
        # Try ROPgadget first
        cmd = ["ROPgadget", "--binary", str(binary_path), "--depth", str(max_depth)]
        if gadget_filter:
            cmd.extend(["--only", gadget_filter])

        rop_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if rop_result.returncode == 0 and rop_result.stdout.strip():
            tool_used = "ROPgadget"
            # Parse ROPgadget output: 0x0000000000401234 : pop rdi ; ret
            for line in rop_result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("0x") and " : " in line:
                    parts = line.split(" : ", 1)
                    addr = parts[0].strip()
                    instructions = parts[1].strip() if len(parts) > 1 else ""
                    gadgets.append({
                        "address": addr,
                        "instructions": instructions
                    })
        else:
            raise FileNotFoundError("ROPgadget not available or failed")

    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fall back to ropper
        try:
            cmd = ["ropper", "--file", str(binary_path), "--depth", str(max_depth)]
            if gadget_filter:
                cmd.extend(["--search", gadget_filter])

            ropper_result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if ropper_result.returncode == 0:
                tool_used = "ropper"
                # Parse ropper output: 0x0000000000401234: pop rdi; ret;
                for line in ropper_result.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("0x") and ":" in line:
                        parts = line.split(":", 1)
                        addr = parts[0].strip()
                        instructions = parts[1].strip().rstrip(";") if len(parts) > 1 else ""
                        gadgets.append({
                            "address": addr,
                            "instructions": instructions
                        })
            else:
                raise FileNotFoundError("ropper not available or failed")

        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Final fallback: manual gadget search using objdump
            tool_used = "objdump_manual"
            try:
                disasm_result = subprocess.run(
                    ["objdump", "-d", "-M", "intel", str(binary_path)],
                    capture_output=True, text=True, timeout=30
                )

                # Search for ret instructions and look backwards for useful gadgets
                lines = disasm_result.stdout.split("\n")
                for i, line in enumerate(lines):
                    if "\tret" in line.lower():
                        addr_part = line.split(":")[0].strip() if ":" in line else ""
                        # Collect preceding instructions up to max_depth
                        gadget_lines = []
                        for j in range(max(0, i - max_depth), i + 1):
                            instr_line = lines[j].strip()
                            if ":" in instr_line and "\t" in instr_line:
                                instr = instr_line.split("\t")[-1].strip()
                                gadget_lines.append(instr)
                        if gadget_lines and addr_part:
                            gadget_str = " ; ".join(gadget_lines)
                            if not gadget_filter or gadget_filter.lower() in gadget_str.lower():
                                gadgets.append({
                                    "address": f"0x{addr_part.strip()}",
                                    "instructions": gadget_str
                                })
            except Exception:
                pass

    # Apply post-filter if using a tool that doesn't support native filtering
    if gadget_filter and tool_used == "ROPgadget":
        # ROPgadget's --only filter is per-instruction, but user might want substring match
        pass  # Already filtered by ROPgadget

    duration = (time.time() - start) * 1000
    result_data = {
        "binary": str(binary_path),
        "gadgets": gadgets[:500],  # Limit output
        "total_found": len(gadgets),
        "truncated": len(gadgets) > 500,
        "max_depth": max_depth,
        "filter": gadget_filter,
        "tool_used": tool_used
    }
    log_tool_call("rop_gadgets", {"binary": binary, "max_depth": max_depth, "filter": gadget_filter}, {"count": len(gadgets), "tool": tool_used}, duration)

    return jsonify(result_data)


@app.route("/frida/attach", methods=["POST"])
def frida_attach():
    """
    Run a binary under Frida with a custom JavaScript instrumentation script.
    Spawns the binary, injects the script, and returns output.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    script = data.get("script", "")
    timeout = data.get("timeout", 10)
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not script:
        return jsonify({"error": "No Frida script specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Clamp timeout
    timeout = max(1, min(timeout, 120))

    # Write the Frida script to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        # Use frida CLI to spawn and inject
        cmd = [
            "frida",
            "-f", str(binary_path),
            "-l", script_path,
            "--no-pause",
            "-q"
        ]

        # Add binary arguments if provided
        if args:
            cmd.append("--")
            cmd.extend(args)

        result = subprocess.run(
            cmd,
            input=stdin_input if stdin_input else None,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "script_used": script[:500],
            "timeout": timeout
        }
        log_tool_call("frida_attach", {"binary": binary, "timeout": timeout}, {"returncode": result.returncode}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": f"Frida execution timed out after {timeout}s"}
        log_tool_call("frida_attach", {"binary": binary, "timeout": timeout}, result_data)
        return jsonify(result_data), 504
    except FileNotFoundError:
        result_data = {"error": "Frida is not installed. Install with: pip install frida-tools"}
        log_tool_call("frida_attach", {"binary": binary}, result_data)
        return jsonify(result_data), 500
    except Exception as e:
        logger.error(f"Error in frida_attach: {e}")
        result_data = {"error": str(e)}
        log_tool_call("frida_attach", {"binary": binary}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/frida/trace", methods=["POST"])
def frida_trace():
    """
    Trace function calls in a binary using frida-trace.
    Traces specified functions and returns the call log.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    functions = data.get("functions", [])
    timeout = data.get("timeout", 10)
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not functions:
        return jsonify({"error": "No functions specified to trace"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Clamp timeout
    timeout = max(1, min(timeout, 120))

    try:
        # Build frida-trace command
        cmd = ["frida-trace", "-f", str(binary_path)]

        # Add function trace patterns
        for func in functions:
            cmd.extend(["-i", func])

        # Add binary arguments if provided
        if args:
            cmd.append("--")
            cmd.extend(args)

        result = subprocess.run(
            cmd,
            input=stdin_input if stdin_input else None,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # Parse trace output into structured calls
        trace_calls = []
        for line in result.stdout.split("\n"):
            line = line.strip()
            if line and (line.startswith(" ") or line.startswith("/")):
                # frida-trace output lines typically show indented call trees
                trace_calls.append(line)

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "functions_traced": functions,
            "trace_output": result.stdout,
            "trace_calls": trace_calls,
            "call_count": len(trace_calls),
            "stderr": result.stderr,
            "returncode": result.returncode
        }
        log_tool_call("frida_trace", {"binary": binary, "functions": functions}, {"calls": len(trace_calls)}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": f"Frida trace timed out after {timeout}s"}
        log_tool_call("frida_trace", {"binary": binary, "functions": functions}, result_data)
        return jsonify(result_data), 504
    except FileNotFoundError:
        result_data = {"error": "frida-trace is not installed. Install with: pip install frida-tools"}
        log_tool_call("frida_trace", {"binary": binary}, result_data)
        return jsonify(result_data), 500
    except Exception as e:
        logger.error(f"Error in frida_trace: {e}")
        result_data = {"error": str(e)}
        log_tool_call("frida_trace", {"binary": binary}, result_data)
        return jsonify(result_data), 500


@app.route("/frida/hook", methods=["POST"])
def frida_hook():
    """
    Hook and modify function behavior using Frida.
    Generates an Interceptor.attach script from on_enter/on_leave callbacks.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    target = data.get("target")
    on_enter = data.get("on_enter", "")
    on_leave = data.get("on_leave", "")
    timeout = data.get("timeout", 10)
    args = data.get("args", [])
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not target:
        return jsonify({"error": "No target function specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    # Clamp timeout
    timeout = max(1, min(timeout, 120))

    # Build the Frida hook script
    on_enter_body = on_enter if on_enter else 'console.log("[*] " + this.context.pc + " -> " + "' + target + ' called");'
    on_leave_body = on_leave if on_leave else 'console.log("[*] ' + target + ' returned: " + retval);'

    # Determine if target is an address or symbol name
    resolve_expr = f"ptr('{target}')" if target.startswith("0x") else f"Module.findExportByName(null, '{target}')"

    frida_script = f"""
var targetAddr = {resolve_expr};
if (targetAddr) {{
    Interceptor.attach(targetAddr, {{
        onEnter: function(args) {{
            {on_enter_body}
        }},
        onLeave: function(retval) {{
            {on_leave_body}
        }}
    }});
    console.log("[+] Hooked {target} at " + targetAddr);
}} else {{
    console.log("[-] Could not find {target}");
}}
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(frida_script)
        script_path = f.name

    try:
        cmd = [
            "frida",
            "-f", str(binary_path),
            "-l", script_path,
            "--no-pause",
            "-q"
        ]

        if args:
            cmd.append("--")
            cmd.extend(args)

        result = subprocess.run(
            cmd,
            input=stdin_input if stdin_input else None,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "target": target,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "script_generated": frida_script.strip(),
            "timeout": timeout
        }
        log_tool_call("frida_hook", {"binary": binary, "target": target}, {"returncode": result.returncode}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": f"Frida hook timed out after {timeout}s"}
        log_tool_call("frida_hook", {"binary": binary, "target": target}, result_data)
        return jsonify(result_data), 504
    except FileNotFoundError:
        result_data = {"error": "Frida is not installed. Install with: pip install frida-tools"}
        log_tool_call("frida_hook", {"binary": binary, "target": target}, result_data)
        return jsonify(result_data), 500
    except Exception as e:
        logger.error(f"Error in frida_hook: {e}")
        result_data = {"error": str(e)}
        log_tool_call("frida_hook", {"binary": binary, "target": target}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)


@app.route("/gdb/vmmap", methods=["POST"])
def gdb_vmmap():
    """
    Get virtual memory map at a breakpoint.
    Uses GEF's vmmap command or falls back to /proc/self/maps via GDB.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"

    # Try GEF vmmap first, then fall back to info proc mappings
    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===VMMAP===\\n",
        "vmmap",
        "echo ===PROC_MAP===\\n",
        "info proc mappings",
        "quit"
    ])

    gdb_script_fallback = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===PROC_MAP===\\n",
        "info proc mappings",
        "echo ===SECTIONS===\\n",
        "maintenance info sections",
        "quit"
    ])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_script)
        script_path = f.name

    fallback_path = None
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", script_path, str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        raw_output = result.stdout + result.stderr
        used_gef = "===VMMAP===" in raw_output and "Undefined command" not in raw_output

        if not used_gef:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_script_fallback)
                fallback_path = f.name

            result = subprocess.run(
                ["gdb", "-batch", "-x", fallback_path, str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            raw_output = result.stdout + result.stderr

        # Parse memory regions
        regions = []

        if used_gef and "===VMMAP===" in raw_output:
            vmmap_section = raw_output.split("===VMMAP===")[1]
            if "===PROC_MAP===" in vmmap_section:
                vmmap_section = vmmap_section.split("===PROC_MAP===")[0]

            for line in vmmap_section.strip().split("\n"):
                line = line.strip()
                if line and line.startswith("0x"):
                    regions.append(line)

        # Always parse info proc mappings as well / fallback
        if "===PROC_MAP===" in raw_output:
            proc_section = raw_output.split("===PROC_MAP===")[1]
            if "===SECTIONS===" in proc_section:
                proc_section = proc_section.split("===SECTIONS===")[0]

            for line in proc_section.strip().split("\n"):
                line = line.strip()
                if line.startswith("0x"):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            region = {
                                "start": parts[0],
                                "end": parts[1],
                                "size": parts[2],
                                "offset": parts[3] if len(parts) > 3 else "0x0",
                                "objfile": parts[4] if len(parts) > 4 else ""
                            }
                            regions.append(region)
                        except IndexError:
                            regions.append(line)

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "breakpoint": breakpoint,
            "gef_available": used_gef,
            "regions": regions,
            "region_count": len(regions),
            "raw_output": raw_output
        }
        log_tool_call("gdb_vmmap", {"binary": binary, "breakpoint": breakpoint}, {"regions": len(regions), "gef": used_gef}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout during vmmap"}
        log_tool_call("gdb_vmmap", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_vmmap: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_vmmap", {"binary": binary, "breakpoint": breakpoint}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)
        if fallback_path:
            os.unlink(fallback_path)


@app.route("/gdb/search_pattern", methods=["POST"])
def gdb_search_pattern():
    """
    Search for a pattern in the process memory at a breakpoint.
    Uses GEF's search-pattern command or falls back to GDB find command.
    """
    import time
    start = time.time()

    data = request.json or {}
    binary = data.get("binary")
    breakpoint = data.get("breakpoint", "main")
    pattern = data.get("pattern", "")
    search_type = data.get("type", "string")
    stdin_input = data.get("stdin", "")

    if not binary:
        return jsonify({"error": "No binary specified"}), 400

    if not pattern:
        return jsonify({"error": "No search pattern specified"}), 400

    binary_path = BINS_DIR / binary if not binary.startswith("/") else Path(binary)

    if not binary_path.exists():
        return jsonify({"error": f"Binary not found: {binary_path}"}), 404

    bp_cmd = f"break *{breakpoint}" if breakpoint.startswith("0x") else f"break {breakpoint}"

    # Build GDB search commands
    # Try GEF search-pattern first, then fall back to GDB find
    if search_type == "hex":
        gef_search = f"search-pattern {pattern}"
        # For GDB find fallback, convert hex pattern
        gdb_find_pattern = pattern
    else:
        gef_search = f'search-pattern "{pattern}"'
        gdb_find_pattern = f'"{pattern}"'

    gdb_script = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===GEF_SEARCH===\\n",
        gef_search,
        "echo ===END_SEARCH===\\n",
        "quit"
    ])

    gdb_script_fallback = "\n".join([
        "set pagination off",
        "set confirm off",
        bp_cmd,
        "run" + (f" <<< '{stdin_input}'" if stdin_input else ""),
        "echo ===PROC_MAP===\\n",
        "info proc mappings",
        "echo ===FIND_SEARCH===\\n",
        f"find {gdb_find_pattern}",
        "echo ===END_SEARCH===\\n",
        "quit"
    ])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_script)
        script_path = f.name

    fallback_path = None
    try:
        result = subprocess.run(
            ["gdb", "-batch", "-x", script_path, str(binary_path)],
            capture_output=True,
            text=True,
            timeout=30
        )

        raw_output = result.stdout + result.stderr
        used_gef = "===GEF_SEARCH===" in raw_output and "Undefined command" not in raw_output

        if not used_gef:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_script_fallback)
                fallback_path = f.name

            result = subprocess.run(
                ["gdb", "-batch", "-x", fallback_path, str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            raw_output = result.stdout + result.stderr

        # Parse search results
        found_locations = []

        if used_gef and "===GEF_SEARCH===" in raw_output:
            search_section = raw_output.split("===GEF_SEARCH===")[1]
            if "===END_SEARCH===" in search_section:
                search_section = search_section.split("===END_SEARCH===")[0]

            for line in search_section.strip().split("\n"):
                line = line.strip()
                if line and (line.startswith("0x") or line.startswith("[")):
                    found_locations.append(line)

        elif "===FIND_SEARCH===" in raw_output:
            find_section = raw_output.split("===FIND_SEARCH===")[1]
            if "===END_SEARCH===" in find_section:
                find_section = find_section.split("===END_SEARCH===")[0]

            for line in find_section.strip().split("\n"):
                line = line.strip()
                if line.startswith("0x") or "pattern found" in line.lower():
                    found_locations.append(line)

        duration = (time.time() - start) * 1000
        result_data = {
            "binary": str(binary_path),
            "breakpoint": breakpoint,
            "pattern": pattern,
            "type": search_type,
            "gef_available": used_gef,
            "locations": found_locations,
            "match_count": len(found_locations),
            "raw_output": raw_output
        }
        log_tool_call("gdb_search_pattern", {"binary": binary, "pattern": pattern, "type": search_type}, {"matches": len(found_locations), "gef": used_gef}, duration)

        return jsonify(result_data)

    except subprocess.TimeoutExpired:
        result_data = {"error": "GDB timeout during pattern search"}
        log_tool_call("gdb_search_pattern", {"binary": binary, "pattern": pattern}, result_data)
        return jsonify(result_data), 504
    except Exception as e:
        logger.error(f"Error in gdb_search_pattern: {e}")
        result_data = {"error": str(e)}
        log_tool_call("gdb_search_pattern", {"binary": binary, "pattern": pattern}, result_data)
        return jsonify(result_data), 500
    finally:
        os.unlink(script_path)
        if fallback_path:
            os.unlink(fallback_path)


if __name__ == "__main__":
    # Ensure directories exist
    BINS_DIR.mkdir(exist_ok=True)
    LOG_DIR.mkdir(exist_ok=True)

    logger.info("Starting GDB API server on port 5000...")
    logger.info(f"Binaries directory: {BINS_DIR}")
    logger.info(f"Logs directory: {LOG_DIR}")
    logger.info("Upload binaries to /analysis/bins or via POST /upload")

    app.run(host="0.0.0.0", port=5000, debug=False)  # noqa: S104
