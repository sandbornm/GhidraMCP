# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import argparse
import os
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

import requests
from mcp.server.fastmcp import FastMCP

DEFAULT_GDB_SERVER = os.getenv("GHIDRA_GDB_SERVER", os.getenv("GDB_SERVER", "http://127.0.0.1:5051/"))

mcp = FastMCP("ghidra-mcp-gdb")
gdb_server_url = DEFAULT_GDB_SERVER


def gdb_request(endpoint: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any]:
    url = urljoin(gdb_server_url, endpoint)
    try:
        response = requests.get(url, timeout=30) if method == "GET" else requests.post(url, json=data, timeout=120)
        response.encoding = "utf-8"
        if response.ok:
            return cast(dict[str, Any], response.json())
        return {"error": f"HTTP {response.status_code}: {response.text}"}
    except requests.exceptions.ConnectionError:
        return {"error": f"Cannot connect to GDB server at {gdb_server_url}. Is the Docker container running?"}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def gdb_health() -> dict[str, Any]:
    return gdb_request("/health")


@mcp.tool()
def gdb_list_binaries() -> dict[str, Any]:
    return gdb_request("/list_bins")


@mcp.tool()
def gdb_upload_binary(local_path: str, remote_name: str | None = None) -> dict[str, Any]:
    path = Path(local_path)
    if not path.exists():
        return {"error": f"File not found: {local_path}"}
    url = urljoin(gdb_server_url, "/upload")
    try:
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"filename": remote_name or path.name}
            response = requests.post(url, files=files, data=data, timeout=60)
        if response.ok:
            return cast(dict[str, Any], response.json())
        return {"error": f"Upload failed: HTTP {response.status_code}", "body": response.text}
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def gdb_check_arch(binary: str) -> dict[str, Any]:
    return gdb_request("/arch", "POST", {"binary": binary})


@mcp.tool()
def gdb_file_info(binary: str) -> dict[str, Any]:
    return gdb_request("/file_info", "POST", {"binary": binary})


@mcp.tool()
def gdb_run_binary(binary: str, args: list[str] | None = None, stdin: str = "", timeout: int = 10, arch: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary, "args": args or [], "stdin": stdin, "timeout": timeout}
    if arch:
        data["arch"] = arch
    return gdb_request("/run", "POST", data)


@mcp.tool()
def gdb_execute(binary: str, commands: list[str]) -> dict[str, Any]:
    return gdb_request("/gdb", "POST", {"binary": binary, "commands": commands})


@mcp.tool()
def gdb_breakpoint_run(binary: str, breakpoints: list[str], stdin: str = "") -> dict[str, Any]:
    return gdb_request("/gdb/breakpoint_run", "POST", {"binary": binary, "breakpoints": breakpoints, "stdin": stdin})


@mcp.tool()
def gdb_read_registers(binary: str, breakpoint: str = "main") -> dict[str, Any]:
    return gdb_request("/gdb/registers", "POST", {"binary": binary, "breakpoint": breakpoint})


@mcp.tool()
def gdb_read_memory(binary: str, address: str, length: int = 64, format: str = "hex") -> dict[str, Any]:
    return gdb_request("/gdb/memory", "POST", {"binary": binary, "address": address, "length": length, "format": format})


@mcp.tool()
def gdb_step_execution(binary: str, breakpoint: str = "main", command: str = "stepi", count: int = 1) -> dict[str, Any]:
    return gdb_request(
        "/gdb/step",
        "POST",
        {"binary": binary, "breakpoint": breakpoint, "command": command, "count": count},
    )


@mcp.tool()
def gdb_inspect_stack(binary: str, breakpoint: str = "main", depth: int = 20) -> dict[str, Any]:
    return gdb_request("/gdb/stack", "POST", {"binary": binary, "breakpoint": breakpoint, "depth": depth})


@mcp.tool()
def gdb_vmmap(binary: str, breakpoint: str = "main") -> dict[str, Any]:
    return gdb_request("/gdb/vmmap", "POST", {"binary": binary, "breakpoint": breakpoint})


@mcp.tool()
def gdb_search_pattern(binary: str, pattern: str, breakpoint: str = "main", pattern_type: str = "string") -> dict[str, Any]:
    return gdb_request(
        "/gdb/search_pattern",
        "POST",
        {"binary": binary, "pattern": pattern, "breakpoint": breakpoint, "pattern_type": pattern_type},
    )


@mcp.tool()
def gdb_checksec(binary: str) -> dict[str, Any]:
    return gdb_request("/checksec", "POST", {"binary": binary})


@mcp.tool()
def gdb_disassemble(binary: str, symbol: str | None = None) -> dict[str, Any]:
    return gdb_request("/disassemble", "POST", {"binary": binary, "symbol": symbol})


@mcp.tool()
def gdb_strings(binary: str, min_length: int = 4) -> dict[str, Any]:
    return gdb_request("/strings", "POST", {"binary": binary, "min_length": min_length})


@mcp.tool()
def gdb_sections(binary: str) -> dict[str, Any]:
    return gdb_request("/sections", "POST", {"binary": binary})


@mcp.tool()
def gdb_symbols(binary: str, filter_type: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary}
    if filter_type:
        data["filter"] = filter_type
    return gdb_request("/symbols", "POST", data)


@mcp.tool()
def gdb_entropy(binary: str, block_size: int = 256) -> dict[str, Any]:
    return gdb_request("/entropy", "POST", {"binary": binary, "block_size": block_size})


@mcp.tool()
def gdb_imports(binary: str) -> dict[str, Any]:
    return gdb_request("/imports", "POST", {"binary": binary})


@mcp.tool()
def gdb_libs(binary: str) -> dict[str, Any]:
    return gdb_request("/libs", "POST", {"binary": binary})


@mcp.tool()
def gdb_patch_elf(binary: str, address: str, hex_bytes: str, output: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary, "address": address, "bytes": hex_bytes}
    if output:
        data["output"] = output
    return gdb_request("/patch_elf", "POST", data)


@mcp.tool()
def gdb_got_plt(binary: str) -> dict[str, Any]:
    return gdb_request("/got_plt", "POST", {"binary": binary})


@mcp.tool()
def gdb_rop_gadgets(binary: str, max_depth: int = 5, filter: str | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary, "max_depth": max_depth}
    if filter:
        data["filter"] = filter
    return gdb_request("/rop_gadgets", "POST", data)


@mcp.tool()
def gdb_frida_instrument(binary: str, script: str, timeout: int = 10) -> dict[str, Any]:
    return gdb_request("/frida/attach", "POST", {"binary": binary, "script": script, "timeout": timeout})


@mcp.tool()
def gdb_frida_trace(binary: str, functions: list[str], timeout: int = 10) -> dict[str, Any]:
    return gdb_request("/frida/trace", "POST", {"binary": binary, "functions": functions, "timeout": timeout})


@mcp.tool()
def gdb_frida_hook(
    binary: str,
    target: str,
    on_enter: str | None = None,
    on_leave: str | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary, "target": target, "timeout": timeout}
    if on_enter is not None:
        data["on_enter"] = on_enter
    if on_leave is not None:
        data["on_leave"] = on_leave
    return gdb_request("/frida/hook", "POST", data)


@mcp.tool()
def angr_entry(binary: str) -> dict[str, Any]:
    return gdb_request("/angr/entry", "POST", {"binary": binary})


@mcp.tool()
def angr_cfg(binary: str, timeout: int = 60) -> dict[str, Any]:
    return gdb_request("/angr/cfg", "POST", {"binary": binary, "timeout": timeout})


@mcp.tool()
def angr_explore(binary: str, find_addr: str, avoid_addrs: list[str] | None = None, timeout: int = 120) -> dict[str, Any]:
    data: dict[str, Any] = {"binary": binary, "find_addr": find_addr, "timeout": timeout, "stdin_symbolic": True}
    if avoid_addrs:
        data["avoid_addrs"] = avoid_addrs
    return gdb_request("/angr/explore", "POST", data)


@mcp.tool()
def gdb_angr_selftest(timeout: int = 30) -> dict[str, Any]:
    return gdb_request("/angr/selftest", "POST", {"timeout": timeout})


@mcp.tool()
def auto_triage(binary: str, include_strings: bool = True, string_filter: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"binary": binary, "steps": {}, "errors": []}

    fi = gdb_file_info(binary)
    if "error" in fi:
        result["errors"].append(f"file_info: {fi['error']}")
    else:
        result["steps"]["file_info"] = fi

    cs = gdb_checksec(binary)
    if "error" in cs:
        result["errors"].append(f"checksec: {cs['error']}")
    else:
        result["steps"]["checksec"] = cs

    ent = gdb_entropy(binary)
    if "error" in ent:
        result["errors"].append(f"entropy: {ent['error']}")
    else:
        result["steps"]["entropy"] = ent

    imp = gdb_imports(binary)
    if "error" in imp:
        result["errors"].append(f"imports: {imp['error']}")
    else:
        result["steps"]["imports"] = imp

    if include_strings:
        st = gdb_strings(binary, min_length=6)
        if "error" in st:
            result["errors"].append(f"strings: {st['error']}")
        else:
            strings = cast(list[str], st.get("strings", []))
            if string_filter:
                strings = [s for s in strings if string_filter.lower() in s.lower()]
            result["steps"]["strings_sample"] = strings[:30]

    return result


@mcp.tool()
def gdb_get_telemetry(lines: int = 100) -> dict[str, Any]:
    return gdb_request(f"/telemetry?lines={lines}")


@mcp.tool()
def gdb_get_command_telemetry(lines: int = 100) -> dict[str, Any]:
    return gdb_request(f"/command_telemetry?lines={lines}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Dedicated GDB MCP bridge")
    parser.add_argument("--gdb-server", default=DEFAULT_GDB_SERVER, help=f"default: {DEFAULT_GDB_SERVER}")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8082)
    args = parser.parse_args()

    global gdb_server_url
    gdb_server_url = args.gdb_server

    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
