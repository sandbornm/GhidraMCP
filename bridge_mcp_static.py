# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import argparse
import os
import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import urljoin

import requests
from mcp.server.fastmcp import FastMCP

from trajectory_recorder import TrajectoryRecorder, analyze_trajectory, export_trajectory_markdown

DEFAULT_GHIDRA_SERVER = os.getenv("GHIDRA_SERVER", "http://127.0.0.1:8080/")
DEFAULT_GDB_SERVER = os.getenv("GHIDRA_GDB_SERVER", os.getenv("GDB_SERVER", "http://127.0.0.1:5051/"))
DEFAULT_TRAJECTORY_DIR = os.path.expanduser("~/Github/GhidraMCP/trajectories")

mcp = FastMCP("ghidra-mcp-static")

ghidra_server_url = DEFAULT_GHIDRA_SERVER
gdb_server_url = DEFAULT_GDB_SERVER
trajectory_recorder: TrajectoryRecorder | None = None


def _record_call(tool_name: str, params: dict[str, Any], result: Any, duration_ms: float, success: bool = True) -> None:
    global trajectory_recorder
    if trajectory_recorder:
        trajectory_recorder.record(tool_name, params, result, duration_ms, success)


def recorded_tool(func):
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
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
            duration_ms = (time.time() - start) * 1000
            _record_call(func.__name__, cast(dict[str, Any], kwargs), result, duration_ms, success)

    return wrapper


def safe_get(endpoint: str, params: dict[str, Any] | None = None) -> list[str]:
    url = urljoin(ghidra_server_url, endpoint)
    try:
        response = requests.get(url, params=params or {}, timeout=30)
        response.encoding = "utf-8"
        if response.ok:
            return response.text.splitlines()
        return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {e}"]


def safe_post(endpoint: str, data: dict[str, Any] | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=30)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=30)
        response.encoding = "utf-8"
        if response.ok:
            return response.text.strip()
        return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {e}"


@mcp.tool()
@recorded_tool
def gdb_health() -> dict[str, Any]:
    """Check if dynamic GDB API is healthy."""
    try:
        res = requests.get(urljoin(gdb_server_url, "/health"), timeout=10)
        return cast(dict[str, Any], res.json()) if res.ok else {"error": res.text}
    except Exception as e:
        return {"error": f"Cannot connect to {gdb_server_url}: {e}"}


@mcp.tool()
@recorded_tool
def list_methods(offset: int = 0, limit: int = 100) -> list[str]:
    return safe_get("methods", {"offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def list_functions() -> list[str]:
    # Headless server exposes this as /methods.
    return safe_get("methods")


@mcp.tool()
@recorded_tool
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list[str]:
    if not query:
        return ["Error: query is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def list_imports(offset: int = 0, limit: int = 100) -> list[str]:
    return safe_get("imports", {"offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def list_exports(offset: int = 0, limit: int = 100) -> list[str]:
    return safe_get("exports", {"offset": offset, "limit": limit})


@mcp.tool()
@recorded_tool
def list_strings(offset: int = 0, limit: int = 2000, filter: str | None = None) -> list[str]:
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)


@mcp.tool()
@recorded_tool
def get_program_info() -> str:
    return "\n".join(safe_get("get_program_info"))


@mcp.tool()
@recorded_tool
def decompile_function(name: str) -> str:
    return safe_post("decompile", name)


@mcp.tool()
@recorded_tool
def decompile_function_by_address(address: str) -> str:
    return "\n".join(safe_get("decompile_function", {"address": address}))


@mcp.tool()
@recorded_tool
def disassemble_function(address: str) -> list[str]:
    return safe_get("disassemble_function", {"address": address})


@mcp.tool()
@recorded_tool
def rename_function(old_name: str, new_name: str) -> str:
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})


@mcp.tool()
@recorded_tool
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    return safe_post("renameVariable", {"functionName": function_name, "oldName": old_name, "newName": new_name})


@mcp.tool()
@recorded_tool
def set_decompiler_comment(address: str, comment: str) -> str:
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})


@mcp.tool()
@recorded_tool
def set_disassembly_comment(address: str, comment: str) -> str:
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})


@mcp.tool()
@recorded_tool
def run_auto_analysis() -> str:
    return "\n".join(safe_get("run_auto_analysis"))


@mcp.tool()
@recorded_tool
def patch_bytes(address: str, hex_bytes: str) -> str:
    return safe_post("patch_bytes", {"address": address, "bytes": hex_bytes})


@mcp.tool()
@recorded_tool
def patch_instruction(address: str, assembly: str) -> str:
    return safe_post("patch_instruction", {"address": address, "assembly": assembly})


@mcp.tool()
@recorded_tool
def nop_region(start_address: str, end_address: str) -> str:
    return safe_post("nop_region", {"start_address": start_address, "end_address": end_address})


@mcp.tool()
@recorded_tool
def get_bytes(address: str, length: int = 16) -> str:
    return "\n".join(safe_get("get_bytes", {"address": address, "length": length}))


@mcp.tool()
@recorded_tool
def export_binary(output_path: str, format: str = "original") -> str:
    return safe_post("export_binary", {"output_path": output_path, "format": format})


@mcp.tool()
@recorded_tool
def save_program() -> str:
    return safe_post("save_program", {})


@mcp.tool()
@recorded_tool
def export_and_upload_to_gdb(
    output_path: str, remote_name: str | None = None, format: str = "original"
) -> dict[str, Any]:
    """
    Export a patched binary from Ghidra and upload it to the GDB API.
    This is the intended static<->dynamic interop path.
    """
    export_result = export_binary(output_path=output_path, format=format)
    path = Path(output_path)
    if not path.exists():
        return {"error": "Export failed or file not found", "export_result": export_result}

    url = urljoin(gdb_server_url, "/upload")
    try:
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"filename": remote_name or path.name}
            response = requests.post(url, files=files, data=data, timeout=60)
        if response.ok:
            return {
                "status": "exported_and_uploaded",
                "export_result": export_result,
                "gdb_upload": cast(dict[str, Any], response.json()),
            }
        return {
            "error": f"Upload failed: HTTP {response.status_code}",
            "export_result": export_result,
            "gdb_response": response.text,
        }
    except Exception as e:
        return {"error": f"Upload request failed: {e}", "export_result": export_result}


@mcp.tool()
def trajectory_start(binary_name: str | None = None, output_dir: str | None = None) -> dict[str, Any]:
    """Start lightweight trajectory recording for this static session."""
    global trajectory_recorder
    if trajectory_recorder:
        return {"error": "Recording already active. Call trajectory_stop() first."}

    if not binary_name:
        detected = safe_get("get_program_name")
        binary_name = detected[0] if detected and not detected[0].startswith("Error") else "unknown_binary"

    output = output_dir or DEFAULT_TRAJECTORY_DIR
    trajectory_recorder = TrajectoryRecorder(output_dir=output, binary_name=binary_name)
    return {
        "status": "recording_started",
        "session_id": trajectory_recorder.session_id,
        "binary": binary_name,
        "output_path": str(trajectory_recorder.get_session_path()),
    }


@mcp.tool()
def trajectory_note(note: str, category: str = "observation") -> dict[str, Any]:
    global trajectory_recorder
    if not trajectory_recorder:
        return {"error": "No active recording session. Call trajectory_start() first."}
    trajectory_recorder.add_note(note, category)
    return {"status": "note_added", "category": category, "note": note}


@mcp.tool()
def trajectory_status() -> dict[str, Any]:
    global trajectory_recorder
    if not trajectory_recorder:
        return {"recording": False, "message": "No active session"}
    analysis = analyze_trajectory(str(trajectory_recorder.get_session_path()))
    return {
        "recording": True,
        "session_id": trajectory_recorder.session_id,
        "binary": trajectory_recorder.binary_name,
        "output_path": str(trajectory_recorder.get_session_path()),
        "total_tool_calls": analysis.get("total_tool_calls", 0),
    }


@mcp.tool()
def trajectory_stop(summary: str | None = None) -> dict[str, Any]:
    global trajectory_recorder
    if not trajectory_recorder:
        return {"error": "No active recording session."}
    session_path = trajectory_recorder.get_session_path()
    analysis = analyze_trajectory(str(session_path))
    trajectory_recorder.end_session(summary)
    trajectory_recorder = None
    return {
        "status": "recording_stopped",
        "trajectory_path": str(session_path),
        "summary": summary,
        "total_tool_calls": analysis.get("total_tool_calls", 0),
    }


@mcp.tool()
def analysis_session_recap(trajectory_path: str, output_path: str | None = None) -> dict[str, Any]:
    """Export a concise markdown recap from a trajectory file."""
    try:
        if output_path:
            export_trajectory_markdown(trajectory_path, output_path)
            return {"status": "exported", "output_path": output_path}
        return {"markdown": export_trajectory_markdown(trajectory_path)}
    except Exception as e:
        return {"error": str(e)}


def _auto_start_trajectory_if_enabled(enabled: bool) -> None:
    global trajectory_recorder
    if not enabled or trajectory_recorder:
        return
    detected = safe_get("get_program_name")
    binary_name = detected[0] if detected and not detected[0].startswith("Error") else "unknown_binary"
    trajectory_recorder = TrajectoryRecorder(output_dir=DEFAULT_TRAJECTORY_DIR, binary_name=binary_name)


def main() -> None:
    parser = argparse.ArgumentParser(description="Static Ghidra MCP bridge (minimal trajectory, optional GDB interop)")
    parser.add_argument("--ghidra-server", default=DEFAULT_GHIDRA_SERVER, help=f"default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--gdb-server", default=DEFAULT_GDB_SERVER, help=f"default: {DEFAULT_GDB_SERVER}")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--mcp-host", default="127.0.0.1")
    parser.add_argument("--mcp-port", type=int, default=8081)
    parser.add_argument(
        "--no-auto-trajectory",
        action="store_true",
        help="Disable automatic trajectory session start at bridge boot",
    )
    args = parser.parse_args()

    global ghidra_server_url, gdb_server_url
    ghidra_server_url = args.ghidra_server
    gdb_server_url = args.gdb_server
    _auto_start_trajectory_if_enabled(not args.no_auto_trajectory)

    if args.transport == "sse":
        mcp.settings.host = args.mcp_host
        mcp.settings.port = args.mcp_port
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
