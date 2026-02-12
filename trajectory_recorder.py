#!/usr/bin/env python3
"""
Trajectory Recorder for GhidraMCP

Records all tool calls, results, and analysis steps for reverse engineering sessions.
Creates structured logs that capture the "thought process" of binary analysis.

Trajectory Format (JSONL):
{
    "timestamp": "2026-01-30T16:30:00.000Z",
    "session_id": "abc123",
    "binary": "crymore",
    "tool": "decompile_function",
    "category": "static_analysis",  # static_analysis, dynamic_analysis, patching, navigation
    "params": {"name": "main"},
    "result_summary": "Decompiled 45 lines",
    "result": "...",  # Full result (optional, can be large)
    "duration_ms": 150,
    "address_context": ["0x401000", "0x401050"],  # Addresses involved
    "success": true
}
"""

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any


class TrajectoryRecorder:
    """Records analysis trajectories for reverse engineering sessions."""

    # Tool categorization
    TOOL_CATEGORIES = {
        # Static Analysis
        "list_methods": "static_analysis",
        "list_functions": "static_analysis",
        "list_classes": "static_analysis",
        "list_segments": "static_analysis",
        "list_imports": "static_analysis",
        "list_exports": "static_analysis",
        "list_namespaces": "static_analysis",
        "list_data_items": "static_analysis",
        "list_strings": "static_analysis",
        "decompile_function": "static_analysis",
        "decompile_function_by_address": "static_analysis",
        "disassemble_function": "static_analysis",
        "search_functions_by_name": "static_analysis",
        "get_xrefs_to": "static_analysis",
        "get_xrefs_from": "static_analysis",
        "get_function_xrefs": "static_analysis",
        "get_bytes": "static_analysis",
        "gdb_checksec": "static_analysis",
        "gdb_disassemble": "static_analysis",
        "gdb_strings": "static_analysis",
        "gdb_check_arch": "static_analysis",

        # Navigation
        "get_current_address": "navigation",
        "get_current_function": "navigation",
        "get_function_by_address": "navigation",

        # Enhanced Analysis
        "get_call_graph": "static_analysis",
        "list_undefined_functions": "static_analysis",
        "get_function_cfg_info": "static_analysis",

        # Annotation
        "rename_function": "annotation",
        "rename_function_by_address": "annotation",
        "rename_variable": "annotation",
        "rename_data": "annotation",
        "set_decompiler_comment": "annotation",
        "set_disassembly_comment": "annotation",
        "set_function_prototype": "annotation",
        "set_local_variable_type": "annotation",
        "rename_variable_by_address": "annotation",
        "batch_rename": "annotation",

        # Patching
        "patch_bytes": "patching",
        "patch_instruction": "patching",
        "nop_region": "patching",
        "gdb_patch_elf": "patching",

        # Dynamic Analysis
        "gdb_run_binary": "dynamic_analysis",
        "gdb_execute": "dynamic_analysis",
        "gdb_breakpoint_run": "dynamic_analysis",
        "gdb_strace": "dynamic_analysis",
        "gdb_ltrace": "dynamic_analysis",

        # File Operations
        "export_binary": "file_ops",
        "save_program": "file_ops",
        "gdb_upload_binary": "file_ops",
        "gdb_list_binaries": "file_ops",
        "list_exporters": "file_ops",

        # System
        "gdb_health": "system",
        "gdb_get_logs": "system",
        "gdb_get_telemetry": "system",
    }

    def __init__(self, output_dir: str = None, binary_name: str = None):
        """
        Initialize trajectory recorder.

        Args:
            output_dir: Directory to store trajectory files
            binary_name: Name of the binary being analyzed
        """
        self.output_dir = Path(output_dir or os.environ.get("TRAJECTORY_DIR", "./trajectories"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.session_id = self._generate_session_id()
        self.binary_name = binary_name or "unknown"
        self.start_time = datetime.now(timezone.utc)

        # Session file
        self.session_file = self.output_dir / f"{self.session_id}.jsonl"

        # Thread safety
        self._lock = threading.Lock()

        # Session metadata
        self._write_session_start()

    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        random_suffix = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:8]
        return f"{timestamp}_{random_suffix}"

    def _write_session_start(self):
        """Write session start metadata."""
        entry = {
            "type": "session_start",
            "timestamp": self.start_time.isoformat(),
            "session_id": self.session_id,
            "binary": self.binary_name,
        }
        self._write_entry(entry)

    def _write_entry(self, entry: dict):
        """Write an entry to the trajectory file."""
        with self._lock, open(self.session_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _extract_addresses(self, params: dict, result: Any) -> list:
        """Extract addresses mentioned in params or results."""
        addresses = []

        # Check params for address-like fields
        for key in ["address", "start_address", "end_address", "function_address"]:
            if key in params:
                addresses.append(params[key])

        # Check result for addresses (if string)
        if isinstance(result, str):
            import re
            hex_pattern = r'0x[0-9a-fA-F]+'
            found = re.findall(hex_pattern, result)
            addresses.extend(found[:5])  # Limit to first 5

        return list(set(addresses))

    def _summarize_result(self, result: Any, tool: str) -> str:
        """Create a brief summary of the result."""
        if isinstance(result, str):
            lines = result.count('\n') + 1
            length = len(result)
            if lines > 1:
                return f"{lines} lines, {length} chars"
            return result[:100] + "..." if length > 100 else result
        elif isinstance(result, list):
            return f"{len(result)} items"
        elif isinstance(result, dict):
            if "error" in result:
                return f"Error: {result['error'][:50]}"
            return f"Dict with {len(result)} keys"
        return str(type(result).__name__)

    def record(self, tool: str, params: dict, result: Any, duration_ms: float, success: bool = True):
        """
        Record a tool call.

        Args:
            tool: Tool name
            params: Tool parameters
            result: Tool result
            duration_ms: Execution time in milliseconds
            success: Whether the call succeeded
        """
        entry = {
            "type": "tool_call",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "binary": self.binary_name,
            "tool": tool,
            "category": self.TOOL_CATEGORIES.get(tool, "unknown"),
            "params": params,
            "result_summary": self._summarize_result(result, tool),
            "duration_ms": round(duration_ms, 2),
            "address_context": self._extract_addresses(params, result),
            "success": success,
        }

        # Include full result for certain categories (but truncate if huge)
        if entry["category"] in ["patching", "annotation", "dynamic_analysis"]:
            result_str = str(result)
            if len(result_str) < 10000:
                entry["result"] = result_str

        self._write_entry(entry)

    def set_binary(self, binary_name: str):
        """Update the current binary being analyzed."""
        self.binary_name = binary_name
        self._write_entry({
            "type": "binary_change",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "binary": binary_name,
        })

    def add_note(self, note: str, category: str = "observation"):
        """Add a manual note/observation to the trajectory."""
        self._write_entry({
            "type": "note",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "binary": self.binary_name,
            "category": category,
            "note": note,
        })

    def end_session(self, summary: str = None):
        """End the recording session."""
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        self._write_entry({
            "type": "session_end",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "binary": self.binary_name,
            "duration_seconds": round(duration, 2),
            "summary": summary,
        })

    def get_session_path(self) -> Path:
        """Get the path to the current session file."""
        return self.session_file


def analyze_trajectory(trajectory_path: str) -> dict:
    """
    Analyze a trajectory file and extract insights.

    Args:
        trajectory_path: Path to the JSONL trajectory file

    Returns:
        Analysis summary including:
        - Tool usage statistics
        - Category breakdown
        - Timeline of analysis
        - Key addresses analyzed
        - Patches applied
    """
    entries = []
    with open(trajectory_path) as f:
        for line in f:
            entries.append(json.loads(line))

    # Filter to tool calls only
    tool_calls = [e for e in entries if e.get("type") == "tool_call"]

    # Statistics
    tool_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    total_duration = 0
    addresses = set()
    patches = []
    errors = []

    for entry in tool_calls:
        tool = entry.get("tool", "unknown")
        category = entry.get("category", "unknown")

        tool_counts[tool] = tool_counts.get(tool, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1
        total_duration += entry.get("duration_ms", 0)

        for addr in entry.get("address_context", []):
            addresses.add(addr)

        if category == "patching":
            patches.append({
                "tool": tool,
                "params": entry.get("params"),
                "result": entry.get("result_summary"),
            })

        if not entry.get("success", True):
            errors.append({
                "tool": tool,
                "params": entry.get("params"),
                "result": entry.get("result_summary"),
            })

    # Session info
    session_start: dict[str, Any] = next((e for e in entries if e.get("type") == "session_start"), {})
    session_end: dict[str, Any] = next((e for e in entries if e.get("type") == "session_end"), {})

    return {
        "session_id": session_start.get("session_id"),
        "binary": session_start.get("binary"),
        "start_time": session_start.get("timestamp"),
        "end_time": session_end.get("timestamp"),
        "session_duration_seconds": session_end.get("duration_seconds"),
        "total_tool_calls": len(tool_calls),
        "total_tool_duration_ms": round(total_duration, 2),
        "tool_counts": dict(sorted(tool_counts.items(), key=lambda x: -x[1])),
        "category_counts": dict(sorted(category_counts.items(), key=lambda x: -x[1])),
        "unique_addresses": len(addresses),
        "top_addresses": list(addresses)[:20],
        "patches_applied": patches,
        "errors": errors,
        "notes": [e for e in entries if e.get("type") == "note"],
    }


def export_trajectory_markdown(trajectory_path: str, output_path: str = None) -> str:
    """
    Export a trajectory as a readable markdown document.

    Args:
        trajectory_path: Path to the JSONL trajectory file
        output_path: Optional output path for the markdown file

    Returns:
        Markdown string
    """
    analysis = analyze_trajectory(trajectory_path)

    entries = []
    with open(trajectory_path) as f:
        for line in f:
            entries.append(json.loads(line))

    md = []
    md.append(f"# Reverse Engineering Trajectory: {analysis['binary']}")
    md.append(f"\n**Session ID:** {analysis['session_id']}")
    md.append(f"**Started:** {analysis['start_time']}")
    md.append(f"**Duration:** {analysis.get('session_duration_seconds', 'N/A')} seconds")
    md.append(f"**Total Tool Calls:** {analysis['total_tool_calls']}")

    # Summary
    md.append("\n## Summary")
    md.append("\n### Tool Usage by Category")
    md.append("| Category | Count |")
    md.append("|----------|-------|")
    for cat, count in analysis['category_counts'].items():
        md.append(f"| {cat} | {count} |")

    # Patches
    if analysis['patches_applied']:
        md.append("\n## Patches Applied")
        for i, patch in enumerate(analysis['patches_applied'], 1):
            md.append(f"\n### Patch {i}: {patch['tool']}")
            md.append(f"```json\n{json.dumps(patch['params'], indent=2)}\n```")
            md.append(f"Result: {patch['result']}")

    # Timeline
    md.append("\n## Analysis Timeline")
    tool_calls = [e for e in entries if e.get("type") == "tool_call"]
    for entry in tool_calls:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        tool = entry.get("tool")
        cat = entry.get("category")
        summary = entry.get("result_summary", "")[:80]
        success = "✓" if entry.get("success", True) else "✗"
        md.append(f"- `{ts}` [{cat}] **{tool}** {success} - {summary}")

    # Notes
    notes = [e for e in entries if e.get("type") == "note"]
    if notes:
        md.append("\n## Notes")
        for note in notes:
            ts = note.get("timestamp", "")[:19].replace("T", " ")
            md.append(f"- `{ts}` [{note.get('category')}] {note.get('note')}")

    markdown = "\n".join(md)

    if output_path:
        with open(output_path, "w") as f:
            f.write(markdown)

    return markdown


# Global recorder instance
_recorder: TrajectoryRecorder | None = None


def get_recorder() -> TrajectoryRecorder | None:
    """Get the global trajectory recorder."""
    return _recorder


def init_recorder(output_dir: str = None, binary_name: str = None) -> TrajectoryRecorder:
    """Initialize the global trajectory recorder."""
    global _recorder
    _recorder = TrajectoryRecorder(output_dir, binary_name)
    return _recorder


def record_tool_call(func):
    """Decorator to automatically record tool calls."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        recorder = get_recorder()
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
            if recorder:
                duration_ms = (time.time() - start) * 1000
                # Extract params from args/kwargs
                params = kwargs.copy()
                recorder.record(func.__name__, params, result, duration_ms, success)

    return wrapper


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python trajectory_recorder.py analyze <trajectory.jsonl>")
        print("  python trajectory_recorder.py export <trajectory.jsonl> [output.md]")
        sys.exit(1)

    command = sys.argv[1]

    if command == "analyze" and len(sys.argv) >= 3:
        analysis = analyze_trajectory(sys.argv[2])
        print(json.dumps(analysis, indent=2))

    elif command == "export" and len(sys.argv) >= 3:
        output = sys.argv[3] if len(sys.argv) > 3 else None
        md = export_trajectory_markdown(sys.argv[2], output)
        if not output:
            print(md)
        else:
            print(f"Exported to {output}")

    else:
        print("Unknown command or missing arguments")
        sys.exit(1)
