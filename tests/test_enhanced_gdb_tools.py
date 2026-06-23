"""
Tests for the enhanced GDB/dynamic analysis MCP tools.

Tests the new register, memory, stepping, watchpoint, heap, Frida,
ROP gadget, GOT/PLT, and vmmap tools added to bridge_mcp_ghidra.py.
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_ghidra


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state before each test."""
    bridge_mcp_ghidra.ghidra_server_url = "http://127.0.0.1:8080/"
    bridge_mcp_ghidra.gdb_server_url = "http://127.0.0.1:5051/"
    bridge_mcp_ghidra.trajectory_recorder = None
    yield


# ===========================================================================
# Tests for Register Tools
# ===========================================================================


class TestRegisterTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_read_registers(self, mock_gdb):
        mock_gdb.return_value = {
            "registers": {
                "rax": "0x0",
                "rbx": "0x0",
                "rcx": "0x7fffffff",
                "rdx": "0x7fffffffe4a8",
                "rsp": "0x7fffffffe380",
                "rbp": "0x7fffffffe390",
                "rip": "0x401000",
            },
            "breakpoint": "main",
        }
        result = bridge_mcp_ghidra.gdb_read_registers(binary="test", breakpoint="main")
        assert "registers" in result
        assert result["registers"]["rip"] == "0x401000"
        mock_gdb.assert_called_with(
            "/gdb/registers",
            "POST",
            {
                "binary": "test",
                "breakpoint": "main",
            },
        )

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_read_registers_default_breakpoint(self, mock_gdb):
        mock_gdb.return_value = {"registers": {"rax": "0x0"}}
        bridge_mcp_ghidra.gdb_read_registers(binary="test")
        call_data = mock_gdb.call_args[0][2]
        assert call_data["breakpoint"] == "main"


# ===========================================================================
# Tests for Memory Tools
# ===========================================================================


class TestMemoryTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_read_memory_hex(self, mock_gdb):
        mock_gdb.return_value = {
            "address": "0x401000",
            "length": 64,
            "format": "hex",
            "data": "48 89 5c 24 08 48 89 6c 24 10",
        }
        result = bridge_mcp_ghidra.gdb_read_memory(binary="test", address="0x401000", length=64, format="hex")
        assert result["format"] == "hex"
        mock_gdb.assert_called_with(
            "/gdb/memory",
            "POST",
            {
                "binary": "test",
                "address": "0x401000",
                "length": 64,
                "format": "hex",
            },
        )

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_read_memory_string(self, mock_gdb):
        mock_gdb.return_value = {
            "data": "Hello, World!\x00",
            "format": "string",
        }
        result = bridge_mcp_ghidra.gdb_read_memory(binary="test", address="0x402000", format="string")
        assert result["format"] == "string"

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_read_memory_instructions(self, mock_gdb):
        mock_gdb.return_value = {
            "data": "0x401000: push rbp\n0x401001: mov rbp, rsp",
            "format": "instructions",
        }
        result = bridge_mcp_ghidra.gdb_read_memory(binary="test", address="0x401000", format="instructions")
        assert result["format"] == "instructions"


# ===========================================================================
# Tests for Stepping Tools
# ===========================================================================


class TestSteppingTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_step_execution_stepi(self, mock_gdb):
        mock_gdb.return_value = {
            "output": "0x401001 in main ()\nrax 0x0\nrbx 0x0",
            "command": "stepi",
            "count": 1,
        }
        result = bridge_mcp_ghidra.gdb_step_execution(binary="test", breakpoint="main", command="stepi", count=1)
        assert result["command"] == "stepi"
        mock_gdb.assert_called_with(
            "/gdb/step",
            "POST",
            {
                "binary": "test",
                "breakpoint": "main",
                "command": "stepi",
                "count": 1,
            },
        )

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_step_execution_multiple(self, mock_gdb):
        mock_gdb.return_value = {"output": "Stepped 5 times", "count": 5}
        result = bridge_mcp_ghidra.gdb_step_execution(binary="test", command="nexti", count=5)
        assert result["count"] == 5


# ===========================================================================
# Tests for Watchpoint Tools
# ===========================================================================


class TestWatchpointTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_set_write_watchpoint(self, mock_gdb):
        mock_gdb.return_value = {
            "output": "Hardware watchpoint 2: *0x404000\nOld value = 0\nNew value = 42",
            "triggered": True,
        }
        result = bridge_mcp_ghidra.gdb_set_watchpoint(
            binary="test",
            expression="*0x404000",
            watch_type="write",
            breakpoints=["main"],
        )
        assert result["triggered"] is True

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_set_read_watchpoint(self, mock_gdb):
        mock_gdb.return_value = {"output": "Access watchpoint set"}
        bridge_mcp_ghidra.gdb_set_watchpoint(
            binary="test",
            expression="*0x404000",
            watch_type="read",
        )
        mock_gdb.assert_called_once()

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_watchpoint_default_type(self, mock_gdb):
        mock_gdb.return_value = {"output": "Watchpoint set"}
        bridge_mcp_ghidra.gdb_set_watchpoint(binary="test", expression="*0x404000")
        call_data = mock_gdb.call_args[0][2]
        assert call_data["watch_type"] == "write"


# ===========================================================================
# Tests for Stack Inspection
# ===========================================================================


class TestStackInspection:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_inspect_stack(self, mock_gdb):
        mock_gdb.return_value = {
            "backtrace": "#0 main () at test.c:5\n#1 __libc_start_main",
            "stack_memory": "0x7fffffffe380: 0x00000001 0x00000000",
            "frame_info": "Stack frame at 0x7fffffffe380",
        }
        result = bridge_mcp_ghidra.gdb_inspect_stack(binary="test", breakpoint="main", depth=20)
        assert "backtrace" in result
        mock_gdb.assert_called_with(
            "/gdb/stack",
            "POST",
            {
                "binary": "test",
                "breakpoint": "main",
                "depth": 20,
            },
        )


# ===========================================================================
# Tests for Heap Analysis
# ===========================================================================


class TestHeapAnalysis:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_analyze_heap(self, mock_gdb):
        mock_gdb.return_value = {
            "chunks": "Chunk(addr=0x603000, size=0x20, flags=PREV_INUSE)",
            "bins": "Fastbin[0]: 0x0",
            "gef_available": True,
        }
        result = bridge_mcp_ghidra.gdb_analyze_heap(binary="test", breakpoint="main+50")
        assert "chunks" in result

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_analyze_heap_no_breakpoint(self, mock_gdb):
        mock_gdb.return_value = {"chunks": "No heap data"}
        bridge_mcp_ghidra.gdb_analyze_heap(binary="test")
        call_data = mock_gdb.call_args[0][2]
        assert call_data["binary"] == "test"


# ===========================================================================
# Tests for GOT/PLT
# ===========================================================================


class TestGOTPLT:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_got_plt(self, mock_gdb):
        mock_gdb.return_value = {
            "got_entries": [
                {"name": "printf", "got_address": "0x404018", "plt_address": "0x401030"},
                {"name": "strcmp", "got_address": "0x404020", "plt_address": "0x401040"},
            ],
            "plt_entries": [
                {"address": "0x401030", "name": "printf@plt"},
                {"address": "0x401040", "name": "strcmp@plt"},
            ],
            "count": 2,
        }
        result = bridge_mcp_ghidra.gdb_got_plt(binary="test")
        assert result["count"] == 2
        assert any(e["name"] == "printf" for e in result["got_entries"])
        mock_gdb.assert_called_with("/got_plt", "POST", {"binary": "test"})


# ===========================================================================
# Tests for ROP Gadgets
# ===========================================================================


class TestROPGadgets:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_rop_gadgets_basic(self, mock_gdb):
        mock_gdb.return_value = {
            "gadgets": [
                {"address": "0x401234", "gadget": "pop rdi; ret"},
                {"address": "0x401238", "gadget": "pop rsi; pop r15; ret"},
                {"address": "0x40123c", "gadget": "ret"},
            ],
            "count": 3,
        }
        result = bridge_mcp_ghidra.gdb_rop_gadgets(binary="test")
        assert result["count"] == 3
        assert any("pop rdi" in g["gadget"] for g in result["gadgets"])

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_rop_gadgets_with_filter(self, mock_gdb):
        mock_gdb.return_value = {
            "gadgets": [{"address": "0x401234", "gadget": "pop rdi; ret"}],
            "count": 1,
        }
        result = bridge_mcp_ghidra.gdb_rop_gadgets(binary="test", max_depth=3, filter="pop rdi")
        assert result["count"] == 1
        call_data = mock_gdb.call_args[0][2]
        assert call_data["filter"] == "pop rdi"
        assert call_data["max_depth"] == 3


# ===========================================================================
# Tests for Frida Instrumentation
# ===========================================================================


class TestFridaInstrumentation:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_frida_instrument(self, mock_gdb):
        mock_gdb.return_value = {
            "output": "strcmp called with: 'password' vs 'secret123'",
            "returncode": 0,
        }
        script = """
        Interceptor.attach(Module.findExportByName(null, 'strcmp'), {
            onEnter: function(args) {
                console.log('strcmp: ' + args[0].readUtf8String() + ' vs ' + args[1].readUtf8String());
            }
        });
        """
        result = bridge_mcp_ghidra.gdb_frida_instrument(binary="test", script=script, timeout=10)
        assert "strcmp" in result["output"]

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_frida_trace(self, mock_gdb):
        mock_gdb.return_value = {
            "output": "malloc(64) => 0x603010\nfree(0x603010)\n",
            "functions_traced": ["malloc", "free"],
        }
        result = bridge_mcp_ghidra.gdb_frida_trace(
            binary="test",
            functions=["malloc", "free"],
            timeout=10,
        )
        assert "malloc" in result["output"]
        mock_gdb.assert_called_with(
            "/frida/trace",
            "POST",
            {
                "binary": "test",
                "functions": ["malloc", "free"],
                "timeout": 10,
            },
        )

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_frida_hook(self, mock_gdb):
        mock_gdb.return_value = {
            "output": "Hooked strcmp: arg0='test', arg1='password'",
            "returncode": 0,
        }
        result = bridge_mcp_ghidra.gdb_frida_hook(
            binary="test",
            target="strcmp",
            on_enter="console.log('arg0=' + args[0].readUtf8String())",
            timeout=10,
        )
        assert "Hooked" in result["output"]


# ===========================================================================
# Tests for VMMap
# ===========================================================================


class TestVMMap:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_vmmap(self, mock_gdb):
        mock_gdb.return_value = {
            "regions": [
                {"start": "0x400000", "end": "0x401000", "perms": "r-x", "name": "test"},
                {"start": "0x601000", "end": "0x602000", "perms": "rw-", "name": "test"},
                {"start": "0x7f0000", "end": "0x7f1000", "perms": "r-x", "name": "libc.so"},
            ],
            "count": 3,
        }
        result = bridge_mcp_ghidra.gdb_vmmap(binary="test", breakpoint="main")
        assert result["count"] == 3
        assert any(r["perms"] == "r-x" for r in result["regions"])


# ===========================================================================
# Tests for Pattern Search
# ===========================================================================


class TestPatternSearch:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_search_pattern_string(self, mock_gdb):
        mock_gdb.return_value = {
            "matches": [
                {"address": "0x402000", "section": ".rodata"},
                {"address": "0x7ffff7e00100", "section": "[stack]"},
            ],
            "count": 2,
            "pattern": "flag{",
        }
        result = bridge_mcp_ghidra.gdb_search_pattern(
            binary="test",
            pattern="flag{",
            breakpoint="main",
            pattern_type="string",
        )
        assert result["count"] == 2
        assert result["pattern"] == "flag{"

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_search_pattern_hex(self, mock_gdb):
        mock_gdb.return_value = {
            "matches": [{"address": "0x401000"}],
            "count": 1,
        }
        result = bridge_mcp_ghidra.gdb_search_pattern(
            binary="test",
            pattern="48 89 5c",
            pattern_type="hex",
        )
        assert result["count"] == 1


# ===========================================================================
# Tests for Enhanced GDB Tool Endpoint Routing
# ===========================================================================


class TestEnhancedGDBEndpointRouting:
    """Verify all new tools call the correct endpoints."""

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_all_new_tools_endpoints(self, mock_gdb):
        mock_gdb.return_value = {"status": "ok"}

        # Test each tool calls the right endpoint
        bridge_mcp_ghidra.gdb_read_registers(binary="t")
        assert mock_gdb.call_args[0][0] == "/gdb/registers"

        bridge_mcp_ghidra.gdb_read_memory(binary="t", address="0x0")
        assert mock_gdb.call_args[0][0] == "/gdb/memory"

        bridge_mcp_ghidra.gdb_step_execution(binary="t")
        assert mock_gdb.call_args[0][0] == "/gdb/step"

        bridge_mcp_ghidra.gdb_set_watchpoint(binary="t", expression="*0x0")
        assert mock_gdb.call_args[0][0] == "/gdb/watchpoint"

        bridge_mcp_ghidra.gdb_inspect_stack(binary="t")
        assert mock_gdb.call_args[0][0] == "/gdb/stack"

        bridge_mcp_ghidra.gdb_analyze_heap(binary="t")
        assert mock_gdb.call_args[0][0] == "/gdb/heap"

        bridge_mcp_ghidra.gdb_got_plt(binary="t")
        assert mock_gdb.call_args[0][0] == "/got_plt"

        bridge_mcp_ghidra.gdb_rop_gadgets(binary="t")
        assert mock_gdb.call_args[0][0] == "/rop_gadgets"

        bridge_mcp_ghidra.gdb_frida_instrument(binary="t", script="test")
        assert mock_gdb.call_args[0][0] == "/frida/attach"

        bridge_mcp_ghidra.gdb_frida_trace(binary="t", functions=["main"])
        assert mock_gdb.call_args[0][0] == "/frida/trace"

        bridge_mcp_ghidra.gdb_frida_hook(binary="t", target="main")
        assert mock_gdb.call_args[0][0] == "/frida/hook"

        bridge_mcp_ghidra.gdb_vmmap(binary="t")
        assert mock_gdb.call_args[0][0] == "/gdb/vmmap"

        bridge_mcp_ghidra.gdb_search_pattern(binary="t", pattern="test")
        assert mock_gdb.call_args[0][0] == "/gdb/search_pattern"

        bridge_mcp_ghidra.gdb_pe_info(binary="t")
        assert mock_gdb.call_args[0][0] == "/pe/info"

        bridge_mcp_ghidra.angr_explore(binary="t", find_addr="0x401000")
        assert mock_gdb.call_args[0][0] == "/angr/explore"

        bridge_mcp_ghidra.angr_cfg(binary="t")
        assert mock_gdb.call_args[0][0] == "/angr/cfg"

        bridge_mcp_ghidra.angr_entry(binary="t")
        assert mock_gdb.call_args[0][0] == "/angr/entry"


# ===========================================================================
# Tests for Error Handling on New Tools
# ===========================================================================


class TestEnhancedToolErrors:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_new_tools_handle_connection_error(self, mock_gdb):
        """All new tools should handle connection errors gracefully."""
        mock_gdb.return_value = {"error": "Cannot connect to GDB server at http://127.0.0.1:5051/"}

        # Each tool should return the error dict without crashing
        assert "error" in bridge_mcp_ghidra.gdb_read_registers(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_read_memory(binary="t", address="0x0")
        assert "error" in bridge_mcp_ghidra.gdb_step_execution(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_set_watchpoint(binary="t", expression="*0x0")
        assert "error" in bridge_mcp_ghidra.gdb_inspect_stack(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_analyze_heap(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_got_plt(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_rop_gadgets(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_frida_instrument(binary="t", script="x")
        assert "error" in bridge_mcp_ghidra.gdb_frida_trace(binary="t", functions=["x"])
        assert "error" in bridge_mcp_ghidra.gdb_frida_hook(binary="t", target="x")
        assert "error" in bridge_mcp_ghidra.gdb_vmmap(binary="t")
        assert "error" in bridge_mcp_ghidra.gdb_search_pattern(binary="t", pattern="x")
        assert "error" in bridge_mcp_ghidra.gdb_pe_info(binary="t")
        assert "error" in bridge_mcp_ghidra.angr_explore(binary="t", find_addr="0x401000")
        assert "error" in bridge_mcp_ghidra.angr_cfg(binary="t")
        assert "error" in bridge_mcp_ghidra.angr_entry(binary="t")

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_new_tools_handle_binary_not_found(self, mock_gdb):
        """Tools should handle missing binary errors."""
        mock_gdb.return_value = {"error": "Binary not found: /analysis/bins/missing"}

        result = bridge_mcp_ghidra.gdb_read_registers(binary="missing")
        assert "error" in result
        assert "not found" in result["error"].lower()


# ===========================================================================
# Tests for PE, Angr, and Auto-Triage Tools
# ===========================================================================


class TestPETools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_pe_info(self, mock_gdb):
        mock_gdb.return_value = {
            "binary": "/analysis/bins/sample.exe",
            "format": "PE",
            "machine_type": "amd64",
            "sections": [{"name": ".text", "virtual_address": "0x1000"}],
            "imports": [{"dll": "kernel32.dll", "name": "CreateFileA"}],
        }
        result = bridge_mcp_ghidra.gdb_pe_info(binary="sample.exe")
        assert result["format"] == "PE"
        assert "imports" in result
        mock_gdb.assert_called_with("/pe/info", "POST", {"binary": "sample.exe"})


class TestAngrTools:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_angr_explore(self, mock_gdb):
        mock_gdb.return_value = {
            "found": True,
            "stdin_solution": "flag{test}",
            "reached_addr": "0x401050",
        }
        result = bridge_mcp_ghidra.angr_explore(binary="crackme", find_addr="0x401050")
        assert result["found"] is True
        assert "flag" in result["stdin_solution"]
        mock_gdb.assert_called_with(
            "/angr/explore",
            "POST",
            {"binary": "crackme", "find_addr": "0x401050", "timeout": 120, "stdin_symbolic": True},
        )

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_angr_explore_with_avoid(self, mock_gdb):
        mock_gdb.return_value = {"found": False}
        bridge_mcp_ghidra.angr_explore(binary="crackme", find_addr="0x401050", avoid_addrs=["0x401000"], timeout=60)
        call_data = mock_gdb.call_args[0][2]
        assert call_data["avoid_addrs"] == ["0x401000"]
        assert call_data["timeout"] == 60

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_angr_cfg(self, mock_gdb):
        mock_gdb.return_value = {"node_count": 42, "edge_count": 50, "nodes": [], "edges": []}
        result = bridge_mcp_ghidra.angr_cfg(binary="sample")
        assert result["node_count"] == 42
        mock_gdb.assert_called_with("/angr/cfg", "POST", {"binary": "sample", "timeout": 60})

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_angr_entry(self, mock_gdb):
        mock_gdb.return_value = {"entry_point": "0x401000", "main": "0x401050"}
        result = bridge_mcp_ghidra.angr_entry(binary="sample")
        assert result["entry_point"] == "0x401000"
        assert result["main"] == "0x401050"


class TestAutoTriage:
    @patch("bridge_mcp_ghidra.gdb_request")
    def test_auto_triage_elf(self, mock_gdb):
        def side_effect(endpoint, method="GET", data=None):
            if endpoint == "/file_info":
                return {"architecture": "x86_64", "format": "ELF", "bits": 64, "is_pie": True}
            if endpoint == "/checksec":
                return {"nx": True, "pie": True, "relro": "Full", "canary": True}
            if endpoint == "/entropy":
                return {"likely_packed": False, "overall_entropy": 5.2}
            if endpoint == "/imports":
                return {"imports": ["printf", "malloc", "strcmp"]}
            if endpoint == "/strings":
                return {"strings": ["flag{test}", "password", "admin"]}
            return {"error": "unknown"}

        mock_gdb.side_effect = side_effect

        result = bridge_mcp_ghidra.auto_triage(binary="chall", include_strings=True)
        assert result["architecture"] == "x86_64"
        assert result["format"] == "ELF"
        assert result["likely_packed"] is False
        assert len(result["imports"]) == 3
        assert "flag" in str(result["strings_sample"])
        assert "summary" in result

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_auto_triage_pe(self, mock_gdb):
        def side_effect(endpoint, method="GET", data=None):
            if endpoint == "/file_info":
                return {"architecture": "amd64", "format": "PE", "bits": 64}
            if endpoint == "/checksec":
                return {"nx": True}
            if endpoint == "/entropy":
                return {"likely_packed": False}
            if endpoint == "/pe/info":
                return {"imports": [{"dll": "kernel32", "name": "CreateFile"}]}
            if endpoint == "/strings":
                return {"strings": ["hello"]}
            return {"error": "unknown"}

        mock_gdb.side_effect = side_effect

        result = bridge_mcp_ghidra.auto_triage(binary="sample.exe")
        assert result["format"] == "PE"
        assert "imports" in result

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_auto_triage_handles_errors(self, mock_gdb):
        mock_gdb.return_value = {"error": "Connection refused"}
        result = bridge_mcp_ghidra.auto_triage(binary="chall")
        assert "errors" in result
        assert len(result["errors"]) > 0
        assert "summary" in result
