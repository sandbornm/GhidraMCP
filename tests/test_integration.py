"""
Integration tests for GhidraMCP.

These tests validate end-to-end workflows by testing the MCP bridge tools
with mocked server responses that simulate realistic multi-step analysis
scenarios. They test tool composition, state management, and error recovery.

Run with: python -m pytest tests/test_integration.py -v -m integration
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge_mcp_ghidra

# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state before each test."""
    bridge_mcp_ghidra.ghidra_server_url = "http://127.0.0.1:8080/"
    bridge_mcp_ghidra.gdb_server_url = "http://127.0.0.1:5000/"
    bridge_mcp_ghidra.trajectory_recorder = None
    yield


def _mock_response(text="", status_code=200, ok=True, json_data=None):
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = ok
    resp.text = text
    resp.encoding = "utf-8"
    if json_data is not None:
        resp.json.return_value = json_data
    return resp


# ===========================================================================
# Test: Full Binary Triage Workflow
# ===========================================================================


class TestBinaryTriageWorkflow:
    """Test a complete binary triage workflow combining multiple tools."""

    @patch("bridge_mcp_ghidra.gdb_request")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_full_triage_pipeline(self, mock_get, mock_gdb):
        """Simulate: checksec → file_info → strings → imports → entropy."""
        # Step 1: checksec
        mock_gdb.return_value = {
            "binary": "/analysis/bins/challenge",
            "nx": True,
            "pie": True,
            "relro": "Full",
            "canary": True,
        }
        checksec_result = bridge_mcp_ghidra.gdb_checksec(binary="challenge")
        assert checksec_result["nx"] is True
        assert checksec_result["pie"] is True

        # Step 2: file_info
        mock_gdb.return_value = {
            "type": "ELF 64-bit LSB pie executable, x86-64",
            "size_bytes": 16384,
            "md5": "abc123",
            "sha256": "def456",
            "architecture": "x86_64",
            "format": "ELF",
            "bits": 64,
        }
        file_info = bridge_mcp_ghidra.gdb_file_info(binary="challenge")
        assert file_info["architecture"] == "x86_64"
        assert file_info["bits"] == 64

        # Step 3: strings
        mock_get.return_value = [
            '0x402000: "Enter password: "',
            '0x402020: "flag{%s}"',
            '0x402030: "Access denied"',
            '0x402040: "Correct!"',
        ]
        strings = bridge_mcp_ghidra.list_strings(filter="flag")
        assert any("flag" in s for s in strings)

        # Step 4: imports
        mock_get.return_value = [
            "strcmp -> EXTERNAL:0x1000",
            "printf -> EXTERNAL:0x1008",
            "malloc -> EXTERNAL:0x1010",
            "free -> EXTERNAL:0x1018",
        ]
        imports = bridge_mcp_ghidra.list_imports()
        assert len(imports) == 4
        assert any("strcmp" in i for i in imports)

        # Step 5: entropy
        mock_gdb.return_value = {
            "overall_entropy": 5.8,
            "likely_packed": False,
            "analysis": "NORMAL - likely not packed",
        }
        entropy = bridge_mcp_ghidra.gdb_entropy(binary="challenge")
        assert entropy["likely_packed"] is False


# ===========================================================================
# Test: Function Analysis and Annotation Workflow
# ===========================================================================


class TestFunctionAnalysisWorkflow:
    """Test decompile → analyze → rename → comment workflow."""

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_analyze_and_annotate_function(self, mock_get, mock_post):
        """Simulate: decompile → get_call_graph → rename → comment."""
        # Step 1: Find undefined functions
        mock_get.return_value = [
            "Found 3 undefined functions:",
            "FUN_00401000 @ 0x401000 (size=200, params=2, callers=5)",
            "FUN_00401200 @ 0x401200 (size=50, params=1, callers=1)",
        ]
        undefined = bridge_mcp_ghidra.list_undefined_functions()
        assert "FUN_00401000" in undefined[1]

        # Step 2: Decompile the interesting function
        mock_post.return_value = (
            "int FUN_00401000(char *param_1, int param_2) {\n"
            "  int local_8;\n"
            "  local_8 = 0;\n"
            "  while (local_8 < param_2) {\n"
            "    param_1[local_8] = param_1[local_8] ^ 0x42;\n"
            "    local_8 = local_8 + 1;\n"
            "  }\n"
            "  return 0;\n"
            "}"
        )
        decompiled = bridge_mcp_ghidra.decompile_function(name="FUN_00401000")
        assert "0x42" in decompiled  # XOR key visible

        # Step 3: Get call graph
        mock_get.return_value = [
            "=== Call Graph for FUN_00401000 ===",
            "--- CALLERS ---",
            "<- main @ 0x400000",
            "<- process_input @ 0x400500",
            "--- CALLEES ---",
            "(none - leaf function)",
        ]
        call_graph = bridge_mcp_ghidra.get_call_graph(name="FUN_00401000", depth=1)
        assert "CALLERS" in call_graph
        assert "main" in call_graph

        # Step 4: Batch rename
        mock_post.return_value = (
            "OK: Renamed function FUN_00401000 → xor_decrypt\n"
            "OK: Renamed variable local_8 → i\n"
            "OK: Renamed variable param_1 → buffer\n"
            "Batch complete: 3 succeeded, 0 failed"
        )
        ops = json.dumps(
            [
                {"type": "function", "old_name": "FUN_00401000", "new_name": "xor_decrypt"},
                {"type": "variable", "function_address": "0x401000", "old_name": "local_8", "new_name": "i"},
                {"type": "variable", "function_address": "0x401000", "old_name": "param_1", "new_name": "buffer"},
            ]
        )
        rename_result = bridge_mcp_ghidra.batch_rename(operations=ops)
        assert "3 succeeded" in rename_result

        # Step 5: Add comment
        mock_post.return_value = "Comment set successfully"
        comment_result = bridge_mcp_ghidra.set_decompiler_comment(
            address="0x401000", comment="XOR decryption with key 0x42. Called from main and process_input."
        )
        assert "Comment set" in comment_result

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_type_system_workflow(self, mock_get, mock_post):
        """Test creating structs, enums, and applying them."""
        # Create struct
        mock_post.return_value = "Created structure: /PacketHeader (size=0)"
        result = bridge_mcp_ghidra.create_struct(name="PacketHeader", size=0)
        assert "Created" in result

        # Add fields
        for field_name, field_type, offset in [
            ("magic", "int", 0),
            ("length", "short", 4),
            ("flags", "short", 6),
            ("payload_offset", "int", 8),
        ]:
            mock_post.return_value = f"Added field {field_name} ({field_type}) to PacketHeader"
            result = bridge_mcp_ghidra.add_struct_field(
                struct_name="PacketHeader",
                field_type=field_type,
                field_name=field_name,
                offset=offset,
            )
            assert "Added" in result

        # Verify struct
        mock_get.return_value = [
            "Structure: PacketHeader",
            "Size: 12 bytes",
            "  offset=0x0 size=4 int magic",
            "  offset=0x4 size=2 short length",
            "  offset=0x6 size=2 short flags",
            "  offset=0x8 size=4 int payload_offset",
        ]
        fields = bridge_mcp_ghidra.get_struct_fields(name="PacketHeader")
        assert "magic" in fields
        assert "payload_offset" in fields


# ===========================================================================
# Test: Dynamic Analysis Workflow
# ===========================================================================


class TestDynamicAnalysisWorkflow:
    """Test dynamic analysis tool composition."""

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_debug_and_trace_workflow(self, mock_gdb):
        """Simulate: run → strace → breakpoint_run → memory inspect."""
        # Step 1: Run binary
        mock_gdb.return_value = {
            "stdout": "Enter password: \nAccess denied\n",
            "stderr": "",
            "returncode": 1,
            "architecture": "x86_64",
            "emulated": False,
        }
        run_result = bridge_mcp_ghidra.gdb_run_binary(binary="challenge", stdin="wrong_password")
        assert run_result["returncode"] == 1
        assert "denied" in run_result["stdout"]

        # Step 2: strace to find key syscalls
        mock_gdb.return_value = {
            "stdout": "Enter password: \n",
            "strace_output": (
                'openat(AT_FDCWD, "/etc/secret.key", O_RDONLY) = 3\n'
                'read(3, "supersecret\\n", 4096) = 12\n'
                "close(3) = 0\n"
                'write(1, "Enter password: ", 16) = 16\n'
                'read(0, "wrong_password\\n", 1024) = 15\n'
            ),
            "returncode": 1,
        }
        strace_result = bridge_mcp_ghidra.gdb_strace(binary="challenge", stdin="wrong_password")
        assert "/etc/secret.key" in strace_result["strace_output"]

        # Step 3: Set breakpoint and inspect state
        mock_gdb.return_value = {
            "output": (
                "Breakpoint 1, 0x0000000000401234 in check_password ()\n"
                "rax            0x7fffffffe000\n"
                "rbx            0x0\n"
                "rcx            0xf\n"
                "rdx            0xc\n"
                "rsi            0x7fffffffe100\n"
                "rdi            0x7fffffffe000\n"
            ),
            "returncode": 0,
        }
        bp_result = bridge_mcp_ghidra.gdb_breakpoint_run(
            binary="challenge",
            breakpoints=["check_password"],
            stdin="wrong_password",
        )
        assert "check_password" in bp_result["output"]

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_security_analysis_workflow(self, mock_gdb):
        """Test full security assessment pipeline."""
        # checksec
        mock_gdb.return_value = {
            "nx": True,
            "pie": False,
            "relro": "Partial",
            "canary": False,
        }
        checksec = bridge_mcp_ghidra.gdb_checksec(binary="vuln")
        assert checksec["canary"] is False  # No canary — stack overflow possible

        # Find ROP gadgets (if tool exists)
        mock_gdb.return_value = {
            "gadgets": [
                {"address": "0x401234", "gadget": "pop rdi; ret"},
                {"address": "0x401238", "gadget": "pop rsi; pop r15; ret"},
                {"address": "0x40123c", "gadget": "ret"},
            ],
            "count": 3,
        }
        if hasattr(bridge_mcp_ghidra, "gdb_rop_gadgets"):
            gadgets = bridge_mcp_ghidra.gdb_rop_gadgets(binary="vuln", filter="pop rdi")
            assert gadgets["count"] >= 1

        # GOT/PLT inspection
        mock_gdb.return_value = {
            "got_entries": [
                {"name": "printf", "got_address": "0x404018", "plt_address": "0x401030"},
                {"name": "system", "got_address": "0x404020", "plt_address": "0x401040"},
            ],
            "count": 2,
        }
        if hasattr(bridge_mcp_ghidra, "gdb_got_plt"):
            got = bridge_mcp_ghidra.gdb_got_plt(binary="vuln")
            assert any(e["name"] == "system" for e in got["got_entries"])


# ===========================================================================
# Test: Patching Workflow
# ===========================================================================


class TestPatchingWorkflow:
    """Test binary patching and export workflow."""

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_patch_and_export(self, mock_get, mock_post):
        """Simulate: read bytes → patch → verify → export."""
        # Step 1: Read original bytes at target
        mock_get.return_value = [
            "Bytes at 0x401050 (8 bytes):",
            "74 05 E8 XX XX XX XX C3    t.......    (JZ +5; CALL xxx; RET)",
        ]
        original = bridge_mcp_ghidra.get_bytes(address="0x401050", length=8)
        assert "74 05" in original  # JZ instruction

        # Step 2: NOP out the conditional jump (bypass check)
        mock_post.return_value = "NOPed 2 bytes from 0x401050 to 0x401051"
        nop_result = bridge_mcp_ghidra.nop_region(start_address="0x401050", end_address="0x401051")
        assert "NOPed" in nop_result

        # Step 3: Verify the patch
        mock_get.return_value = [
            "Bytes at 0x401050 (8 bytes):",
            "90 90 E8 XX XX XX XX C3    ........    (NOP; NOP; CALL xxx; RET)",
        ]
        patched = bridge_mcp_ghidra.get_bytes(address="0x401050", length=8)
        assert "90 90" in patched  # NOPs visible

        # Step 4: Export the patched binary
        mock_post.return_value = "Exported to /tmp/challenge_patched (16384 bytes)"
        export_result = bridge_mcp_ghidra.export_binary(output_path="/tmp/challenge_patched", format="original")
        assert "Exported" in export_result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_instruction_patch_workflow(self, mock_post):
        """Test patching specific instructions."""
        # Patch a conditional jump to unconditional
        mock_post.return_value = "Patched instruction at 0x401050: JZ → JMP"
        result = bridge_mcp_ghidra.patch_instruction(address="0x401050", assembly="JMP 0x401057")
        assert "Patched" in result

        # Patch a return value
        mock_post.return_value = "Patched instruction at 0x401080: XOR EAX, EAX"
        result = bridge_mcp_ghidra.patch_instruction(address="0x401080", assembly="XOR EAX, EAX")
        assert "Patched" in result


# ===========================================================================
# Test: Trajectory Recording Workflow
# ===========================================================================


class TestTrajectoryWorkflow:
    """Test trajectory recording across a multi-tool session."""

    @patch("bridge_mcp_ghidra.requests.get")
    def test_full_trajectory_session(self, mock_get):
        """Test start → tools → notes → stop → analyze."""
        # Start recording
        mock_get.return_value = _mock_response("test_binary")
        start_result = bridge_mcp_ghidra.trajectory_start(binary_name="challenge")
        assert start_result["status"] == "recording_started"
        session_id = start_result["session_id"]
        assert session_id is not None

        # Check status
        status = bridge_mcp_ghidra.trajectory_status()
        assert status["recording"] is True
        assert status["binary"] == "challenge"

        # Add a note
        note_result = bridge_mcp_ghidra.trajectory_note(
            note="Binary uses XOR encryption with key 0x42", category="finding"
        )
        assert note_result["status"] == "note_added"

        # Stop recording
        stop_result = bridge_mcp_ghidra.trajectory_stop(summary="Identified XOR decryption routine and key")
        assert stop_result["status"] == "recording_stopped"
        assert stop_result["session_id"] == session_id

        # Verify trajectory file exists
        trajectory_path = stop_result["trajectory_path"]
        assert trajectory_path.endswith(".jsonl")


# ===========================================================================
# Test: Error Recovery Workflows
# ===========================================================================


class TestErrorRecovery:
    """Test graceful error handling across workflows."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_ghidra_server_down(self, mock_get):
        """All tools should return error messages when Ghidra is unreachable."""
        mock_get.return_value = ["Request failed: Connection refused"]

        # These should all return error messages, not crash
        result = bridge_mcp_ghidra.list_methods()
        assert "Request failed" in result[0]

        result = bridge_mcp_ghidra.list_functions()
        assert "Request failed" in result[0]

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_server_down(self, mock_gdb):
        """GDB tools should return error dict when Docker is unreachable."""
        mock_gdb.return_value = {"error": "Cannot connect to GDB server at http://127.0.0.1:5000/."}

        result = bridge_mcp_ghidra.gdb_health()
        assert "error" in result

        result = bridge_mcp_ghidra.gdb_run_binary(binary="test")
        assert "error" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_rename_nonexistent_function(self, mock_post):
        """Renaming a nonexistent function should return error."""
        mock_post.return_value = "Error: Function 'nonexistent' not found"
        result = bridge_mcp_ghidra.rename_function(old_name="nonexistent", new_name="new_name")
        assert "Error" in result

    @patch("bridge_mcp_ghidra.safe_post")
    def test_patch_invalid_address(self, mock_post):
        """Patching an invalid address should return error."""
        mock_post.return_value = "Error: Address 0xDEADBEEF is not in any memory block"
        result = bridge_mcp_ghidra.patch_bytes(address="0xDEADBEEF", hex_bytes="90 90")
        assert "Error" in result

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_run_missing_binary(self, mock_gdb):
        """Running a nonexistent binary should return error."""
        mock_gdb.return_value = {"error": "Binary not found: /analysis/bins/missing"}
        result = bridge_mcp_ghidra.gdb_run_binary(binary="missing")
        assert "error" in result

    @patch("bridge_mcp_ghidra.safe_get")
    @patch("bridge_mcp_ghidra.safe_post")
    def test_mixed_success_failure(self, mock_post, mock_get):
        """Test workflow where some operations succeed and others fail."""
        # Success: list functions
        mock_get.return_value = ["main at 0x401000", "check at 0x401100"]
        funcs = bridge_mcp_ghidra.list_functions()
        assert len(funcs) == 2

        # Fail: decompile
        mock_post.return_value = "Error: Decompilation timeout for function at 0x401100"
        result = bridge_mcp_ghidra.decompile_function(name="check")
        assert "Error" in result

        # Success: still can do other operations
        mock_get.return_value = ["0x401050: CALL check [UNCONDITIONAL_CALL]"]
        xrefs = bridge_mcp_ghidra.get_xrefs_to(address="0x401100")
        assert len(xrefs) == 1


# ===========================================================================
# Test: Cross-Tool Data Flow
# ===========================================================================


class TestCrossToolDataFlow:
    """Test that data flows correctly between related tools."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_address_from_search_to_decompile(self, mock_get):
        """Use search results as input to other tools."""
        # Search for function
        mock_get.return_value = [
            "encrypt_block @ 0x401500 (IMPORTED:false)",
        ]
        search_results = bridge_mcp_ghidra.search_functions_by_name(query="encrypt")
        assert "0x401500" in search_results[0]

        # Use the found address for decompilation
        mock_get.return_value = [
            "void encrypt_block(char *data, int len, char key) {",
            "  for (int i = 0; i < len; i++) {",
            "    data[i] ^= key;",
            "  }",
            "}",
        ]
        decompiled = bridge_mcp_ghidra.decompile_function_by_address(address="0x401500")
        assert "encrypt_block" in decompiled

        # Get CFG info for same address
        mock_get.return_value = [
            "=== CFG Info for encrypt_block @ 0x401500 ===",
            "Body size: 45 bytes",
            "Instructions: 12",
            "Estimated cyclomatic complexity: 2",
            "Complexity class: Low",
        ]
        cfg = bridge_mcp_ghidra.get_function_cfg_info(address="0x401500")
        assert "Low" in cfg

    @patch("bridge_mcp_ghidra.safe_get")
    def test_xref_chain_navigation(self, mock_get):
        """Follow xref chains: A calls B calls C."""
        # Get callees of main
        mock_get.return_value = [
            "main calls process_input @ 0x401200",
            "main calls check_password @ 0x401300",
        ]
        callees = bridge_mcp_ghidra.get_callees(name="main")
        assert len(callees) == 2

        # Get callees of check_password
        mock_get.return_value = [
            "check_password calls strcmp @ EXTERNAL",
            "check_password calls decrypt @ 0x401400",
        ]
        callees2 = bridge_mcp_ghidra.get_callees(name="check_password")
        assert any("decrypt" in c for c in callees2)

        # Get callers of decrypt (reverse)
        mock_get.return_value = [
            "check_password @ 0x401300 -> decrypt",
        ]
        callers = bridge_mcp_ghidra.get_callers(name="decrypt")
        assert any("check_password" in c for c in callers)


# ===========================================================================
# Test: GDB Server Endpoint Validation
# ===========================================================================


class TestGDBServerEndpoints:
    """Validate all GDB tool endpoints are called correctly."""

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_all_gdb_tools_callable(self, mock_gdb):
        """Verify every GDB tool can be called without errors."""
        mock_gdb.return_value = {"status": "ok"}

        # Basic tools
        bridge_mcp_ghidra.gdb_health()
        bridge_mcp_ghidra.gdb_check_arch(binary="test")
        bridge_mcp_ghidra.gdb_list_binaries()
        bridge_mcp_ghidra.gdb_run_binary(binary="test")
        bridge_mcp_ghidra.gdb_execute(binary="test", commands=["info registers"])
        bridge_mcp_ghidra.gdb_breakpoint_run(binary="test", breakpoints=["main"])
        bridge_mcp_ghidra.gdb_strace(binary="test")
        bridge_mcp_ghidra.gdb_ltrace(binary="test")
        bridge_mcp_ghidra.gdb_checksec(binary="test")
        bridge_mcp_ghidra.gdb_disassemble(binary="test")
        bridge_mcp_ghidra.gdb_strings(binary="test")
        bridge_mcp_ghidra.gdb_file_info(binary="test")
        bridge_mcp_ghidra.gdb_readelf(binary="test")
        bridge_mcp_ghidra.gdb_sections(binary="test")
        bridge_mcp_ghidra.gdb_symbols(binary="test")
        bridge_mcp_ghidra.gdb_entropy(binary="test")
        bridge_mcp_ghidra.gdb_binwalk(binary="test")
        bridge_mcp_ghidra.gdb_hexdump(binary="test")
        bridge_mcp_ghidra.gdb_imports(binary="test")
        bridge_mcp_ghidra.gdb_libs(binary="test")
        bridge_mcp_ghidra.gdb_patch_elf(binary="test", address="0x401000", hex_bytes="90")
        bridge_mcp_ghidra.gdb_get_logs()
        bridge_mcp_ghidra.gdb_get_telemetry()

        # All calls should have succeeded
        assert mock_gdb.call_count == 23

    @patch("bridge_mcp_ghidra.gdb_request")
    def test_gdb_request_methods(self, mock_gdb):
        """Verify correct HTTP methods are used for each endpoint."""
        mock_gdb.return_value = {"status": "ok"}

        bridge_mcp_ghidra.gdb_health()
        # health uses GET
        mock_gdb.assert_called_with("/health")

        bridge_mcp_ghidra.gdb_run_binary(binary="test", args=["arg1"])
        # run uses POST
        mock_gdb.assert_called_with(
            "/run",
            "POST",
            {
                "binary": "test",
                "args": ["arg1"],
                "stdin": "",
                "timeout": 10,
            },
        )


# ===========================================================================
# Test: Pagination Consistency
# ===========================================================================


class TestPaginationConsistency:
    """Test that pagination works correctly across all list tools."""

    @patch("bridge_mcp_ghidra.safe_get")
    def test_pagination_params_propagated(self, mock_get):
        """Verify offset/limit params are passed through correctly."""
        mock_get.return_value = ["item1", "item2"]

        tools_with_pagination = [
            ("list_methods", {"offset": 10, "limit": 5}),
            ("list_classes", {"offset": 0, "limit": 50}),
            ("list_segments", {"offset": 5, "limit": 10}),
            ("list_imports", {"offset": 0, "limit": 200}),
            ("list_exports", {"offset": 20, "limit": 30}),
            ("list_namespaces", {"offset": 0, "limit": 100}),
            ("list_data_items", {"offset": 0, "limit": 100}),
        ]

        for tool_name, params in tools_with_pagination:
            tool_func = getattr(bridge_mcp_ghidra, tool_name)
            tool_func(**params)
            call_args = mock_get.call_args
            for key, value in params.items():
                assert call_args[0][1][key] == value, f"{tool_name}: expected {key}={value}"


# ===========================================================================
# Test: Bookmark Workflow
# ===========================================================================


class TestBookmarkWorkflow:
    """Test bookmark creation, listing, and deletion."""

    @patch("bridge_mcp_ghidra.safe_post")
    @patch("bridge_mcp_ghidra.safe_get")
    def test_bookmark_lifecycle(self, mock_get, mock_post):
        """Create → list → delete bookmarks."""
        # Create bookmarks
        mock_post.return_value = "Bookmark set at 0x401000 [Vuln]: Buffer overflow"
        bridge_mcp_ghidra.set_bookmark(address="0x401000", category="Vuln", comment="Buffer overflow")

        mock_post.return_value = "Bookmark set at 0x401200 [Crypto]: AES routine"
        bridge_mcp_ghidra.set_bookmark(address="0x401200", category="Crypto", comment="AES routine")

        # List all bookmarks
        mock_get.return_value = [
            "0x401000 [Note/Vuln]: Buffer overflow",
            "0x401200 [Note/Crypto]: AES routine",
        ]
        bookmarks = bridge_mcp_ghidra.list_bookmarks()
        assert len(bookmarks) == 2

        # List filtered bookmarks
        mock_get.return_value = [
            "0x401000 [Note/Vuln]: Buffer overflow",
        ]
        vuln_bookmarks = bridge_mcp_ghidra.list_bookmarks(category="Vuln")
        assert len(vuln_bookmarks) == 1

        # Delete bookmark
        mock_post.return_value = "Removed 1 bookmark(s) at 0x401000"
        bridge_mcp_ghidra.delete_bookmark(address="0x401000")
